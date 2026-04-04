# client


import os
import sys
import time
import struct
import threading

from socket import *
from config import *
from packet_helper import *




# receive

# seq numbers received set
receivedSet = set()
# file handle disk
outputFile = None
# next seq (cumulative ACK)
expectedSeq = 0

# file info
fileName = ''
fileSize = 0
numChunks = 0
serverMD5 = ''

# transfer
isDone = False
ackCount = 0

# packet stat
validCount = 0
duplicateCount = 0
outOfOrderCount = 0

# security

# AES 256 from HKDF
sessionKey = None
# 8B from handshake
sessionId = None
# nonce use from handsahke
clientNonce = None
handshakeOk = False

# security counters

# AEAD failures (tampered/forged)
aeadFailCount = 0
# replay/duplicate/out of window drops
replayDropCount = 0

# SHA 256 verif
serverSHA256 = ''
sha256Match = False

# thread lock (multithreading safety)
# prevent send from interleaving
clientLock = threading.Lock()


# Send Filename Request to Server

def requestFile(sock, filename):
    print('')
    print('[request] send file request: ' + filename)
    print(' server: ' + serverIP + ':' + str(serverPort))
    sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
               typeFilename, 0, 0, filename.encode('utf-8'))
    print(' request sent')


# security handshake
# establish secure session
def doSecurityHandshake(sock):
    global sessionKey, sessionId, clientNonce, handshakeOk

    print('')
    print(' Phase 2: Security Handshake')
    print('')

    # build ClientHello ( nonce + HMAC using PSK)
    print('[handshake] building ClientHello')
    helloData, clientNonce = buildClientHello(psk)

    # send ClientHello to server
    print('[handshake] sending ClientHello to server')
    # send 3 copy
    # reliability (UDP might drop one)
    for i in range(3):
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeClientHello, 0, 0, helloData)
        time.sleep(0.05)
    print(' ClientHello sent (with HMAC proof)')

    # wait for ServerHello
    print('[handshake] waiting for ServerHello')
    serverNonce = None
    for attempt in range(maxRetry):
        parsed = recvPacket(sock, clientPort, timeout=5)
        if parsed is None:
            print(' timeout waiting for ServerHello (' +
                  str(attempt + 1) + '/' + str(maxRetry) + ')')
            # resend ClientHello
            # in case it was lost
            sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                       typeClientHello, 0, 0, helloData)
            continue

        if parsed['pktType'] == typeServerHello:
            print('[handshake] receive ServerHello')
            # verify server HMAC (proves server same PSK)
            serverNonce, sessionId = parseServerHello(
                psk, parsed['data'], clientNonce)

            if serverNonce is None:
                # HMAC fail server has different PSK
                print('[handshake] Failed b/c server PSK mismatch')
                handshakeOk = False
                return False

            print('[handshake] server authenticated ok')
            break

    if serverNonce is None:
        print('[handshake] Failed b/c no ServerHello received after ' + str(maxRetry) + ' tries')
        handshakeOk = False
        return False

    # derive session key (HKDF-SHA256)
    sessionKey = deriveSessionKey(psk, clientNonce, serverNonce)
    print('[handshake] session key derived (HKDF-SHA256)')
    print(' session ID: ' + sessionId.hex())
    print(' enc_key (first 8 bytes): ' + sessionKey[0:8].hex() + '...')

    handshakeOk = True
    print('')
    print('[handshake] Success and secure session established')
    print(' cipher: AES-256-GCM (AEAD)')
    print('')
    return True


# Wait for File Info from Server
# server sends: filename|size|numChunks|md5hash
def waitForFileInfo(sock, filename):
    global fileName, fileSize, numChunks, serverMD5

    print('')
    print('[wait] waiting for file info from server')
    for attempt in range(maxRetry):
        parsed = recvPacket(sock, clientPort, timeout=3)
        if parsed is None:
            print(' timeout, resending file request (' +
                  str(attempt + 1) + '/' + str(maxRetry) + ')')
            requestFile(sock, filename)
            continue

        if parsed['pktType'] == typeFileInfo:
            infoStr = parsed['data'].decode('utf-8')
            # check for error response
            if infoStr.startswith('ERROR:'):
                print('[error] server says: ' + infoStr)
                return False

            # parse file info field
            parts = infoStr.split('|')
            if len(parts) >= 4:
                receivedName = parts[0]
                # validate filename from server
                if not validateFilename(receivedName):
                    print('[error] server sent invalid filename')
                    return False
                fileName = receivedName
                # safely parse numbers
                # error handling
                try:
                    fileSize = int(parts[1])
                    numChunks = int(parts[2])
                except ValueError:
                    print('[error] invalid file info from server (bad numbers)')
                    return False
                serverMD5 = parts[3]
            else:
                print('[error] invalid file info format from server')
                return False

            # validate fileSize and numChunks error handling
            if fileSize < 0 or numChunks < 0:
                print('[error] invalid file info from server: size=' +
                      str(fileSize) + ' chunks=' + str(numChunks))
                return False

            print('')
            print('[info] got file info from server')
            print(' filename: ' + fileName)
            print(' size: ' + str(fileSize) + ' bytes (' +
                  str(fileSize // 1024) + ' KB)')
            print(' chunks: ' + str(numChunks))
            print(' server MD5: ' + serverMD5)
            return True

        # skip duplicate ServerHello packets
        # late arrival
        if parsed['pktType'] == typeServerHello:
            continue

    print('[error] could not get file info after ' + str(maxRetry) + ' tries')
    return False


# Output File on Disk
# pre-allocate so we can write chunks at any offset (out of order)

def prepareOutputFile():
    global outputFile
    if not os.path.exists(clientDir):
        os.makedirs(clientDir)

    outputPath = os.path.join(clientDir, fileName)

    # create file and pre allocate to expected size
    f = open(outputPath, 'wb')
    if fileSize > 0:
        f.seek(fileSize - 1)
        f.write(b'\x00')
    f.close()

    # reopen for random access writing
    outputFile = open(outputPath, 'r+b')

    print('')
    print('[prepare] output file ready: ' + outputPath)
    print('  pre allocated ' + str(fileSize) + ' bytes')


# write chunk to correct position
# offset = seqNum x chunkSize, handles out of order

def writeChunkToDisk(seqNum, data):
    # returns True if write succeess, False if  failed
    # caller only add to receivedSet if True
    global outputFile
    try:
        offset = seqNum * chunkSize
        outputFile.seek(offset)
        outputFile.write(data)
        return True
    except Exception as e:
        print(' [error] failed to write chunk #' + str(seqNum) + ': ' + str(e))
        return False


# send cumulative ACK
# encrypt ACK with AEAD same as data packets
def sendCumulativeAck(sock):
    global ackCount

    if securityEnabled and sessionKey is not None:
        # encrypt the ack number
        ackData = struct.pack('!I', expectedSeq)
        encAck = encryptData(sessionKey, ackData,
                             sessionId, typeAck, 0, expectedSeq)
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeAck, 0, expectedSeq, encAck)
    else:
        # Phase 1
        # plain ACK (just seq and ack)
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeAck, 0, expectedSeq)

    ackCount = ackCount + 1


# send FIN_ACK with security counters + SHA-256 result
# so server report shows accurate numbers#
# payload: chunks(4) + aeadFail(4) + replayDrop(4) + sha256Flag(1) (1=match, 0=no match)
def sendFinAck(sock):
    if securityEnabled and sessionKey is not None:
        sha256Flag = 1 if sha256Match else 0
        confirmData = struct.pack('!IIIB',
            numChunks,
            aeadFailCount,
            replayDropCount,
            sha256Flag
        )
        encConfirm = encryptData(sessionKey, confirmData,
                                 sessionId, typeFinAck, 0, numChunks)
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeFinAck, 0, numChunks, encConfirm)
    else:
        # Phase 1: plain FIN_ACK
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeFinAck, 0, numChunks)


# Send Encrypted SHA Confirm
# tell server we got SHA-256 hash
def sendShaConfirm(sock):
    if securityEnabled and sessionKey is not None:
        confirmData = b'SHA256-OK'
        encConfirm = encryptData(sessionKey, confirmData,
                                 sessionId, typeShaConfirm, 0, 0)
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeShaConfirm, 0, 0, encConfirm)
    else:
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeShaConfirm, 0, 0)


# decrypt received data packet
# returns plaintext if AEAD ok
# None if tampered/forged
def decryptReceivedData(parsed):
    global aeadFailCount

    if not securityEnabled or sessionKey is None:
        # Phase 1no encryption, data is plaintext
        return parsed['data']

    encData = parsed['data']
    plaintext = decryptData(sessionKey, encData,
                            sessionId, typeData,
                            parsed['seqNum'], 0)

    if plaintext is None:
        # AEAD failed = tampered, forged, or wrong key
        aeadFailCount = aeadFailCount + 1
        if showDebug:
            print(' [security] AEAD Fail for seq=' +
                  str(parsed['seqNum']) + '! packet dropped.')
        return None

    return plaintext


# ack Sender thread (Client side multithreading)
# sends periodic ACKs (0.5s) so server knows our progress
def ackSenderThread(sock):
    while not isDone:
        time.sleep(0.5)
        if not isDone and expectedSeq > 0:
            clientLock.acquire()
            try:
                sendCumulativeAck(sock)
            finally:
                clientLock.release()


# Receive Data Packets from Server
# main receive loop
# with all validation checks
#
#  receiver validation order (defense in depth):
#    1. bounds check: seqNum >= numChunks? (invalid file range)
#    2. window check: seqNum > expectedSeq + limit? (way out of window)
#       Phase 1: drop immediately (no AEAD to catch it)
#       Phase 2: let it pass to AEAD (so forged packets increment
#                aeadFailCount correctly for Test 5)
#    3. replay check: seqNum already in receivedSet? (duplicate)
#    4. AEAD decrypt: tampered/forged/wrong key? (integrity)
#    5. write valid data to disk
#    6. send cumulative ACK periodically
# ============================================================

def receiveData(sock):
    global expectedSeq, isDone
    global validCount, duplicateCount, outOfOrderCount
    global serverSHA256, sha256Match
    global aeadFailCount, replayDropCount

    print('')
    print('[receive] starting to receive data (' +
          str(numChunks) + ' chunks expected)')
    if securityEnabled:
        print(' decryption: AES-256-GCM (AEAD)')
        print(' replay protection: receivedSet + window limit (' + str(recvWindowLimit) + ')')

    # handle empty
    if numChunks == 0:
        print('[done] empty file, no chunks to receive')
        return

    # periodic ACK sender thread (multithreading)
    ackThread = threading.Thread(target=ackSenderThread, args=(sock,))
    ackThread.daemon = True
    ackThread.start()

    sock.settimeout(timeoutValue * 3)
    timeoutCount = 0
    lastAckTime = time.time()
    sinceLastAck = 0

    while not isDone:
        try:
            parsed = recvPacket(sock, clientPort, timeout=timeoutValue * 3)

            if parsed is None:
                timeoutCount = timeoutCount + 1
                if timeoutCount > maxTimeouts:
                    print('')
                    print('[timeout] too many timeouts (' + str(maxTimeouts) + '), stopping')
                    break
                # send ACK so server know still here
                clientLock.acquire()
                try:
                    sendCumulativeAck(sock)
                finally:
                    clientLock.release()
                lastAckTime = time.time()
                continue

            timeoutCount = 0  # reset timeout counter (receive packet)

            # SHA 256 verification
            if parsed['pktType'] == typeShaVerify:
                print('')
                print('[sha-256] received SHA-256 hash from server')
                if securityEnabled and sessionKey is not None:
                    shaPlain = decryptData(sessionKey, parsed['data'],
                                           sessionId, typeShaVerify,
                                           parsed['seqNum'], 0)
                    if shaPlain is not None:
                        serverSHA256 = shaPlain.decode('utf-8')
                        print(' server SHA-256: ' + serverSHA256)
                        clientLock.acquire()
                        try:
                            sendShaConfirm(sock)
                        finally:
                            clientLock.release()
                    else:
                        print(' [security] SHA-256 packet AEAD failed')
                        aeadFailCount = aeadFailCount + 1
                continue

            # FIN packet
            if parsed['pktType'] == typeFin:
                # only accept FIN if got all chunks
                if expectedSeq < numChunks:
                    # not ready
                    # send ACK so server know progress
                    clientLock.acquire()
                    try:
                        sendCumulativeAck(sock)
                    finally:
                        clientLock.release()
                    lastAckTime = time.time()
                    sinceLastAck = 0
                    continue

                print('')
                print('[fin] received finish signal from server')

                # verify FIN with AEAD before accept
                if securityEnabled and sessionKey is not None:
                    finPlain = decryptData(sessionKey, parsed['data'],
                                           sessionId, typeFin,
                                           parsed['seqNum'], 0)
                    if finPlain is None:
                        # AEAD failed on FIN
                        # forged
                        aeadFailCount = aeadFailCount + 1
                        if showDebug:
                            print('  [security] FIN packet AEAD failed, ignore')
                        continue

                # calc SHA-256 on receive file before FIN_ACK
                # so sha256Match in FIN_ACK is real result
                if outputFile is not None:
                    outputFile.flush()
                    os.fsync(outputFile.fileno())  # force data to disk
                    # exact file size
                    outputFile.truncate(fileSize)
                    outputFile.flush()
                    os.fsync(outputFile.fileno())
                if securityEnabled and serverSHA256 != '':
                    outputPath = os.path.join(clientDir, fileName)
                    receivedSHA = calculateSHA256(outputPath)
                    sha256Match = (receivedSHA == serverSHA256)
                    if sha256Match:
                        print('[sha-256] pre-FIN_ACK verify: MATCH')
                    else:
                        print('[sha-256] pre-FIN_ACK verify: MISMATCH')

                # send encrypted FIN_ACK with counters + sha256 result
                # 5 copy (UDP might drop some)
                clientLock.acquire()
                try:
                    for i in range(5):
                        sendFinAck(sock)
                        time.sleep(0.01)
                finally:
                    clientLock.release()
                print('[fin] FIN_ACK sent (with security counters)')
                isDone = True
                break

            # only process data packet from here
            if parsed['pktType'] != typeData:
                continue

            seqNum = parsed['seqNum']

            # check valid file range
            # seq are 0 to numChunks-1
            # anything >= numChunks is not real file chunk


            # Phase 1 no AEAD safety net
            if seqNum >= numChunks:
                if not securityEnabled:
                    if showDebug:
                        print('  invalid seq=' + str(seqNum) +
                              ' >= numChunks=' + str(numChunks) + ', dropped')
                    continue
                # Phase 2 fall through to AEAD below

            # check receiver window
            # Phase 1: block immediately
            # Phase 2: through to AEAD so forged packets increment aeadFailCount
            if seqNum > expectedSeq + recvWindowLimit:
                if not securityEnabled:
                    if showDebug:
                        print('  out-of-window: seq=' + str(seqNum) + ', dropped')
                    continue
                # Phase 2: fall through to AEAD

            # check replay protection
            # reject already received seq numbers
            if seqNum in receivedSet:
                duplicateCount = duplicateCount + 1
                if securityEnabled:
                    replayDropCount = replayDropCount + 1
                    if showDebug and replayDropCount <= 10:
                        print('  [security] replay dropped: seq=' + str(seqNum))
                # still ACK so server can move window
                clientLock.acquire()
                try:
                    sendCumulativeAck(sock)
                finally:
                    clientLock.release()
                lastAckTime = time.time()
                sinceLastAck = 0
                continue

            # check decrypt data with AEAD
            data = decryptReceivedData(parsed)
            if data is None:
                # dont write bad data to file
                continue

            # extra safety
            # if AEAD pass but seq is beyond file range
            if seqNum >= numChunks:
                if showDebug:
                    print('  [security] AEAD ok but seq=' + str(seqNum) +
                          ' >= numChunks=' + str(numChunks) + ', dropped')
                continue

            # handle in order and out order
            if seqNum == expectedSeq:
                # in order: write to disk, advance expectedSeq
                writeOk = writeChunkToDisk(seqNum, data)
                if writeOk:
                    receivedSet.add(seqNum)
                    validCount = validCount + 1
                    sinceLastAck = sinceLastAck + 1
                    # advance past any buffered out of order
                    while expectedSeq in receivedSet:
                        expectedSeq = expectedSeq + 1

            elif seqNum > expectedSeq:
                # out of order, write at correct offset
                writeOk = writeChunkToDisk(seqNum, data)
                if writeOk:
                    receivedSet.add(seqNum)
                    validCount = validCount + 1
                    outOfOrderCount = outOfOrderCount + 1
                    sinceLastAck = sinceLastAck + 1

            else:
                # seqNum < expectedSeq and not in receivedSet
                # very late retransmission, treat as duplicate
                duplicateCount = duplicateCount + 1
                if securityEnabled:
                    replayDropCount = replayDropCount + 1

            # send cumulative ACK periodically
            shouldAck = False
            if seqNum < expectedSeq:
                # just completed in order batch
                shouldAck = True
            if sinceLastAck >= ackEvery:
                # every N packets
                shouldAck = True
            if time.time() - lastAckTime > 0.5:
                # timer based
                shouldAck = True

            if shouldAck:
                clientLock.acquire()
                try:
                    sendCumulativeAck(sock)
                finally:
                    clientLock.release()
                lastAckTime = time.time()
                sinceLastAck = 0

            # print progress
            if expectedSeq % printEvery == 0 or expectedSeq >= numChunks:
                if numChunks > 0:
                    progress = expectedSeq * 100 // numChunks
                else:
                    progress = 0
                print(' progress: ' + str(expectedSeq) + '/' +
                      str(numChunks) + ' [' + str(progress) + '%]')

            # check all chunks received
            if expectedSeq >= numChunks:
                print('')
                print('[done] all ' + str(numChunks) + ' chunks received!')
                # send multiple ACK make sure server get at least one
                clientLock.acquire()
                try:
                    for i in range(5):
                        sendCumulativeAck(sock)
                        time.sleep(0.01)
                finally:
                    clientLock.release()

        except Exception as e:
            timeoutCount = timeoutCount + 1
            if timeoutCount > maxTimeouts:
                break
            # send ACK on timeout so server know progress
            clientLock.acquire()
            try:
                sendCumulativeAck(sock)
            finally:
                clientLock.release()
            lastAckTime = time.time()

    # print final stats
    print('')
    print('[stats] valid=' + str(validCount) +
          ', duplicate=' + str(duplicateCount) +
          ', outOfOrder=' + str(outOfOrderCount) +
          ', acksSent=' + str(ackCount))
    if securityEnabled:
        print('  AEAD failures=' + str(aeadFailCount) +
              ', replay drops=' + str(replayDropCount))


# verify receive file with MD5 + SHA-256
def verifyFile():
    global outputFile, sha256Match

    print('')
    print('[verify] checking received file')

    # close file handle
    # flush all data to disk
    if outputFile is not None:
        outputFile.flush()
        os.fsync(outputFile.fileno())  # all data to disk
        # remove any stale pre allocation zero
        # last chunk may smaller than chunkSize
        outputFile.truncate(fileSize)
        outputFile.close()
        outputFile = None

    outputPath = os.path.join(clientDir, fileName)

    # check for missing chunks
    missing = 0
    for seq in range(numChunks):
        if seq not in receivedSet:
            missing = missing + 1
            if missing <= 10:
                print(' missing chunk #' + str(seq))

    if missing == 0:
        print('[verify] all ' + str(numChunks) + ' chunks received')
    else:
        print('[verify] Warning: ' + str(missing) + ' chunks missing')

    # MD5 verification
    receivedMD5 = calculateMD5(outputPath)
    print('')
    print('[MD5 verify]')
    print(' server MD5:   ' + serverMD5)
    print(' received MD5: ' + receivedMD5)
    md5Ok = (receivedMD5 == serverMD5)
    if md5Ok:
        print(' result: MD5 MATCH')
    else:
        print(' result: MD5 MISMATCH')

    # SHA-256 verification
    if securityEnabled and serverSHA256 != '':
        receivedSHA256 = calculateSHA256(outputPath)
        print('')
        print('[SHA-256 verify]')
        print(' server SHA-256:   ' + serverSHA256)
        print(' received SHA-256: ' + receivedSHA256)
        sha256Match = (receivedSHA256 == serverSHA256)
        if sha256Match:
            print(' result: SHA-256 match')
        else:
            print(' result: SHA-256 Mismatch')
    elif securityEnabled:
        # server SHA 256 not receive
        # cannot verify
        print('[sha-256] server hash not received, SHA-256 not verified')
        sha256Match = False

    return md5Ok


#  Print client security summary

def printSecurityReport():
    print('')
    print('')
    print(' Security Report (Client Side)')
    print('')
    print('  Security enabled (PSK + AEAD): ' + ('Yes' if securityEnabled else 'No'))
    print('  Handshake status: ' + ('Success' if handshakeOk else 'Fail'))
    print('  AEAD authentication failures (invalid packets dropped): ' + str(aeadFailCount))
    print('  Replay drops (duplicate/out-of-window packets): ' + str(replayDropCount))
    print('  SHA-256 match: ' + ('Yes' if sha256Match else 'No'))
    print('')
    print('')


# main

if __name__ == '__main__':

    print('')
    print('')
    print(' Weiting Liu, Youran Ye, Jingkai Liu, Yinfei Lu ')
    print(' CS5700 SRFT Client ')
    if securityEnabled:
        print(' Phase 2: Secure Reliable File Transfer')
    else:
        print(' Phase 1: Reliable File Transfer')
    print('')
    print('')

    # check command line args
    if len(sys.argv) < 2:
        print('usage: python3 SRFT_UDPClient.py <filename>')
        print(' example: python3 SRFT_UDPClient.py test_10mb_file')
        print(' example: python3 SRFT_UDPClient.py test_100mb_file')
        sys.exit(1)

    fileName = sys.argv[1]

    # validate filename before send
    if not validateFilename(fileName):
        print('[error] invalid filename. exiting.')
        sys.exit(1)

    # validate PSK length (warn only)
    if securityEnabled:
        if not validatePsk(psk):
            print('[warning] PSK may cause handshake failure (see above)')
            print('  client will continue')

    print('requesting file: ' + fileName)

    # create client socket
    print('')
    print('[socket] creating client socket')
    mySocket = createClientSocket()
    print('  client socket created')

    try:
        # send file request to server
        requestFile(mySocket, fileName)

        # Phase 2 security handshake
        if securityEnabled:
            success = doSecurityHandshake(mySocket)
            if not success:
                print('')
                print('[error] handshake failed and connection rejected.')
                printSecurityReport()
                mySocket.close()
                sys.exit(1)

        # wait for file info
        if not waitForFileInfo(mySocket, fileName):
            print('[exit] could not get file info from server')
            mySocket.close()
            sys.exit(1)

        # prepare output file on disk
        prepareOutputFile()

        # receive all data packet
        receiveData(mySocket)

        # verify received file (MD5 + SHA-256)
        success = verifyFile()

        print('')
        print('')
        if success:
            print(' File Transfer successful')
        else:
            print(' Warnning: file transfer may be incomplete')
        print('')

        # print security summary
        if securityEnabled:
            printSecurityReport()

    except KeyboardInterrupt:
        print('')
        print('client stopped')
    except Exception as e:
        print('')
        print('error: ' + str(e))
        import traceback
        traceback.print_exc()
    finally:
        if outputFile is not None:
            outputFile.close()
        mySocket.close()
        print('socket closed')