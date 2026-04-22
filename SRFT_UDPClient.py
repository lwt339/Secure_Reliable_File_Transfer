# client


import os
import sys
import time
import struct
import threading

from socket import *
from config import *
import config
from packet_helper import *
import packet_helper




# receive
receivedSet = set()
outputFile = None
expectedSeq = 0

# file info
fileName = ''
fileSize = 0
numChunks = 0
serverMD5 = ''
receivedMD5 = ''

# transfer
isDone = False
ackCount = 0

# packet stat
validCount = 0
duplicateCount = 0
outOfOrderCount = 0
totalRecvCount = 0

# timing
startTime = 0.0
endTime = 0.0

# security

# AES 256
sessionKey = None
# 8B from handshake
sessionId = None
# nonce
clientNonce = None
handshakeOk = False

# security counters

# AEAD fail (tampered/forged)
aeadFailCount = 0
# replay/duplicate/out of window drops
replayDropCount = 0

# SHA 256 verif
serverSHA256 = ''
sha256Match = False

# thread lock
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
def doSecurityHandshake(sock):
    global sessionKey, sessionId, clientNonce, handshakeOk

    print('')
    print(' Phase 2: Security Handshake')
    print('')

    # ClientHello ( nonce + HMAC using PSK)
    print('[handshake] building ClientHello')
    helloData, clientNonce = buildClientHello(psk)

    print('[handshake] sending ClientHello to server')
    # send 3 copy
    # UDP might drop one
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
            sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                       typeClientHello, 0, 0, helloData)
            continue

        if parsed['pktType'] == typeServerHello:
            print('[handshake] receive ServerHello')
            # verify server HMAC (proves same PSK)
            serverNonce, sessionId = parseServerHello(
                psk, parsed['data'], clientNonce)

            if serverNonce is None:
                print('[handshake] Failed b/c server PSK mismatch')
                handshakeOk = False
                return False

            print('[handshake] server authenticated ok')
            break

    if serverNonce is None:
        print('[handshake] Failed b/c no ServerHello received after ' + str(maxRetry) + ' tries')
        handshakeOk = False
        return False

    sessionKey = deriveSessionKey(psk, clientNonce, serverNonce)
    print('[handshake] session key derived (HKDF-SHA256)')
    print(' session ID: ' + sessionId.hex())
    print(' enc_key (first 8 bytes): ' + sessionKey[0:8].hex() + '...')

    set_session_cipher(config.cipherInfo)

    handshakeOk = True
    print('')
    print('[handshake] Success and secure session established')
    print(' cipher: ' + config.cipherInfo + ' (AEAD)')
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
# pre allocate so we can write chunks at any offset (out of order)
def prepareOutputFile():
    global outputFile
    if not os.path.exists(clientDir):
        try:
            os.makedirs(clientDir)
        except OSError as e:
            print('[error] prepareOutputFile: cannot create clientDir ' +
                  repr(clientDir))
            print('        ' + str(e))
            raise

    outputPath = os.path.join(clientDir, fileName)

    try:
        f = open(outputPath, 'wb')
        if fileSize > 0:
            f.seek(fileSize - 1)
            f.write(b'\x00')
        f.close()
    except OSError as e:
        print('[error] prepareOutputFile: cannot create/preallocate file ' +
              repr(outputPath))
        print('        fileSize=' + str(fileSize))
        print('        ' + str(e))
        raise

    try:
        outputFile = open(outputPath, 'r+b')
    except OSError as e:
        print('[error] prepareOutputFile: cannot reopen for r+b ' +
              repr(outputPath))
        print('        ' + str(e))
        raise

    print('')
    print('[prepare] output file ready: ' + outputPath)
    print('  pre allocated ' + str(fileSize) + ' bytes')


# write chunk to correct position
# offset = seqNum x chunkSize, handles out of order
def writeChunkToDisk(seqNum, data):
    # returns True if write succeess, False if  failed
    global outputFile
    offset = seqNum * chunkSize
    try:
        outputFile.seek(offset)
        outputFile.write(data)
        return True
    except Exception as e:
        print('[error] writeChunkToDisk failed')
        print('        seqNum=' + str(seqNum) +
              ', offset=' + str(offset) +
              ', len(data)=' + str(len(data)))
        print('        ' + type(e).__name__ + ': ' + str(e))
        return False


# send cumulative ACK
# encrypt ACK with AEAD same as data packets
def sendCumulativeAck(sock):
    global ackCount

    currentAck = expectedSeq
    if securityEnabled and sessionKey is not None:
        # encrypt ack number
        ackData = struct.pack('!I', currentAck)
        encAck = encryptData(sessionKey, ackData,
                             sessionId, typeAck, 0, currentAck)
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeAck, 0, currentAck, encAck)
    else:
        # Phase 1
        # plain ACK
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeAck, 0, currentAck)

    ackCount = ackCount + 1


# send FIN_ACK with security counters + SHA-256 result
# chunks(4) + aeadFail(4) + replayDrop(4) + sha256Flag(1) (1=match, 0=no match)
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
        # Phase 1 plain FIN_ACK
        sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                   typeFinAck, 0, numChunks)


# Send Encrypted SHA Confirm
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



# returns plaintext if AEAD ok
# None if tampered/forged
def decryptReceivedData(parsed):
    global aeadFailCount

    if not securityEnabled or sessionKey is None:
        # Phase 1 no encryption, data is plaintext
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
        time.sleep(0.05)
        if not isDone and expectedSeq > 0:
            clientLock.acquire()
            try:
                sendCumulativeAck(sock)
            finally:
                clientLock.release()


# Receive Data Packets from Server
# main receive loop with all validation checks
def receiveData(sock):
    global expectedSeq, isDone
    global validCount, duplicateCount, outOfOrderCount, totalRecvCount
    global serverSHA256, sha256Match
    global aeadFailCount, replayDropCount
    global startTime, endTime

    print('')
    print('[receive] starting to receive data (' +
          str(numChunks) + ' chunks expected)')
    if securityEnabled:
        print(' decryption: ' + get_session_cipher() + ' (AEAD)')
        print(' replay protection: receivedSet + window limit (' + str(recvWindowLimit) + ')')

    # start client timer
    startTime = time.time()

    if numChunks == 0:
        endTime = time.time()
        print('[done] empty file, no chunks to receive')
        return

    # periodic ACK sender thread
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

            timeoutCount = 0

            totalRecvCount = totalRecvCount + 1

            # SHA 256
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

                # verify FIN with AEAD
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

                # calc SHA-256 receive file before FIN_ACK
                if outputFile is not None:
                    outputFile.flush()
                    os.fsync(outputFile.fileno())
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
                endTime = time.time()
                isDone = True
                break

            # process data packet
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

            # check receiver window
            # Phase 1 block immediately
            # Phase 2 through to AEAD forged packets increment aeadFailCount
            if seqNum > expectedSeq + recvWindowLimit:
                if not securityEnabled:
                    if showDebug:
                        print('  out-of-window: seq=' + str(seqNum) + ', dropped')
                    continue
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
                # duplicate
                duplicateCount = duplicateCount + 1
                if securityEnabled:
                    replayDropCount = replayDropCount + 1

            # send cumulative ACK periodically
            shouldAck = False
            if seqNum < expectedSeq:
                shouldAck = True
            if sinceLastAck >= ackEvery:
                shouldAck = True
            if time.time() - lastAckTime > 0.5:
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
                # send multiple ACK
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
            # send ACK on timeout
            clientLock.acquire()
            try:
                sendCumulativeAck(sock)
            finally:
                clientLock.release()
            lastAckTime = time.time()

    # if exit
    if endTime <= 0:
        endTime = time.time()

    # print final stats
    print('')
    print('[stats] valid=' + str(validCount) +
          ', duplicate=' + str(duplicateCount) +
          ', outOfOrder=' + str(outOfOrderCount) +
          ', acksSent=' + str(ackCount))
    if securityEnabled:
        print('  AEAD failures=' + str(aeadFailCount) +
              ', replay drops=' + str(replayDropCount))


# verify MD5 + SHA-256
def verifyFile():
    global outputFile, sha256Match, receivedMD5

    print('')
    print('[verify] checking received file')

    # flush all data to disk
    if outputFile is not None:
        outputFile.flush()
        os.fsync(outputFile.fileno())
        # remove any stale pre allocation zero
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

    # MD5
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

    # SHA-256
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
        # SHA 256 not receive
        print('[sha-256] server hash not received, SHA-256 not verified')
        sha256Match = False

    return md5Ok



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


# client side report
def writeClientReport():
    if endTime > 0 and startTime > 0 and endTime >= startTime:
        duration = endTime - startTime
    else:
        duration = 0.0

    # rchecksum error
    checksumErrors = packet_helper.checksumErrorCount

    # test label
    if config.attackMode == 'wrongpsk':
        testLabel = 'Test 2 Wrong PSK (Authentication Failure)'
    elif not securityEnabled:
        testLabel = 'Phase 1 Reliable Transfer (no security)'
    elif not handshakeOk:
        testLabel = 'Test 2 Wrong PSK (Authentication Failure)'
    elif config.attackMode == 'tamper':
        testLabel = 'Test 3 Tamper Detection (Integrity)'
    elif config.attackMode == 'replay':
        testLabel = 'Test 4 Replay Protection'
    elif config.attackMode == 'inject':
        testLabel = 'Test 5 Forged Injection'
    else:
        testLabel = 'Phase 2 Test'

    barLine = '-' * 60
    lines = []
    lines.append('')
    lines.append(barLine)
    lines.append('CLIENT REPORT')
    lines.append(barLine)
    lines.append('Test: ' + testLabel)
    lines.append('Timestamp: ' + time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() - 14400)))
    lines.append('')

    # transfer metadata
    lines.append('Name of the transferred file:            ' +
                 (fileName if fileName != '' else 'N/A'))
    lines.append('Size of the transferred file:            ' +
                 str(fileSize) + ' bytes')
    lines.append('Number of packets received from server:  ' +
                 str(totalRecvCount))
    lines.append('Number of duplicate packets:             ' +
                 str(duplicateCount))
    lines.append('Number of out-of-order packets:          ' +
                 str(outOfOrderCount))
    lines.append('Number of packets with checksum errors:  ' +
                 str(checksumErrors))
    lines.append('Time duration of the file transfer:      ' +
                 formatTime(duration))
    lines.append('Received file MD5:                       ' +
                 (receivedMD5 if receivedMD5 != '' else 'N/A'))


    # phase 1 = no security = skip AEAD/SHA-256 lines
    if securityEnabled:
        lines.append('')
        lines.append('Phase 2 security fields')
        lines.append('Security enabled (PSK + AEAD):                        Yes')
        lines.append('Handshake status:                                     ' +
                     ('Success' if handshakeOk else 'Fail'))
        lines.append('AEAD authentication failures (invalid packets drop):  ' +
                     str(aeadFailCount))
        lines.append('Replay drops (duplicate/out-of-window packets):       ' +
                     str(replayDropCount))
        lines.append('SHA-256 match:                                        ' +
                     ('Yes' if sha256Match else 'No'))
        if config.attackMode != 'none':
            lines.append('Attack test mode:                                     ' +
                         config.attackMode)
    else:
        # phase 1
        lines.append('')
        lines.append('Phase 1 (security off)')
        lines.append('Security enabled (PSK + AEAD):                        No')

    lines.append(barLine)
    lines.append('')

    report = '\n'.join(lines)
    print(report)

    try:
        with open(clientReportPath, 'a') as f:
            f.write(report + '\n')
        print('client report saved to ' + clientReportPath)
    except PermissionError:
        altPath = os.path.expanduser('~/Client_Report.txt')
        try:
            with open(altPath, 'a') as f:
                f.write(report + '\n')
            print('client report saved to ' + altPath)
            print('  (permission denied on ' + clientReportPath + ', used ' + altPath + ')')
            print('  tip: sudo chmod 666 ' + clientReportPath)
        except Exception as e2:
            print('warning: could not save client report: ' + str(e2))
    except Exception as e:
        print('warning: could not save client report: ' + str(e))


def parse_client_argv(argv):
    args = list(argv)
    if len(args) < 1:
        return None
    if '--cipher' in args:
        i = args.index('--cipher')
        if i + 1 >= len(args):
            print('[error] --cipher requires a value (aes-gcm or chacha)')
            return None
        val = args[i + 1].lower()
        args = args[0:i] + args[i + 2:]
        if val in ('aes-gcm', 'aes', 'gcm'):
            config.cipherInfo = CIPHER_AES_GCM
        elif val in ('chacha', 'chacha20', 'chacha20-poly1305'):
            config.cipherInfo = CIPHER_CHACHA
        else:
            print('[error] unknown --cipher ' + repr(val))
            print('  use: aes-gcm | chacha')
            return None
    if len(args) != 1:
        return None
    return args[0]


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

    # reset checksum error counter
    packet_helper.resetChecksumErrorCount()

    if len(sys.argv) < 2:
        print('usage: python3 SRFT_UDPClient.py [--cipher aes-gcm|chacha] <filename>')
        print(' example: python3 SRFT_UDPClient.py test_10mb_file')
        print(' example: python3 SRFT_UDPClient.py --cipher chacha test_10mb_file')
        sys.exit(1)

    fileName = parse_client_argv(sys.argv[1:])
    if fileName is None:
        print('usage: python3 SRFT_UDPClient.py [--cipher aes-gcm|chacha] <filename>')
        print(' example: python3 SRFT_UDPClient.py test_10mb_file')
        print(' example: python3 SRFT_UDPClient.py --cipher chacha test_10mb_file')
        sys.exit(1)

    # filename before send
    if not validateFilename(fileName):
        print('[error] invalid filename. exiting.')
        sys.exit(1)

    # PSK length
    if securityEnabled:
        if not validatePsk(psk):
            print('[warning] PSK may cause handshake failure (see above)')
            print('  client will continue')

    print('requesting file: ' + fileName)
    if securityEnabled:
        print(' AEAD cipher: ' + config.cipherInfo)

    # client socket
    print('')
    print('[socket] creating client socket')
    mySocket = createClientSocket()
    print('  client socket created')

    try:
        # file request to server
        requestFile(mySocket, fileName)

        # Phase 2 security handshake
        if securityEnabled:
            success = doSecurityHandshake(mySocket)
            if not success:
                print('')
                print('[error] handshake failed and connection rejected.')
                printSecurityReport()
                startTime = time.time()
                endTime = startTime
                writeClientReport()
                mySocket.close()
                sys.exit(1)

        # wait file info
        if not waitForFileInfo(mySocket, fileName):
            print('[exit] could not get file info from server')
            mySocket.close()
            sys.exit(1)

        # output file on disk
        prepareOutputFile()

        # receive
        receiveData(mySocket)

        # verify
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

        writeClientReport()

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