# Sever

import os
import sys
import time
import struct
import threading

from socket import *
from config import *
from packet_helper import *


# packet counters
totalSent = 0
totalRetransmit = 0
totalReceived = 0

# security counter
aeadFailCount = 0
replayDropCount = 0

# client security counter
# attacks go from server to client, so client detect them
# client send back inside encrypted FIN_ACK
clientAeadFailCount = 0
clientReplayDropCount = 0
clientSha256Match = False

# timing
startTime = 0.0
endTime = 0.0

# sliding window
# windowBase = first unack seq number
# nextToSend = next seq number to send
# when get ACK for seq N, windowBase moves to N
windowBase = 0
nextToSend = 0
isDone = False

# thread safety
lastWindowMoveTime = 0.0
windowLock = threading.Lock()

# file info
filePath = ''
numChunks = 0


# keep file open instead of opening/closing during transferr
# make faster for large file
serverFileHandle = None

# server socket ref
serverSocket = None

# client address
# saved on first request
savedClientIP = ''
savedClientPort = 0

# Phase 2 security session state

# HKDF derived key
sessionKey = None
# random session ID
sessionId = None
handshakeOk = False

# attack test mode

# saved packet for replay
attackPacketSaved = None
attackDone = False

# attack mode from config (--attack flag)
currentAttackMode = attackMode

# lock for counter increments (multiple threads touch these)
counterLock = threading.Lock()

def addSent(count=1):
    global totalSent
    counterLock.acquire()
    try:
        totalSent = totalSent + count
    finally:
        counterLock.release()

def addRetransmit(count=1):
    global totalRetransmit
    counterLock.acquire()
    try:
        totalRetransmit = totalRetransmit + count
    finally:
        counterLock.release()

def addReceived(count=1):
    global totalReceived
    counterLock.acquire()
    try:
        totalReceived = totalReceived + count
    finally:
        counterLock.release()

def addAeadFail(count=1):
    # thread safe increment for AEAD fail counter
    # called ACK receiver thread and sendFinish
    global aeadFailCount
    counterLock.acquire()
    try:
        aeadFailCount = aeadFailCount + count
    finally:
        counterLock.release()


# wait for client to send filename request

def waitForRequest(sock):
    global savedClientIP, savedClientPort

    print('')
    print('[wait] server listening on ' + serverIP + ':' + str(serverPort))
    print(' waiting for client to connect')

    while True:
        parsed = recvPacket(sock, serverPort, timeout=None)
        if parsed is None:
            continue
        # check if is a file request
        if parsed['pktType'] == typeFilename:
            filename = parsed['data'].decode('utf-8')
            savedClientIP = parsed['srcIP']
            savedClientPort = parsed['srcPort']
            addReceived()
            print('')
            print('[got] received file request')
            print(' client: ' + savedClientIP + ':' + str(savedClientPort))
            print(' file requested: ' + filename)
            return filename


# security handshake (server side)
#  from project: before file transfer, perform a handshake

def doSecurityHandshake(sock):
    global sessionKey, sessionId, handshakeOk

    print('')
    print('')
    print('  Phase 2: Security Handshake')
    print('')

    # wait for ClientHello
    print('[handshake] waiting for ClientHello')
    clientNonce = None
    for attempt in range(maxRetry):
        parsed = recvPacket(sock, serverPort, timeout=5)
        if parsed is None:
            print(' timeout (' + str(attempt + 1) + '/' + str(maxRetry) + ')')
            continue
        if parsed['pktType'] == typeClientHello:
            addReceived()
            print('[handshake] received ClientHello')
            # verify HMAC
            # check if client knows PSK
            clientNonce = parseClientHello(psk, parsed['data'])
            if clientNonce is None:
                # HMAC failed = client has different PSK
                print('[handshake] Failed b/c client PSK mismatch!')
                handshakeOk = False
                return False
            print('[handshake] client authenticated ok')
            break
        else:
            addReceived()

    if clientNonce is None:
        print('[handshake] Failed b/c no ClientHello received after ' + str(maxRetry) + ' tries')
        handshakeOk = False
        return False

    # send ServerHello
    print('[handshake] sending ServerHello')
    helloData, serverNonce, sessionId = buildServerHello(psk, clientNonce)
    # 3 copy
    for i in range(3):
        sendPacket(sock, savedClientIP, savedClientPort,
                   serverIP, serverPort,
                   typeServerHello, 0, 0, helloData)
        addSent()
        time.sleep(0.05)
    print('[handshake] ServerHello sent (x3)')

    # derive session key using HKDF
    sessionKey = deriveSessionKey(psk, clientNonce, serverNonce)
    print('[handshake] session key derived (HKDF-SHA256)')
    print('  session ID: ' + sessionId.hex())
    print('  enc_key (first 8 bytes): ' + sessionKey[0:8].hex() + '...')

    handshakeOk = True
    print('')
    print('[handshake] Success secure session established')
    print('  cipher: AES-256-GCM (AEAD)')
    print('')
    return True


# send file info to client
# tell client: filename, size, number of chunks, MD5 hash

def sendFileInfo(sock, filename, fSize, nChunks, md5Hash):
    # pack file info
    infoStr = filename + '|' + str(fSize) + '|' + str(nChunks) + '|' + md5Hash
    # send 3 copies
    for i in range(3):
        sendPacket(sock, savedClientIP, savedClientPort,
                   serverIP, serverPort,
                   typeFileInfo, 0, 0, infoStr.encode('utf-8'))
        addSent()
        time.sleep(0.05)
    print('[send] file info sent to client (x3)')


# encrypt chunk before sending (Phase 2)
# Phase 1 just returns raw data=
def prepareDataForSend(chunkData, seqNum):
    if securityEnabled and sessionKey is not None:
        # encrypt with AES-256-GCM
        # AAD includes session_id + type + seq + ack
        return encryptData(sessionKey, chunkData,
                           sessionId, typeData, seqNum, 0)
    else:
        # Phase 1
        return chunkData


# check AEAD on encrypted ACK from client
# if fails we ignore
def verifyAckPacket(parsed):

    if not securityEnabled or sessionKey is None:
        return parsed['ackNum']

    encData = parsed['data']
    if len(encData) == 0:
        # no encrypted payload
        return parsed['ackNum']

    # decrypt ACK
    plaintext = decryptData(sessionKey, encData,
                            sessionId, typeAck,
                            parsed['seqNum'], parsed['ackNum'])
    if plaintext is None:
        # AEAD failed forged or tampered ACK
        addAeadFail()
        if showDebug:
            print('  [security] ACK AEAD failed, dropped.')
        return None

    # extract real ack number from decrypted data
    if len(plaintext) >= 4:
        realAck = struct.unpack('!I', plaintext[0:4])[0]
        return realAck
    return parsed['ackNum']


# check AEAD on control packets (FIN_ACK, SHA_CONFIRM)
def verifyControlPacket(parsed):

    if not securityEnabled or sessionKey is None:
        return b'OK'  # Phase 1 just accept

    encData = parsed['data']
    if len(encData) == 0:
        return b'OK'

    # decrypt
    # use packet own type as part of AAD
    plaintext = decryptData(sessionKey, encData,
                            sessionId, parsed['pktType'],
                            parsed['seqNum'], parsed['ackNum'])
    if plaintext is None:
        addAeadFail()
        if showDebug:
            print('  [security] control packet AEAD failed! (' +
                  getTypeName(parsed['pktType']) + ') dropped')
        return None

    return plaintext


# attack test functions

# Test 3: tamper = flip 2 bits in encrypted payload
def doTamperAttack(sock, chunkData, seqNum):

    print('')
    print('[ATTACK] tamper attack on seq=' + str(seqNum))
    print('  flipping 2 bits in encrypted payload')

    # first encrypt normal
    # then corrupt the ciphertext
    if securityEnabled and sessionKey is not None:
        payload = encryptData(sessionKey, chunkData,
                              sessionId, typeData, seqNum, 0)
    else:
        payload = chunkData

    # flip 2 bits (0 to 1, 1 to 0)
    if len(payload) > 2:
        tampered = bytearray(payload)
        pos1 = min(15, len(tampered) - 1)
        pos2 = min(20, len(tampered) - 1)
        tampered[pos1] = tampered[pos1] ^ 0x01  # flip bit 0
        tampered[pos2] = tampered[pos2] ^ 0x02  # flip bit 1
        payload = bytes(tampered)
        print(' bits flipped at byte ' + str(pos1) + ' and byte ' + str(pos2))

    # send the corrupted packet
    sendPacket(sock, savedClientIP, savedClientPort,
               serverIP, serverPort, typeData, seqNum, 0, payload)
    addSent()
    print(' tampered packet sent. client should drop it (AEAD fail)')


# Test 4: replay = resend an old packet
def doReplayAttack(sock, savedPkt):

    if savedPkt is None:
        print('[ATTACK] no saved packet to replay')
        return

    print('')
    print('[ATTACK] replay attack: resending old seq=' + str(savedPkt['seqNum']))
    sendPacket(sock, savedClientIP, savedClientPort,
               serverIP, serverPort,
               typeData, savedPkt['seqNum'], 0, savedPkt['data'])
    addSent()
    print(' replayed packet sent. client should reject it (duplicate)')


# Test 5: inject = send forged packet with random bytes
def doInjectAttack(sock):

    print('')
    print('[ATTACK] inject attack: sending forged packet with random bytes')
    fakeData = os.urandom(100)  # random garbage data
    sendPacket(sock, savedClientIP, savedClientPort,
               serverIP, serverPort, typeData, 99999, 0, fakeData)
    addSent()
    print('  forged packet sent (random 100 bytes, seq=99999).')
    print('  client should drop it (AEAD fail).')


# retransmission watcher thread ( after timeout )
# checks if windowBase is stuck longer than timeout
# if so retransmit all unacked packets in window
# try/finally on lock to avoid deadlock

def retransmitWatcher(sock):
    global isDone, lastWindowMoveTime

    lastSeenBase = 0
    while not isDone:
        time.sleep(0.05)  # check every 50ms

        windowLock.acquire()
        try:
            currentBase = windowBase
            currentNext = nextToSend

            # skip empty
            if numChunks == 0:
                continue

            if currentBase > lastSeenBase:
                # window moved forward
                # reset timer
                lastSeenBase = currentBase
                lastWindowMoveTime = time.time()
            elif currentBase < numChunks and currentNext > currentBase:
                # window is stuck (no new ACKs)
                # check timed out
                elapsed = time.time() - lastWindowMoveTime
                if elapsed >= timeoutValue:
                    # timeout retransmit all unacked
                    endSeq = min(currentNext, numChunks)
                    count = endSeq - currentBase
                    print('')
                    print('[timeout] windowBase=' + str(currentBase) +
                          ' stuck for ' + str(round(elapsed, 2)) + 's')
                    print('[timeout] retransmitting ' + str(count) + ' packets')

                    for seq in range(currentBase, endSeq):
                        if seq < numChunks:
                            # use persistent file handle
                            if serverFileHandle is not None:
                                chunkData = readChunkFromHandle(serverFileHandle, seq)
                            else:
                                chunkData = readChunk(filePath, seq)
                            payload = prepareDataForSend(chunkData, seq)
                            sendPacket(sock, savedClientIP, savedClientPort,
                                       serverIP, serverPort,
                                       typeData, seq, 0, payload)
                            addSent()
                            addRetransmit()
                    lastWindowMoveTime = time.time()
        finally:
            # always release lock
            windowLock.release()


# ACK receiver thread
# cumulative ACK slides window forward
# runs in a separate thread
def receiveAcks(sock):
    global windowBase, isDone, lastWindowMoveTime

    while not isDone:
        parsed = recvPacket(sock, serverPort, timeout=timeoutValue + 1)
        if parsed is None:
            if isDone:
                break
            continue

        # only accept packets from our client
        if parsed['srcIP'] != savedClientIP:
            continue

        # only process ACK packets for window management
        if parsed['pktType'] != typeAck:
            # count all received client packet
            addReceived()
            continue

        addReceived()

        # verify AEAD on ACK
        if securityEnabled and sessionKey is not None:
            ackNum = verifyAckPacket(parsed)
            if ackNum is None:
                # AEAD failed, ignore
                continue
        else:
            ackNum = parsed['ackNum']

        # cumulative ACK
        # move window base forward
        windowLock.acquire()
        try:
            if ackNum > windowBase:
                oldBase = windowBase
                windowBase = ackNum
                lastWindowMoveTime = time.time()

                # print progress
                if windowBase % printEvery == 0 or windowBase >= numChunks:
                    print('  <- ACK=' + str(ackNum) + ': window ' +
                          str(oldBase) + ' -> ' + str(windowBase) +
                          '/' + str(numChunks))

                # check all chunk ack
                if windowBase >= numChunks:
                    isDone = True
                    print('')
                    print('[done] all ' + str(numChunks) + ' chunks acknowledged')
        finally:
            windowLock.release()


# sliding window sender (main thread)
# can send seq numbers from windowBase to windowBase + windowSize - 1
# attack hooks are here for security testing

def slidingWindowSend(sock):
    global nextToSend, lastWindowMoveTime
    global attackPacketSaved, attackDone

    while not isDone:
        windowLock.acquire()
        try:
            # send all within current window
            while nextToSend < windowBase + windowSize and nextToSend < numChunks:
                seq = nextToSend
                if serverFileHandle is not None:
                    chunkData = readChunkFromHandle(serverFileHandle, seq)
                else:
                    chunkData = readChunk(filePath, seq)
                payload = prepareDataForSend(chunkData, seq)

                # attack test

                # Test 3: tamper attack at seq=5
                if currentAttackMode == 'tamper' and not attackDone and seq == 5:
                    doTamperAttack(sock, chunkData, seq)
                    attackDone = True
                    nextToSend = nextToSend + 1
                    # also send the real packet
                    # so transfer still complete
                    sendPacket(sock, savedClientIP, savedClientPort,
                               serverIP, serverPort,
                               typeData, seq, 0, payload)
                    addSent()
                    continue

                # Test 4: save packet at seq=5
                # replay it at seq=15
                if currentAttackMode == 'replay' and not attackDone and seq == 5:
                    attackPacketSaved = {'seqNum': seq, 'data': payload}
                    print('[ATTACK] saved packet seq=5 for replay later')

                if currentAttackMode == 'replay' and not attackDone and seq == 15:
                    doReplayAttack(sock, attackPacketSaved)
                    attackDone = True

                # Test 5: inject forged packet at seq=10
                if currentAttackMode == 'inject' and not attackDone and seq == 10:
                    doInjectAttack(sock)
                    attackDone = True

                # send real data packet
                sendPacket(sock, savedClientIP, savedClientPort,
                           serverIP, serverPort,
                           typeData, seq, 0, payload)
                addSent()

                # print progress
                if seq % printEvery == 0 or seq == numChunks - 1:
                    progress = (seq + 1) * 100 // numChunks
                    print('  -> send seq=' + str(seq) + '/' + str(numChunks - 1) +
                          ' [' + str(progress) + '%] (base=' + str(windowBase) + ')')

                nextToSend = nextToSend + 1
        finally:
            windowLock.release()

        time.sleep(0.001)  # dont busy wait


# send FIN + SHA-256 + wait for FIN_ACK
# send encrypted SHA-256 so client can verify file
# also extracts client security counter from FIN_ACK payload
# numChunks(4) + aeadFail(4) + replayDrop(4) + sha256Flag(1)

def sendFinish(sock, md5Hash, sha256Hash):
    global clientAeadFailCount, clientReplayDropCount, clientSha256Match

    print('')
    print('[fin] sending finish')

    # track client confirm SHA-256
    shaConfirmReceived = False

    # send encrypted SHA256 hash first (3x)
    if securityEnabled and sessionKey is not None:
        shaData = sha256Hash.encode('utf-8')
        encSha = encryptData(sessionKey, shaData,
                             sessionId, typeShaVerify, numChunks, 0)
        for i in range(3):
            sendPacket(sock, savedClientIP, savedClientPort,
                       serverIP, serverPort,
                       typeShaVerify, numChunks, 0, encSha)
            addSent()
            time.sleep(0.1)
        print('[sha-256] encrypted SHA 256 hash sent to client (x3)')
        time.sleep(0.3)

    # send FIN packet
    # wait for FIN_ACK
    for attempt in range(maxRetry):

        # re-send SHA256 if client no confirmed yet
        if securityEnabled and sessionKey is not None and not shaConfirmReceived:
            encSha = encryptData(sessionKey, sha256Hash.encode('utf-8'),
                                 sessionId, typeShaVerify, numChunks, 0)
            sendPacket(sock, savedClientIP, savedClientPort,
                       serverIP, serverPort,
                       typeShaVerify, numChunks, 0, encSha)
            addSent()

        # encrypt FIN data with AEAD
        finData = md5Hash.encode('utf-8')
        if securityEnabled and sessionKey is not None:
            finData = encryptData(sessionKey, finData,
                                  sessionId, typeFin, numChunks, 0)
        sendPacket(sock, savedClientIP, savedClientPort,
                   serverIP, serverPort,
                   typeFin, numChunks, 0, finData)
        addSent()

        # wait up to 3s for FIN_ACK
        waitStart = time.time()
        while time.time() - waitStart < 3.0:
            parsed = recvPacket(sock, serverPort, timeout=0.5)
            if parsed is None:
                continue

            # only accept from client
            if parsed['srcIP'] != savedClientIP:
                continue

            # handle FIN_ACK
            if parsed['pktType'] == typeFinAck:
                addReceived()
                # verify AEAD and extract client counters
                if securityEnabled and sessionKey is not None:
                    plaintext = verifyControlPacket(parsed)
                    if plaintext is None:
                        print('  [security] forged FIN_ACK rejected')
                        continue
                    # extract client security counters
                    # numChunks(4) + aeadFail(4) + replayDrop(4) + sha256Flag(1) = 13
                    try:
                        if len(plaintext) >= 13:
                            vals = struct.unpack('!IIIB', plaintext[0:13])
                            clientAeadFailCount = vals[1]
                            clientReplayDropCount = vals[2]
                            clientSha256Match = (vals[3] == 1)
                            print('  client reports: AEAD failures=' +
                                  str(clientAeadFailCount) +
                                  ', replay drops=' + str(clientReplayDropCount) +
                                  ', SHA-256=' + ('Yes' if clientSha256Match else 'No'))
                        elif len(plaintext) >= 12:
                            # legacy format without sha256 flag
                            vals = struct.unpack('!III', plaintext[0:12])
                            clientAeadFailCount = vals[1]
                            clientReplayDropCount = vals[2]
                            print('  client reports: AEAD=' +
                                  str(clientAeadFailCount) +
                                  ', replay=' + str(clientReplayDropCount))
                    except struct.error as e:
                        print('  [warning] could not parse FIN_ACK counters: ' + str(e))
                print('[fin] got FIN_ACK (verified), transfer complete!')
                return True

            # SHA_CONFIRM from client
            if parsed['pktType'] == typeShaConfirm:
                addReceived()
                if securityEnabled and sessionKey is not None:
                    plaintext = verifyControlPacket(parsed)
                    if plaintext is None:
                        print('  [security] forged SHA_CONFIRM rejected')
                        continue
                shaConfirmReceived = True
                print('[sha-256] got SHA-256 confirm from client')

            # count any late ACKs
            if parsed['pktType'] == typeAck:
                addReceived()

        print('  [fin] retry ' + str(attempt + 1) + '/' + str(maxRetry))

    print('[fin] warning: no FIN_ACK received after ' + str(maxRetry) + ' attempts')
    return False


# report

def writeReport(filename, fSize, sha256Hash, sha256Match):
    # safe duration calc
    # handles edge cases
    if endTime > 0 and startTime > 0 and endTime >= startTime:
        duration = endTime - startTime
    else:
        duration = 0.0

    # determine test
    if currentAttackMode == 'wrongpsk':
        testLabel = 'Test 2 Wrong PSK (Authentication Failure)'
    elif securityEnabled and not handshakeOk and currentAttackMode == 'none':
        testLabel = 'Test 2 Wrong PSK (Authentication Failure)'
    elif currentAttackMode == 'tamper':
        testLabel = 'Test 3 Tamper Detection (Integrity)'
    elif currentAttackMode == 'replay':
        testLabel = 'Test 4 Replay Protection'
    elif currentAttackMode == 'inject':
        testLabel = 'Test 5 Forged Injection'
    elif not securityEnabled:
        testLabel = 'Phase 1 Reliable Transfer (no security)'
    else:
        testLabel = 'Test 1 Secure Transfer (Baseline)'

    lines = []
    lines.append('')
    lines.append('SRFT Transfer Report - ' + testLabel)
    lines.append('Timestamp: ' + time.strftime('%Y-%m-%d %H:%M:%S'))
    lines.append('File: ' + filename)
    lines.append('')

    # Phase 1 report
    lines.append('- Name of the transferred file: ' + filename)
    lines.append('- Size of the transferred file: ' + str(fSize) + ' bytes')
    lines.append('- The number of packets sent from the server: ' + str(totalSent))
    lines.append('- The number of retransmitted packets from the server: ' + str(totalRetransmit))
    lines.append('- The number of packets received from the client: ' + str(totalReceived))
    lines.append('- The time duration of the file transfer (hh:min:ss): ' + formatTime(duration))

    # Phase 2 report
    if securityEnabled:
        # use client side counter only
        totalAeadFail = clientAeadFailCount
        totalReplayDrop = clientReplayDropCount

        # log server side noise (debug, not in report)
        if aeadFailCount > 0 or replayDropCount > 0:
            print('[note] server-side noise: ' +
                  str(aeadFailCount) + ' corrupted ACKs, ' +
                  str(replayDropCount) + ' replay on ACKs')

        # client actual SHA-256 verify result
        if clientSha256Match:
            finalSha256 = True
        else:
            finalSha256 = sha256Match

        lines.append('- Security enabled (PSK + AEAD): Yes')
        lines.append('- Handshake status: ' + ('Success' if handshakeOk else 'Fail'))
        lines.append('- AEAD authentication failures (invalid packets dropped): ' + str(totalAeadFail))
        lines.append('- Replay drops (duplicate/out-of-window packets): ' + str(totalReplayDrop))
        lines.append('- SHA-256 match: ' + ('Yes' if finalSha256 else 'No'))
        if currentAttackMode != 'none':
            lines.append('- Attack test mode: ' + currentAttackMode)
    else:
        lines.append('- Security enabled (PSK + AEAD): No')
        lines.append('- Handshake status: N/A')
        lines.append('- AEAD authentication failures (invalid packets dropped): 0')
        lines.append('- Replay drops (duplicate/out-of-window packets): 0')
        lines.append('- SHA-256 match: N/A')

    lines.append('')
    lines.append('')

    report = '\n'.join(lines)
    print(report)

    # append
    try:
        with open(reportPath, 'a') as f:
            f.write(report + '\n')
        print('report save to ' + reportPath)
    except PermissionError:
        # sudo might own the file
        altPath = os.path.expanduser('~/report.txt')
        try:
            with open(altPath, 'a') as f:
                f.write(report + '\n')
            print('report save ' + altPath)
            print('  (permission denied on ' + reportPath + ', used ' + altPath + ')')
            print('  tip: sudo chmod 666 ' + reportPath)
        except Exception as e2:
            print('warning: could not save report: ' + str(e2))
    except Exception as e:
        print('warning: could not save report: ' + str(e))



# main

if __name__ == '__main__':

    print('')
    print('')
    print(' Weiting Liu, Youran Ye, Jingkai Liu, Yinfei Lu ')
    print(' CS5700 SRFT Server')
    if securityEnabled:
        print(' Phase 2: Secure Reliable File Transfer')
    else:
        print(' Phase 1: Reliable File Transfer')
    print('')
    print('')

    # check for attack flag
    # Test 3: sudo python3 SRFT_UDPServer.py --attack tamper
    # Test 4: sudo python3 SRFT_UDPServer.py --attack replay
    # Test 5: sudo python3 SRFT_UDPServer.py --attack inject
    if len(sys.argv) >= 3 and sys.argv[1] == '--attack':
        currentAttackMode = sys.argv[2]
        # validate
        if currentAttackMode not in validAttackModes:
            print('[error] unknown attack mode: ' + currentAttackMode)
            print('  valid modes: ' + str(validAttackModes))
            sys.exit(1)
        # attack tests only make sense with security enabled
        if not securityEnabled and currentAttackMode != 'none':
            print('[warning] attack mode "' + currentAttackMode + '" securityEnabled=True')
            sys.exit(1)
        print('[ATTACK MODE] attack test: ' + currentAttackMode)
        print('')

    # warnPSK length

    if securityEnabled:
        if not validatePsk(psk):
            print('[warning] wrong PSK may cause handshake failure')
            print('')

    # create server socket
    print('[socket] creating server socket')
    serverSocket = createServerSocket()
    print('  server socket created')

    # make sure server directory exists
    if not os.path.exists(serverDir):
        os.makedirs(serverDir)
        print('  create ' + serverDir + ' test files here')

    try:
        # wait for client to send filename
        filename = waitForRequest(serverSocket)

        # validate filename (error handling)
        if not validateFilename(filename):
            errMsg = 'ERROR: invalid filename'
            sendPacket(serverSocket, savedClientIP, savedClientPort,
                       serverIP, serverPort,
                       typeFileInfo, 0, 0, errMsg.encode('utf-8'))
            serverSocket.close()
            sys.exit(1)

        # check file exists on server
        filepath = os.path.join(serverDir, filename)
        if not os.path.exists(filepath):
            print('')
            print('[error] file not found: ' + filepath)
            errMsg = 'ERROR: file not found'
            sendPacket(serverSocket, savedClientIP, savedClientPort,
                       serverIP, serverPort,
                       typeFileInfo, 0, 0, errMsg.encode('utf-8'))
            serverSocket.close()
            sys.exit(1)

        # get file info and compute hashes
        fSize = os.path.getsize(filepath)
        md5Hash = calculateMD5(filepath)
        sha256Hash = calculateSHA256(filepath)

        print('')
        print('[file] ' + filename)
        print('  size: ' + str(fSize) + ' bytes (' + str(fSize // 1024) + ' KB)')
        print('  MD5:    ' + md5Hash)
        print('  SHA256: ' + sha256Hash)

        filePath = filepath
        numChunks = countChunks(filepath)
        print('  chunks: ' + str(numChunks) + ' (each up to ' + str(chunkSize) + ' bytes)')

        # Phase 2 security handshake
        sha256Match = False
        if securityEnabled:
            success = doSecurityHandshake(serverSocket)
            if not success:
                print('')
                print('[error] handshake failed')
                endTime = time.time()
                startTime = endTime
                # wrong PSK but still write report
                writeReport(filename, fSize, sha256Hash, False)
                serverSocket.close()
                sys.exit(1)

        # send file info to client
        sendFileInfo(serverSocket, filename, fSize, numChunks, md5Hash)
        time.sleep(0.5)

        # start file transfer with sliding window
        startTime = time.time()

        # open persistent file handle for speed
        # keeps file open throughout transfer instead of open/close per chunk
        serverFileHandle = open(filepath, 'rb')

        # flush stale packets from previous test
        # prevent old encrypted packets
        flushSocket(serverSocket)

        print('')
        print('[transfer] starting file transfer')
        print('  window size: ' + str(windowSize))
        print('  timeout: ' + str(timeoutValue) + 's')
        print('  chunk size: ' + str(chunkSize) + ' bytes')
        if securityEnabled:
            print('  encryption: AES-256-GCM (AEAD)')

        windowBase = 0
        nextToSend = 0
        isDone = False
        lastWindowMoveTime = time.time()

        # handle empty file
        if numChunks == 0:
            isDone = True
            print('[done] empty file, no chunks to send')
        else:
            # multithreading: ACK receiver + retransmit watcher
            ackThread = threading.Thread(target=receiveAcks, args=(serverSocket,))
            ackThread.daemon = True
            ackThread.start()

            # pass socket
            watcherThread = threading.Thread(target=retransmitWatcher, args=(serverSocket,))
            watcherThread.daemon = True
            watcherThread.start()

            # main thread
            # sliding window sender
            slidingWindowSend(serverSocket)

            # wait for ACK to finish
            ackThread.join(timeout=10)

        # send FIN + SHA-256 ,wait for FIN_ACK
        sendFinish(serverSocket, md5Hash, sha256Hash)
        endTime = time.time()

        # done reading chunks
        if serverFileHandle is not None:
            serverFileHandle.close()
            serverFileHandle = None

        # use client actual result
        sha256Match = clientSha256Match

        # report
        writeReport(filename, fSize, sha256Hash, sha256Match)
        print('')
        print('server complete')
        print('')

    except KeyboardInterrupt:
        print('')
        print('server stop')
    except Exception as e:
        print('')
        print('error: ' + str(e))
        import traceback
        traceback.print_exc()
    finally:
        # always close file handle and socket on exit
        if serverFileHandle is not None:
            serverFileHandle.close()
            serverFileHandle = None
        serverSocket.close()
        print('socket closed')