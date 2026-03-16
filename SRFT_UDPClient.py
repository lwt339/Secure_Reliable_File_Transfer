# Client

import os
import sys
import time
import threading

from socket import *
from config import *
from packet_helper import *


# Global Var

# key = sequence number, value = data bytes
recvBuffer = {} # stores
expectedSeq = 0 # next sequence number expect to receive

# file info from server)
fileName = ''
fileSize = 0
numChunks = 0
serverMD5 = ''

# transfer state
isDone = False
ackCount = 0

# packets receive stat
validCount = 0
duplicateCount = 0
outOfOrderCount = 0


# Send filename request tell server which file it wants
def requestFile(sock, filename):

    print('')
    print('[Request] Send file request: ' + filename)
    print('Target: ' + serverIP + ':' + str(serverPort))
    sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
               typeFilename, 0, 0, filename.encode('utf-8'))
    print('Request sent')

# Wait server send back file information
def waitForFileInfo(sock, filename):

    global fileName, fileSize, numChunks, serverMD5

    print('')
    print('[Wait] for file info from server')

    for attempt in range(maxRetry):
        parsed = recvPacket(sock, clientPort, timeout=3)
        if parsed is None:
            print('Timeout, resending request (' +
                  str(attempt + 1) + '/' + str(maxRetry) + ')')
            requestFile(sock, filename)
            continue

        if parsed['pktType'] == typeFileInfo:
            infoStr = parsed['data'].decode('utf-8')

            # check if sever sent error message
            if infoStr.startswith('ERROR:'):
                print('')
                print('[Error] Server says: ' + infoStr)
                return False

            # parsefile info
            # filename|size|chunks|md5
            parts = infoStr.split('|')
            if len(parts) >= 4:
                fileName = parts[0]
                fileSize = int(parts[1])
                numChunks = int(parts[2])
                serverMD5 = parts[3]

            print('')
            print('[Info] get file info')
            print('Filename: ' + fileName)
            print('Size: ' + str(fileSize) + ' bytes (' +
                  str(fileSize // 1024) + ' KB)')
            print('Chunks: ' + str(numChunks))
            print('MD5: ' + serverMD5)
            return True

    print('[Error] Could not get file info after ' + str(maxRetry) + ' tries!')
    return False

# cumulative ACK to the server ( received everything before expectedSeq )
def sendCumulativeAck(sock):

    global ackCount

    sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
               typeAck, 0, expectedSeq)
    ackCount = ackCount + 1

# receive data packet from the server
def receiveData(sock):

    global expectedSeq, isDone
    global validCount, duplicateCount, outOfOrderCount

    print('')
    print('[Receive] Starting to receive data (expecting ' +
          str(numChunks) + ' chunks)')

    sock.settimeout(timeoutValue * 5)
    timeoutCount = 0 # consecutive timeouts
    lastAckTime = time.time() # last sent ACK
    sinceLastAck = 0 # packets received since last ACK

    while not isDone:
        try:
            parsed = recvPacket(sock, clientPort, timeout=timeoutValue * 5)

            if parsed is None:
                # timeout
                timeoutCount = timeoutCount + 1
                if timeoutCount > maxTimeouts:
                    print('')
                    print('[Timeout] Too many consecutive timeouts, stopping')
                    break
                # still send ACK so server knows we are still alive
                sendCumulativeAck(sock)
                lastAckTime = time.time()
                continue

            timeoutCount = 0  # reset timeout

            # FIN
            if parsed['pktType'] == typeFin:
                print('')
                print('[FIN] Received finish from server')
                # send FIN_ACK back 3 times
                for i in range(3):
                    sendPacket(sock, serverIP, serverPort, clientIP, clientPort,
                               typeFinAck, 0, numChunks)
                    time.sleep(0.01)
                print('[FIN] FIN ACK sent')
                isDone = True
                break

            # only prtocess data packets
            if parsed['pktType'] != typeData:
                continue

            seqNum = parsed['seqNum']
            data = parsed['data']

            # seqNum == expectedSeq inorder packet, buffer it and advance
            if seqNum == expectedSeq:
                recvBuffer[seqNum] = data
                validCount = validCount + 1
                sinceLastAck = sinceLastAck + 1

                # advance expectedSeq check if buffered future packets
                # store temp until missing segments arrive
                while expectedSeq in recvBuffer:
                    expectedSeq = expectedSeq + 1

            # seqNum > expectedSeq = out-of-order, buffer it arriver early
            elif seqNum > expectedSeq:
                # buffer it for later
                if seqNum not in recvBuffer:
                    recvBuffer[seqNum] = data
                    validCount = validCount + 1
                    outOfOrderCount = outOfOrderCount + 1
                else:
                    duplicateCount = duplicateCount + 1

            # seqNum < expectedSeq = duplicate, ignore
            else:
                # already received this one
                duplicateCount = duplicateCount + 1

            # send cumulative ACK
            # So send ACK periodically, not for every single packet avoid sending an ack per packet
            shouldAck = False
            if seqNum < expectedSeq:
                shouldAck = True  # always ACK duplicates
            if sinceLastAck >= ackEvery:
                shouldAck = True # ACK every 3 packets
            if time.time() - lastAckTime > 0.5:
                shouldAck = True # ACK at least every 0.5 seconds

            if shouldAck:
                sendCumulativeAck(sock)
                lastAckTime = time.time()
                sinceLastAck = 0

            # print progress
            if expectedSeq % printEvery == 0 or expectedSeq >= numChunks:
                if numChunks > 0:
                    progress = expectedSeq * 100 // numChunks
                else:
                    progress = 0
                print(' Progress: ' + str(expectedSeq) + '/' +
                      str(numChunks) + ' [' + str(progress) + '%]')

            # check if received everything
            if expectedSeq >= numChunks:
                print('')
                print('[Done] All ' + str(numChunks) + ' chunks receive')
                # send extra ACKs make sure server
                for i in range(5):
                    sendCumulativeAck(sock)
                    time.sleep(0.01)

        except Exception as e:
            timeoutCount = timeoutCount + 1
            if timeoutCount > maxTimeouts:
                break
            sendCumulativeAck(sock)
            lastAckTime = time.time()

    print('')
    print('[Stats] Valid=' + str(validCount) +
          ' Duplicate=' + str(duplicateCount) +
          ' OutOfOrder=' + str(outOfOrderCount) +
          ' ACKsSent=' + str(ackCount))


# Put back together into original file
# verify MD5 hash matches what the server sent ( received file and the original same )
def reassembleFile():

    print('')
    print('[Assemble] Reassembling file')

    # create client files if no exist
    if not os.path.exists(clientDir):
        os.makedirs(clientDir)

    outputPath = os.path.join(clientDir, fileName)
    missing = 0

    # write all chunks in order
    with open(outputPath, 'wb') as f:
        for seq in range(numChunks):
            if seq in recvBuffer:
                f.write(recvBuffer[seq])
            else:
                missing = missing + 1
                print('missing chunk #' + str(seq) + '!')

    if missing == 0:
        print('[Assemble] file saved: ' + outputPath)
    else:
        print('[Assemble] warning: ' + str(missing) + ' chunks missing')

    # verify MD5 hash
    receivedMD5 = calculateMD5(outputPath)
    print('')
    print('[Verify] Server MD5:   ' + serverMD5)
    print('received MD5: ' + receivedMD5)

    if receivedMD5 == serverMD5:
        print('MD5 match, file transfer successful')
        return True
    else:
        print('MD5 MISMATCH , file may be corrupted')
        return False




if __name__ == '__main__':
    print(' ' )
    print('  CS5700 - SRFT Client (Phase 1: Reliable File Transfer)')
    print(' ' )


    fileName = sys.argv[1]
    print('')
    print('requesting file: ' + fileName)
    print('')

    # client socket
    print('creating socket')
    mySocket = createClientSocket()
    print(' client socket creat finish')

    try:
        # send filename request to server
        requestFile(mySocket, fileName)

        # wait for file info from server
        if not waitForFileInfo(mySocket, fileName):
            print('[Exit] could not get file info')
            mySocket.close()
            sys.exit(1)

        # receive all the file data
        receiveData(mySocket)

        # reassemble file and verify MD5
        success = reassembleFile()

        # print final result
        print('')
        print(' ' * 60)
        if success:
            print('Client task complete,  file transfer success')
        else:
            print('  Warning: File transfer may be incomplete')
        print('=' * 60)

    except KeyboardInterrupt:
        print('')
        print('stop')
    except Exception as e:
        print('')
        print('Error' + str(e))
        import traceback
        traceback.print_exc()
    finally:
        mySocket.close()
        print('cleanup Socket closed')