# Client
# cumulative ACK, sequence numbers, checksum

import os
import sys
import time
import threading

from socket import *
from config import *
from packet_helper import *


# Global Var


receivedSet = set() # stores sequence numbers we received
outputFile = None # file handle for writing data to disk
expectedSeq = 0 # next sequence number expect to receive

# file info from server
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

            # parse file info
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


# Prepare output file on disk before receiving data
def prepareOutputFile():

    global outputFile

    # client dir
    if not os.path.exists(clientDir):
        os.makedirs(clientDir)

    outputPath = os.path.join(clientDir, fileName)

    # pre allocate
    f = open(outputPath, 'wb')
    if fileSize > 0:
        f.seek(fileSize - 1)
        f.write(b'\x00')
    f.close()

    # read and write
    outputFile = open(outputPath, 'r+b')

    print('')
    print('[Prepare] Output file ready: ' + outputPath)
    print(' Pre-allocated ' + str(fileSize) + ' bytes on disk')


# write a chunk of data to correct position on disk
def writeChunkToDisk(seqNum, data):

    global outputFile

    # calculatebyte
    offset = seqNum * chunkSize
    outputFile.seek(offset)
    outputFile.write(data)


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

            # only process data packets
            if parsed['pktType'] != typeData:
                continue

            seqNum = parsed['seqNum']
            data = parsed['data']

            # seqNum == expectedSeq = in-order packet
            if seqNum == expectedSeq:

                # write data directly to disk (not store in memory)
                writeChunkToDisk(seqNum, data)
                receivedSet.add(seqNum)
                validCount = validCount + 1
                sinceLastAck = sinceLastAck + 1

                # advance expectedSeq check if buffered future packets
                # until missing segments arrive, then delivers them in order
                while expectedSeq in receivedSet:
                    expectedSeq = expectedSeq + 1

            # seqNum > expectedSeq = out-of-order, arrived early
            elif seqNum > expectedSeq:
                # buffer it for later (only if not already received)
                if seqNum not in receivedSet:
                    writeChunkToDisk(seqNum, data)
                    receivedSet.add(seqNum)
                    validCount = validCount + 1
                    outOfOrderCount = outOfOrderCount + 1
                else:
                    duplicateCount = duplicateCount + 1

            # seqNum < expectedSeq = duplicate, ignore
            else:
                # already received this one
                duplicateCount = duplicateCount + 1

            # send cumulative ACK
            # send ACK periodically
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


# Verify the received file
def verifyFile():

    global outputFile

    print('')
    print('[Verify] Verifying received file')

    # close the output file (flush all writes to disk)
    if outputFile is not None:
        outputFile.flush()
        outputFile.close()
        outputFile = None

    outputPath = os.path.join(clientDir, fileName)

    # check for missing chunks
    missing = 0
    for seq in range(numChunks):
        if seq not in receivedSet:
            missing = missing + 1
            if missing <= 10:
                print('  missing chunk #' + str(seq) + '!')

    if missing == 0:
        print('[Verify] All ' + str(numChunks) + ' chunks received')
    else:
        print('[Verify] WARNING: ' + str(missing) + ' chunks missing!')

    # verify MD5 hash
    # project says: use md5sum to compare
    receivedMD5 = calculateMD5(outputPath)
    print('')
    print('[Verify] Server MD5:   ' + serverMD5)
    print('         Received MD5: ' + receivedMD5)

    if receivedMD5 == serverMD5:
        print('         MD5 MATCH, file transfer successful')
        return True
    else:
        print('         MD5 MISMATCH, file may be corrupted')
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

        # prepare output file on disk before receiving data
        prepareOutputFile()

        # receive all the file data
        receiveData(mySocket)

        # verify file (data already on disk, just check MD5)
        success = verifyFile()

        # print final result
        print('')
        print(' ')
        if success:
            print('Client task complete, file transfer success')
        else:
            print('  Warning: File transfer may be incomplete')
        print(' ' )

    except KeyboardInterrupt:
        print('')
        print('stop')
    except Exception as e:
        print('')
        print('Error ' + str(e))
        import traceback
        traceback.print_exc()
    finally:
        # make sure output file is closed
        if outputFile is not None:
            outputFile.close()
        mySocket.close()
        print('cleanup Socket closed')