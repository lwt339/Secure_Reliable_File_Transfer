# Server
# sliding window, sequence numbers, retransmission (like TCP error control)

import os
import sys
import time
import threading

from socket import *
from config import *
from packet_helper import *


# Global Var

# stat counter
totalSent = 0 # packets sent in total
totalRetransmit = 0 # resend
totalReceived = 0 # receive

# timing
startTime = 0
endTime = 0

# sliding window var
# range of sent but not yet ACKed packets = the window
windowBase = 0 # oldest unack (left edge of window)
nextToSend = 0 # next packet that haven't sent
isDone = False

# thread safety
lastWindowMoveTime = 0.0
windowLock = threading.Lock() # lock ( send thread and receive )
retransmitTimer = None

# file info
# store the file path and read avoid too much memory
filePath = ''
numChunks = 0

# client address
savedClientIP = ''
savedClientPort = 0


# Wait client send filename request
# server sit until client connects
def waitForRequest(sock):

    global totalReceived, savedClientIP, savedClientPort

    print('')
    print('[Wait] Server listening on ' + serverIP + ':' + str(serverPort))
    print(' Wait for client to connect')

    while True:
        parsed = recvPacket(sock, serverPort, timeout=None)
        if parsed is None:
            continue
        if parsed['pktType'] == typeFilename:
            filename = parsed['data'].decode('utf-8')
            savedClientIP = parsed['srcIP']
            savedClientPort = parsed['srcPort']
            totalReceived = totalReceived + 1
            print('')
            print('( Got ) Receive file request')
            print(' Client: ' + savedClientIP + ':' + str(savedClientPort))
            print(' File request: ' + filename)
            return filename


# Send file info to client before start transfer
def sendFileInfo(sock, filename, fSize, nChunks, md5Hash):
    # filename, size, number of chunks, MD5 hash
    global totalSent
    infoStr = filename + '|' + str(fSize) + '|' + str(nChunks) + '|' + md5Hash
    sendPacket(sock, savedClientIP, savedClientPort, serverIP, serverPort,
               typeFileInfo, 0, 0, infoStr.encode('utf-8'))
    totalSent = totalSent + 1
    print('( Send ) file info sent to client')


# Retransmission watcher thread error control
# timer times out, retransmit unACKed packets
def retransmitWatcher():
    global totalSent, totalRetransmit, isDone, lastWindowMoveTime

    # last windowBase
    lastSeenBase = 0

    while not isDone:

        # Check every 50ms
        time.sleep(0.05)

        # safely read window
        windowLock.acquire()

        currentBase = windowBase
        currentNext = nextToSend

        # windowBase advance
        # Update timestamp, reset lastSeenBase
        if currentBase > lastSeenBase:
            lastSeenBase = currentBase
            lastWindowMoveTime = time.time()

        # windowBase stuck
        # window has unacked packets
        elif currentBase < numChunks and currentNext > currentBase:

            elapsed = time.time() - lastWindowMoveTime

            # stuck longer than timeoutValue seconds
            # timeout retransmit
            if elapsed >= timeoutValue:

                # Retransmit all packets from windowBase up to nextToSend
                endSeq = min(currentNext, numChunks)
                count = endSeq - currentBase

                print('')
                print('[Timeout] windowBase=' + str(currentBase) +
                      ' stuck for ' + str(round(elapsed, 2)) + 's')
                print('[Timeout] Retransmitting seq=' + str(currentBase) +
                      ' to ' + str(endSeq - 1) +
                      ' (' + str(count) + ' packets)')

                # Resend every unACKed packet
                # read chunk from disk (not from memory list)
                for seq in range(currentBase, endSeq):
                    if seq < numChunks:
                        chunkData = readChunk(filePath, seq)
                        sendPacket(mySocket, savedClientIP, savedClientPort,
                                   serverIP, serverPort,
                                   typeData, seq, 0, chunkData)
                        totalSent = totalSent + 1
                        totalRetransmit = totalRetransmit + 1

                # reset the timestamp
                lastWindowMoveTime = time.time()
        windowLock.release()


# separate thread to receive ACKs from the client
def receiveAcks(sock):

    global windowBase, isDone, totalReceived, lastWindowMoveTime

    while not isDone:
        parsed = recvPacket(sock, serverPort, timeout=timeoutValue + 1)
        if parsed is None:
            if isDone:
                break
            continue

        # only process ACK packets
        if parsed['pktType'] != typeAck:
            # might be a duplicate filename request
            # count it
            if parsed['pktType'] == typeFilename:
                totalReceived = totalReceived + 1
            continue

        totalReceived = totalReceived + 1
        ackNum = parsed['ackNum']

        windowLock.acquire()
        # Cumulative ACK
        if ackNum > windowBase:
            oldBase = windowBase
            windowBase = ackNum

            # detect timeout
            lastWindowMoveTime = time.time()

            # print progress
            if windowBase % printEvery == 0 or windowBase >= numChunks:
                print('  <- ACK=' + str(ackNum) + ': window ' +
                      str(oldBase) + ' -> ' + str(windowBase) +
                      '/' + str(numChunks))

            # check if all ack
            if windowBase >= numChunks:
                isDone = True
                print('')
                print('[Done] All ' + str(numChunks) + ' chunks acknowledged')
        windowLock.release()


# sliding window sending loop
# sender can send up to windowSize packets ahead of windowBase
def slidingWindowSend(sock):

    global nextToSend, totalSent, lastWindowMoveTime

    while not isDone:
        windowLock.acquire()
        # send as many packets as the window allows
        while nextToSend < windowBase + windowSize and nextToSend < numChunks:
            seq = nextToSend

            # read chunk from disk
            chunkData = readChunk(filePath, seq)

            sendPacket(sock, savedClientIP, savedClientPort,
                       serverIP, serverPort, typeData, seq, 0, chunkData)
            totalSent = totalSent + 1

            # print progress
            if seq % printEvery == 0 or seq == numChunks - 1:
                progress = (seq + 1) * 100 // numChunks
                print('  -> Send seq=' + str(seq) + '/' + str(numChunks - 1) +
                      ' [' + str(progress) + '%] (base=' + str(windowBase) + ')')

            nextToSend = nextToSend + 1

        windowLock.release()
        time.sleep(0.001)  # sleep avoid busy waiting


# Send FIN to the client
def sendFinish(sock, md5Hash):

    global totalSent, totalReceived

    print('')
    print('[FIN] sending finish ')

    for attempt in range(maxRetry):
        sendPacket(sock, savedClientIP, savedClientPort, serverIP, serverPort,
                   typeFin, numChunks, 0, md5Hash.encode('utf-8'))
        totalSent = totalSent + 1

        # wait for FIN ACK from client
        wait_start = time.time()
        while time.time() - wait_start < 3.0:  # 3 second timeout
            parsed = recvPacket(sock, serverPort, timeout=0.5)

            if parsed is None:
                continue  # within the 3s window

            if parsed['pktType'] == typeFinAck:
                totalReceived = totalReceived + 1
                print('[FIN] get FIN ACK so transfer complete')
                return True

        print('  [FIN] retry ' + str(attempt + 1) + '/' + str(maxRetry) + ' ')

    print('[FIN] warning no FIN ACK receive after ' + str(maxRetry) + ' tries')
    return False


# report
def writeReport(filename, fSize):
    # format
    duration = endTime - startTime

    lines = []
    lines.append('')
    lines.append('')
    lines.append('  SRFT Transfer Report (Phase 1)')
    lines.append('  Test file: ' + filename)
    lines.append('  Test time: ' + time.strftime('%Y-%m-%d %H:%M:%S'))
    lines.append(' ')
    lines.append(' Name of the transferred file: ' + filename)
    lines.append(' Size of the transferred file: ' + str(fSize) + ' bytes')
    lines.append(' The number of packets sent from the server: ' + str(totalSent))
    lines.append(' The number of retransmitted packets from the server: ' + str(totalRetransmit))
    lines.append(' The number of packets received from the client: ' + str(totalReceived))
    lines.append(' The time duration of the file transfer: ' + formatTime(duration))
    lines.append(' ')
    lines.append('')

    report = '\n'.join(lines)
    print('')
    print(report)

    # add
    with open(reportPath, 'a') as f:
        f.write(report + '\n')
    print('')
    print('Report appended to ' + reportPath)



# Main
if __name__ == '__main__':
    print(' ' * 60)
    print('CS5700 SRFT Server (Phase 1: Reliable File Transfer)')
    print(' ' * 60)
    print('')

    # create server socket
    print('[ Creating socket ]')
    mySocket = createServerSocket()
    print(' server socket creat')

    # files directory exists
    if not os.path.exists(serverDir):
        os.makedirs(serverDir)
        print(' put files in ' + serverDir + ' directory!')

    try:
        # wait for client to request file
        filename = waitForRequest(mySocket)

        # check if the file exists
        filepath = os.path.join(serverDir, filename)
        if not os.path.exists(filepath):
            print('')
            print('[Error] file not found: ' + filepath)
            mySocket.close()
            sys.exit(1)

        # get file info
        fSize = os.path.getsize(filepath)
        md5Hash = calculateMD5(filepath)
        print('')
        print('[File] ' + filename + ' | ' + str(fSize) + ' bytes | MD5=' + md5Hash)

        # calculates how many chunks from file size
        # reads one chunk at a time when needed
        filePath = filepath
        numChunks = countChunks(filepath)
        print('       ' + str(numChunks) + ' chunks (each <= ' + str(chunkSize) + ' bytes)')

        # send file info to client
        sendFileInfo(mySocket, filename, fSize, numChunks, md5Hash)
        time.sleep(0.5)  # give client time

        # start transfer using sliding window
        startTime = time.time()
        print('')
        print('start transfer, Window=' + str(windowSize) +
              ', Timeout=' + str(timeoutValue) + 's')

        windowBase = 0
        nextToSend = 0
        isDone = False

        lastWindowMoveTime = time.time()

        # ACK receiver thread
        ackThread = threading.Thread(target=receiveAcks, args=(mySocket,))
        ackThread.daemon = True
        ackThread.start()

        # retransmit watcher thread
        watcherThread = threading.Thread(target=retransmitWatcher)
        watcherThread.daemon = True
        watcherThread.start()

        # run sliding window sender (main thread)
        slidingWindowSend(mySocket)

        # wait for ACK thread to finish
        ackThread.join(timeout=10)

        # send FIN
        sendFinish(mySocket, md5Hash)
        endTime = time.time()

        # generate report
        writeReport(filename, fSize)
        print('')
        print('server complete')

    except KeyboardInterrupt:
        print('')
        print('stop')
    except Exception as e:
        print('')
        print('Error ' + str(e))
        import traceback
        traceback.print_exc()
    finally:
        mySocket.close()
        print('Cleanup')