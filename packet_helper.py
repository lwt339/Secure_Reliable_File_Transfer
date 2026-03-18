# Packet Helper Functions


import struct
import hashlib # calculate MD5 and SHA-256 hash
import os
import sys # macOS and Linux detect

from socket import *
from config import *

# Detect operating system
# macOS test local ( use host byte order )
# Linux for AWS ( network byte order )
isMac = (sys.platform == 'darwin')



# checksum

def calcChecksum(data):

    # if length is odd, pad with 0
    # process 2 bytes at a time
    if len(data) % 2 != 0:
        data = data + b'\x00'

    # split to 16 bit words and add them up
    checksum = 0
    for i in range(0, len(data), 2):
        # ! = network byte order  H = unsigned short
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum = checksum + word

    # handle carry (fold any overflow back into 16 bits)
    while checksum > 0xFFFF:
        carry = checksum >> 16 # carry bits (shift right 16)
        remainder = checksum & 0xFFFF
        checksum = carry + remainder

    # one s complement
    # flip all bits
    result = ~checksum & 0xFFFF

    return result

# Verify checksum on the receiver side
def verifyChecksum(data):

    # pad if odd length
    if len(data) % 2 != 0:
        data = data + b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum = checksum + word

    # wrap around carries
    while checksum > 0xFFFF:
        carry = checksum >> 16
        remainder = checksum & 0xFFFF
        checksum = carry + remainder

    # if checksum correct
    # result should be all ones (0xFFFF)
    result = ~checksum & 0xFFFF
    return result == 0


# IPv4 Header

def buildIpHeader(srcIP, dstIP, totalLen):
    # version 4 and IHL 5
    versionAndIHL = (ipVersion << 4) | ipIHL

    # identification ( fragment reassembly ,don't fragment )
    packetId = 54321


    # macOS (Darwin) with SOCK_RAW + IP_HDRINCL ( host byte order )

    if isMac:
        # mixed byte order
        part1 = struct.pack('BB', versionAndIHL, ipTOS) # 2 bytes
        part2 = struct.pack('H', totalLen) # host byte order for macOS
        part3 = struct.pack('!H', packetId) # network byte order
        part4 = struct.pack('H', ipDontFragment)
        part5 = struct.pack('!BBH', ipTTL, ipProtocolUDP, 0)  # checksum = 0
        part6 = inet_aton(srcIP) # inet_aton() IP string to 4 bytes binary
        part7 = inet_aton(dstIP) # 4 bytes
        header = part1 + part2 + part3 + part4 + part5 + part6 + part7
    else:
        # Linux: network byte order big endian
        header = struct.pack('!BBHHHBBH4s4s', # 20 bytes
            versionAndIHL, # B(1)
            ipTOS, # B(1) Type of Service
            totalLen, # H(2)
            packetId, # H(2)
            ipDontFragment, # H(2) Flags + Fragment Offset
            ipTTL, # B(1)
            ipProtocolUDP, # B(1)
            0, # H(2) Header Checksum (kernel calculates for us so put 0)
            inet_aton(srcIP),# 4s(4) Source IP Address
            inet_aton(dstIP) # 4s(4) Dest IP
        )

    return header


# UDP Header (8 bytes)
# source port, dest port, length, checksum

def buildUdpHeader(srcPort, dstPort, udpLen):

    udpCheck = 0  # checksum optional

    header = struct.pack('!HHHH',
        srcPort, # H = Source Port
        dstPort, # H = Destination Port
        udpLen, # H = Total Length
        udpCheck # H= Checksum = 0
    )

    return header


# SRFT header and data
# packet type, seq number, ack number, checksum, data length

def buildSrftPayload(pktType, seqNum, ackNum, data=b''):

    dataLen = len(data)

    # pack header
    tempHeader = struct.pack(srftFormat,
        pktType,# B (1 )
        seqNum, # I (4 )
        ackNum, # I (4 )
        0, # H ( 2 ): checksum placeholder = 0
        dataLen # H (2 bytes)
    )

    # calc checksum:  header + data
    check = calcChecksum(tempHeader + data)

    # repack header with the real checksum
    finalHeader = struct.pack(srftFormat,
        pktType, seqNum, ackNum,
        check, # real checksum
        dataLen
    )
    return finalHeader + data


# Combine to One Packet
# IP header + UDP header + SRFT header + data
# encapsulation each layer adds its own header

def buildFullPacket(srcIP, dstIP, srcPort, dstPort,
                    pktType, seqNum, ackNum, data=b''):

    # SRFT payload (SRFT header + data)
    srftPayload = buildSrftPayload(pktType, seqNum, ackNum, data)

    # UDP header
    udpTotalLen = udpHeaderLen + len(srftPayload)
    udpHdr = buildUdpHeader(srcPort, dstPort, udpTotalLen)

    # IP header
    ipTotalLen = ipHeaderLen + udpTotalLen
    ipHdr = buildIpHeader(srcIP, dstIP, ipTotalLen)

    # combine
    packet = ipHdr + udpHdr + srftPayload
    return packet


# De-encapsulation
# Parse a raw received packet
# receiver de-encapsulation strip headers layer by layer

def parseFullPacket(rawData, myPort=None):

    try:
        # minimum len IP(20) + UDP(8) + SRFT(14) = 42
        if len(rawData) < ipHeaderLen + udpHeaderLen + srftHeaderLen:
            return None

        # parse IP header 20
        ipRaw = rawData[0:ipHeaderLen]
        ipFields = struct.unpack('!BBHHHBBH4s4s', ipRaw)

        versionAndIHL = ipFields[0]
        ihl = versionAndIHL & 0x0F
        ipActualLen = ihl * 4  # actual header length

        srcIP = inet_ntoa(ipFields[8])   # binary to string
        dstIP = inet_ntoa(ipFields[9])

        # UDP header
        udpStart = ipActualLen
        udpRaw = rawData[udpStart:udpStart + udpHeaderLen]
        udpFields = struct.unpack('!HHHH', udpRaw)
        srcPort = udpFields[0]
        dstPort = udpFields[1]

        # port filtering for SOCK_RAW
        if myPort is not None and dstPort != myPort:
            return None

        # unpack SRFT header
        srftStart = udpStart + udpHeaderLen
        if len(rawData) < srftStart + srftHeaderLen:
            return None

        srftRaw = rawData[srftStart:srftStart + srftHeaderLen]
        srftFields = struct.unpack(srftFormat, srftRaw)
        pktType = srftFields[0]
        seqNum = srftFields[1]
        ackNum = srftFields[2]
        checkVal = srftFields[3]
        dataLen = srftFields[4]

        # extract the data portion (everything after the header)
        dataStart = srftStart + srftHeaderLen
        data = rawData[dataStart:dataStart + dataLen]

        # verify checksum
        srftWithData = rawData[srftStart:dataStart + dataLen]
        if not verifyChecksum(srftWithData):
            if showDebug:
                print(' Error: Checksum Failed, Packet dropped')
            return None

        # checksum is good, return a dictionary with all the fields
        return {
            'srcIP': srcIP,       'dstIP': dstIP,
            'srcPort': srcPort,   'dstPort': dstPort,
            'pktType': pktType,
            'seqNum': seqNum,     'ackNum': ackNum,
            'dataLen': dataLen,
            'data': data
        }

    except struct.error:
        return None
    except Exception:
        return None



# create Sockets
# Linux (AWS EC2): socket(AF_INET, SOCK_RAW, IPPROTO_UDP) raw udp
# macOS (local test): socket(AF_INET, SOCK_DGRAM) normal udp

def createServerSocket():

    try:
        if isMac:
            # macOS: normal UDP socket, bind to server port
            sock = socket(AF_INET, SOCK_DGRAM)
            sock.bind(('', serverPort))
            print('    ( macOS ) SOCK_DGRAM for local testing      ')
            print('    Bind to port: ' + str(serverPort))
            return sock
        else:
            # Linux: use raw socket
            # build IP and UDP headers
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
            sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            print('    ( Linux AWS ) SOCK_RAW + IP_HDRINCL     ')
            return sock

    except PermissionError:
        print('')
        print('Permission denied')
        raise
    except Exception as e:
        print('  ( Error ) Failed to create socket: ' + str(e))
        raise


def createClientSocket():
    # Create the client socket

    try:
        if isMac:
            sock = socket(AF_INET, SOCK_DGRAM)
            sock.bind(('', clientPort))
            print('    [macOS] SOCK_DGRAM for local testing')
            print('    Bound to port: ' + str(clientPort))
            return sock
        else:
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
            sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            print('    [Linux ] SOCK_RAW + IP_HDRINCL')
            return sock

    except PermissionError:
        print('')
        print('Permission denied, check ')
        raise
    except Exception as e:
        print('  [Error] Failed to create socket: ' + str(e))
        raise



# for Sending
def sendPacket(sock, dstIP, dstPort, srcIP, srcPort,
               pktType, seqNum, ackNum, data=b''):

    if isMac:
        # macOS only SRFT header + data through normal UDP
        payload = buildSrftPayload(pktType, seqNum, ackNum, data)
        sock.sendto(payload, (dstIP, dstPort))
    else:
        # Linux: send full IP + UDP + SRFT packet through SOCK_RAW
        packet = buildFullPacket(
            srcIP, dstIP, srcPort, dstPort,
            pktType, seqNum, ackNum, data
        )
        sock.sendto(packet, (dstIP, 0))

# Raw Socket for Receiving
def recvPacket(sock, myPort, timeout=None):
    if timeout is not None:
        sock.settimeout(timeout)

    try:
        if isMac:
            # macOS: normal UDP , receive just the SRFT payload
            rawData, addr = sock.recvfrom(recvBufferSize)
            senderIP = addr[0]
            senderPort = addr[1]

            # parse SRFT header (no need for macOS)
            if len(rawData) < srftHeaderLen:
                return None

            try:
                fields = struct.unpack(srftFormat, rawData[0:srftHeaderLen])
            except struct.error:
                return None

            pktType = fields[0]
            seqNum = fields[1]
            ackNum = fields[2]
            checkVal = fields[3]
            dataLen = fields[4]

            # dataLen check (prevent crash on garbage packets)
            if dataLen > len(rawData) - srftHeaderLen:
                return None

            data = rawData[srftHeaderLen:srftHeaderLen + dataLen]

            # verify checksum
            if not verifyChecksum(rawData[0:srftHeaderLen + dataLen]):
                return None

            return {
                'srcIP': senderIP,    'dstIP': '',
                'srcPort': senderPort, 'dstPort': myPort,
                'pktType': pktType,
                'seqNum': seqNum,     'ackNum': ackNum,
                'dataLen': dataLen,
                'data': data
            }
        else:
            # Linux SOCK_RAW, receive complete IP+UDP+SRFT packet
            rawData, addr = sock.recvfrom(recvBufferSize)
            parsed = parseFullPacket(rawData, myPort)
            if parsed is None:
                return None

            # only accept packets for port
            if parsed['dstPort'] != myPort:
                return None

            return parsed

    except Exception:
        # timeout or error
        return None




# Calculate MD5 hash of a file
# verify file integrity
def calculateMD5(filepath):

    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


# SHA-256 hash of a file
# end to end file verification
def calculateSHA256(filepath):

    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


# number chunks a file needs (without loading file into memory)
# important for large files
def countChunks(filepath):

    fileSize = os.path.getsize(filepath)
    # round up
    numChunks = (fileSize + chunkSize - 1) // chunkSize
    return numChunks


# Read one chunk from file by sequence number
def readChunk(filepath, seqNum):

    # calc where chunk start
    offset = seqNum * chunkSize

    # open file, jump to position, read one chunk, close file
    with open(filepath, 'rb') as f:
        f.seek(offset)
        data = f.read(chunkSize)

    return data


# Split file into small chunks (for small files only)
def splitFile(filepath):

    chunks = []
    with open(filepath, 'rb') as f:
        while True:
            piece = f.read(chunkSize)
            if not piece:
                break
            chunks.append(piece)
    return chunks


# Format seconds
# hh:mm:ss for report
def formatTime(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return str(h).zfill(2) + ':' + str(m).zfill(2) + ':' + str(s).zfill(2)

# readable name packet type (for debugging)
def getTypeName(pktType):
    if pktType in typeNames:
        return typeNames[pktType]
    return 'UNKNOWN'