# helper functions for packets, checksum, sockets, hashing, and security



import struct
import hashlib
# built in HMAC module
import hmac as hmacLib
import os
import sys

from socket import *
from config import *

# need cryptography library for AES GCM and HKDF

# install: pip install cryptography
# on AWS:  pip install cryptography --break-system-packages
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# macOS vs Linux detection
# macOS cant do SOCK_RAW on loopback, so use SOCK_DGRAM for local test
# Linux (AWS) = real SOCK_RAW + IP_HDRINCL
isMac = (sys.platform == 'darwin')

# IP packet ID, increments each packet
# avoids fragmentation/reassembly confusion
_ipPacketId = 0


# one complement checksum
# sender computes it, puts in header
# receiver runs it again, should get 0 if correct
# no pseudo header needed so just checksum over SRFT header + data

def calcChecksum(data):
    # 2 bytes at a time (16 bit)

    # pad if odd number of bytes
    if len(data) % 2 != 0:
        data = data + b'\x00'

    # add all 16 bit words
    checksum = 0
    for i in range(0, len(data), 2):
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum = checksum + word

    # wrap around overflow
    while checksum > 0xFFFF:
        carry = checksum >> 16
        remainder = checksum & 0xFFFF
        checksum = carry + remainder

    # flip bits
    # one's complement
    result = ~checksum & 0xFFFF
    return result


# receiver side: verify checksum
# if result is 0, no corruption
def verifyChecksum(data):

    if len(data) % 2 != 0:
        data = data + b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum = checksum + word

    while checksum > 0xFFFF:
        carry = checksum >> 16
        remainder = checksum & 0xFFFF
        checksum = carry + remainder

    result = ~checksum & 0xFFFF
    return result == 0


# build IPv4 header
# 20 bytes: ver, IHL, TOS, total len, ID, flags, TTL, proto, checksum, src, dst

def buildIpHeader(srcIP, dstIP, totalLen):
    global _ipPacketId
    # version(4 bits) + IHL(4 bits) into 1 byte
    versionAndIHL = (ipVersion << 4) | ipIHL

    # increment ID, wrap at 65535
    _ipPacketId = (_ipPacketId + 1) & 0xFFFF

    if isMac:
        # macOS: host byte order for total_length and fragment_offset
        # macOS kernel quirk with raw sockets
        part1 = struct.pack('BB', versionAndIHL, ipTOS)
        part2 = struct.pack('H', totalLen)       # host byte order
        part3 = struct.pack('!H', _ipPacketId)
        part4 = struct.pack('H', ipDontFragment)  # host order
        part5 = struct.pack('!BBH', ipTTL, ipProtocolUDP, 0)
        part6 = inet_aton(srcIP)
        part7 = inet_aton(dstIP)
        header = part1 + part2 + part3 + part4 + part5 + part6 + part7
    else:
        # Linux: everything network byte order (big endian)
        header = struct.pack('!BBHHHBBH4s4s',
            versionAndIHL,
            ipTOS,
            totalLen,
            _ipPacketId,
            ipDontFragment,
            ipTTL,
            ipProtocolUDP,
            # checksum = 0, kernel fills it on Linux
            0,
            inet_aton(srcIP),
            inet_aton(dstIP)
        )
    return header


# UDP header
# 8 bytes: src port, dst port, length, checksum
# set checksum to 0 since it optional
def buildUdpHeader(srcPort, dstPort, udpLen):
    udpCheck = 0  # optional for UDP
    header = struct.pack('!HHHH',
        srcPort,
        dstPort,
        udpLen,
        udpCheck
    )
    return header


# build our SRFT header + data
# custom protocol header
# 14 bytes: type(1) + seq(4) + pad(1) + ack(4) + checksum(2) + len(2)

def buildSrftPayload(pktType, seqNum, ackNum, data=b''):
    dataLen = len(data)

    # first pack with checksum = 0 (placeholder)
    tempHeader = struct.pack(srftFormat,
        pktType,
        seqNum,
        ackNum,
        # checksum placeholder
        0,
        dataLen
    )

    # compute checksum of header + data
    check = calcChecksum(tempHeader + data)

    # repack with actual checksum
    finalHeader = struct.pack(srftFormat,
        pktType, seqNum, ackNum,
        check,
        dataLen
    )
    return finalHeader + data


# full packet = encapsulation
# IP (20B),  UDP (8B),  SRFT (14B), data
# inside out: application - transport - network layer
def buildFullPacket(srcIP, dstIP, srcPort, dstPort,
                    pktType, seqNum, ackNum, data=b''):

    # SRFT payload (app layer)
    srftPayload = buildSrftPayload(pktType, seqNum, ackNum, data)

    # UDP header (transport layer)
    udpTotalLen = udpHeaderLen + len(srftPayload)
    udpHdr = buildUdpHeader(srcPort, dstPort, udpTotalLen)

    # IP header (network layer)
    ipTotalLen = ipHeaderLen + udpTotalLen
    ipHdr = buildIpHeader(srcIP, dstIP, ipTotalLen)

    # put it all together (encapsulation)
    packet = ipHdr + udpHdr + srftPayload
    return packet


# parse received packet (de-encapsulation)
# receiver strips headers layer by layer
# IP - UDP - SRFT - data

def parseFullPacket(rawData, myPort=None):
    try:
        # need at least IP(20) + UDP(8) + SRFT(14) = 42 bytes
        if len(rawData) < ipHeaderLen + udpHeaderLen + srftHeaderLen:
            return None

        # parse IP header
        ipRaw = rawData[0:ipHeaderLen]
        ipFields = struct.unpack('!BBHHHBBH4s4s', ipRaw)
        versionAndIHL = ipFields[0]
        # lower 4 bits = IHL
        ihl = versionAndIHL & 0x0F
        # might be > 20 if options
        ipActualLen = ihl * 4
        srcIP = inet_ntoa(ipFields[8])
        dstIP = inet_ntoa(ipFields[9])

        # parse UDP header (right after IP)
        udpStart = ipActualLen
        # check enough bytes for UDP header
        # IHL might be > 5 if IP options
        if len(rawData) < udpStart + udpHeaderLen:
            return None
        udpRaw = rawData[udpStart:udpStart + udpHeaderLen]
        udpFields = struct.unpack('!HHHH', udpRaw)
        srcPort = udpFields[0]
        dstPort = udpFields[1]

        # SOCK_RAW gets all UDP, only keep ours
        if myPort is not None and dstPort != myPort:
            return None

        # parse SRFT header after UDP
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

        # get the actual data after SRFT header
        dataStart = srftStart + srftHeaderLen

        # check dataLen with actual packet size
        if dataLen > len(rawData) - dataStart:
            return None

        data = rawData[dataStart:dataStart + dataLen]

        # verify checksum, drop if corrupted
        srftWithData = rawData[srftStart:dataStart + dataLen]
        if not verifyChecksum(srftWithData):
            if showDebug:
                print('  checksum failed, packet dropped')
            return None

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


# socket creation
# Linux: SOCK_RAW + IP_HDRINCL (we build headers)
# macOS: SOCK_DGRAM (OS builds headers, for local testing)

def createServerSocket():
    try:
        if isMac:
            # macOS: normal UDP socket for local testing
            sock = socket(AF_INET, SOCK_DGRAM)
            sock.bind(('', serverPort))
            print('    (macOS) SOCK_DGRAM for local testing')
            print('    bound to port ' + str(serverPort))
            return sock
        else:
            # Linux/AWS: raw socket, we build IP+UDP headers
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
            sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            print('    (Linux) SOCK_RAW + IP_HDRINCL')
            return sock
    except PermissionError:
        print('error: need sudo for raw sockets on Linux')
        raise
    except Exception as e:
        print('error creating socket: ' + str(e))
        raise


def createClientSocket():
    try:
        if isMac:
            sock = socket(AF_INET, SOCK_DGRAM)
            sock.bind(('', clientPort))
            print('    (macOS) SOCK_DGRAM for local testing')
            print('    bound to port ' + str(clientPort))
            return sock
        else:
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
            sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            print('    (Linux) SOCK_RAW + IP_HDRINCL')
            return sock
    except PermissionError:
        print('error: permission denied! need sudo on Linux')
        raise
    except Exception as e:
        print('error creating socket: ' + str(e))
        raise


# send/receive helpers
# macOS: send SRFT payload only (OS adds IP+UDP)
# Linux: send full packet (we build everything)

def sendPacket(sock, dstIP, dstPort, srcIP, srcPort,
               pktType, seqNum, ackNum, data=b''):
    if isMac:
        # macOS: send just SRFT data through UDP socket
        payload = buildSrftPayload(pktType, seqNum, ackNum, data)
        sock.sendto(payload, (dstIP, dstPort))
    else:
        # Linux: send full packet (IP + UDP + SRFT) through raw socket
        packet = buildFullPacket(
            srcIP, dstIP, srcPort, dstPort,
            pktType, seqNum, ackNum, data
        )
        sock.sendto(packet, (dstIP, 0))


def recvPacket(sock, myPort, timeout=None):
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        if isMac:
            # macOS: receive SRFT payload
            rawData, addr = sock.recvfrom(recvBufferSize)
            senderIP = addr[0]
            senderPort = addr[1]

            # check minimum size
            if len(rawData) < srftHeaderLen:
                return None

            # parse SRFT header
            try:
                fields = struct.unpack(srftFormat, rawData[0:srftHeaderLen])
            except struct.error:
                return None

            pktType = fields[0]
            seqNum = fields[1]
            ackNum = fields[2]
            checkVal = fields[3]
            dataLen = fields[4]

            # bounds check
            if dataLen > len(rawData) - srftHeaderLen:
                return None

            data = rawData[srftHeaderLen:srftHeaderLen + dataLen]

            # verify checksum
            if not verifyChecksum(rawData[0:srftHeaderLen + dataLen]):
                return None

            return {
                'srcIP': senderIP,     'dstIP': '',
                'srcPort': senderPort, 'dstPort': myPort,
                'pktType': pktType,
                'seqNum': seqNum,      'ackNum': ackNum,
                'dataLen': dataLen,
                'data': data
            }
        else:
            # Linux: receive full IP+UDP+SRFT packet
            rawData, addr = sock.recvfrom(recvBufferSize)
            parsed = parseFullPacket(rawData, myPort)
            if parsed is None:
                return None
            if parsed['dstPort'] != myPort:
                return None
            return parsed

    except Exception:
        return None


# clear out old packets stuck in socket buffer
# happens on Linux when leftover packets from last test
# are still sitting there with different session keys
# prevents false AEAD failures

def flushSocket(sock):
    # clean leftover packets from socket buffer
    oldTimeout = sock.gettimeout()
    # super short timeout
    sock.settimeout(0.01)
    flushed = 0
    while True:
        try:
            sock.recvfrom(recvBufferSize)
            flushed = flushed + 1
        except Exception:
            break
    # put it back
    sock.settimeout(oldTimeout)
    if flushed > 0:
        print('  [clean] cleared ' + str(flushed) + ' stale packets from buffer')


# file hashing
# MD5 for Phase 1 (project says use md5sum to compare)
# SHA-256 for Phase 2 end to end verification
def calculateMD5(filepath):
    # MD5 hash of a file (Phase 1 integrity check)
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


def calculateSHA256(filepath):
    # SHA-256 hash of a file (Phase 2 end to end verify)
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


#  File Chunk Helpers
#  break file into chunks for the sliding window sender

def countChunks(filepath):
    # calculate how many chunks the file needs
    fileSize = os.path.getsize(filepath)
    # empty file (0 bytes = 0 chunks)
    if fileSize == 0:
        return 0
    numChunks = (fileSize + chunkSize - 1) // chunkSize
    return numChunks

# read one chunk from file at the correct offset
# avoids loading entire large file into memory
def readChunk(filepath, seqNum):
    offset = seqNum * chunkSize
    with open(filepath, 'rb') as f:
        f.seek(offset)
        data = f.read(chunkSize)
    return data

# read one chunk using an already open file handle
# way faster for big files, no open/close each time
def readChunkFromHandle(fileHandle, seqNum):

    offset = seqNum * chunkSize
    fileHandle.seek(offset)
    data = fileHandle.read(chunkSize)
    return data




# check filename is safe, no path traversal stuff
# handle errors and input validation

# server reject bad client requests
# client reject crafted server FILE_INFO responses


def validateFilename(filename):
    # block path traversal like ../../etc
    if '..' in filename or '/' in filename or '\\' in filename:
        print('[error] invalid filename (path traversal attempt): ' + filename)
        return False
    # reject empty or too long filenames
    if len(filename) == 0 or len(filename) > 255:
        print('[error] invalid filename length: ' + str(len(filename)))
        return False
    # reject filenames with null bytes
    if '\x00' in filename:
        print('[error] invalid filename (null byte)')
        return False
    return True


# PSK validation, catch bad key length early
# make sure PSK is 32 bytes for AES-256
def validatePsk(pskKey):
    # check that PSK is bytes and correct length
    # returns False if something looks wrong
    if not isinstance(pskKey, bytes):
        print('[warning] PSK must be bytes, got ' + str(type(pskKey)))
        return False
    if len(pskKey) != 32:
        print('[warning] PSK should be exactly 32 bytes for AES-256')
        print('  current PSK length: ' + str(len(pskKey)) + ' bytes')
        return False
    return True


# utility

def formatTime(seconds):
    # hh:mm:ss for report
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return str(h).zfill(2) + ':' + str(m).zfill(2) + ':' + str(s).zfill(2)


# get readable name for a packet type code
def getTypeName(pktType):
    if pktType in typeNames:
        return typeNames[pktType]
    return 'UNKNOWN(0x' + hex(pktType) + ')'


# Phase 2: security functions
# PSK auth, HMAC, key derivation, AES GCM encryption
# confidentiality - encrypt data
# integrity - detect tampering
# authentication - PSK handshake
# replay protection - reject duplicate packets



# HMAC
# only someone with the PSK can compute the right tag
# wrong tag = wrong PSK = reject connection
def computeHmac(key, message):
    # HMAC-SHA256, returns 32 byte tag
    tag = hmacLib.new(key, message, hashlib.sha256).digest()
    return tag

# verify HMAC tag matches
def verifyHmac(key, message, expectedTag):
    # constant time comparison prevent timing attacks
    computedTag = hmacLib.new(key, message, hashlib.sha256).digest()
    return hmacLib.compare_digest(computedTag, expectedTag)


# key derivation with HKDF-SHA256
# PSK is always the same, but we need a fresh key per session
# HKDF mixes PSK + random nonces to get unique session key

def deriveSessionKey(pskKey, clientNonce, serverNonce):
    # salt = both random nonces combined
    salt = clientNonce + serverNonce

    # info label for key purpose
    info = b'srft-session-encryption-key'

    # HKDF extract-then-expand
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        # 32 bytes = 256 bits for AES-256
        length=32,
        salt=salt,
        info=info
    )
    sessionKey = hkdf.derive(pskKey)
    return sessionKey



# build AAD (Additional Authenticated Data) for AEAD
# encryption/decryption
# AAD gets authenticated but not encrypted
# session_id, seq, ack, type
def buildAad(sessionId, pktType, seqNum, ackNum):
    # if an attacker changes any of these, decryption fails
    aad = sessionId + struct.pack('!BII', pktType, seqNum, ackNum)
    return aad

# encrypt with AES-256-GCM
# returns: nonce(12 bytes) + ciphertext + tag(16 bytes)
def encryptData(sessionKey, plaintext, sessionId, pktType, seqNum, ackNum):
    # create AES-GCM cipher with our session key
    aesgcm = AESGCM(sessionKey)

    # random 12 byte nonce (unique packet)
    nonce = os.urandom(nonceSize)

    # AAD from packet metadata
    aad = buildAad(sessionId, pktType, seqNum, ackNum)

    # encrypt: output = ciphertext + 16 byte auth tag appended
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # prepend nonce so receiver knows what nonce we used
    encrypted = nonce + ciphertext
    return encrypted


# decrypt AES-256-GCM
# returns plaintext or None if tampered/forged/wrong key
def decryptData(sessionKey, encryptedData, sessionId, pktType, seqNum, ackNum):

    try:
        # min length check: nonce(12) + tag(16) = 28 bytes
        if len(encryptedData) < nonceSize + tagSize:
            return None

        # split: first 12 bytes = nonce, rest = ciphertext + tag
        nonce = encryptedData[0:nonceSize]
        ciphertext = encryptedData[nonceSize:]

        aesgcm = AESGCM(sessionKey)

        # AAD must match what sender used exactly
        aad = buildAad(sessionId, pktType, seqNum, ackNum)

        # decrypt and verify auth tag
        # throws exception if verification fails (tampered/forged)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext

    except Exception:
        # decryption failed = tampered, forged, or wrong key
        return None




# handshake message builders
# ClientHello: client_nonce + version + cipher + HMAC
# ServerHello: server_nonce + session_id + HMAC
# both derive session key with HKDF
# if HMAC fails connection rejected

def buildClientHello(pskKey):
    # returns (helloData, clientNonce)

    # 16 random bytes
    clientNonce = os.urandom(handshakeNonceSize)

    # protocol version (1 byte)
    versionByte = struct.pack('!B', protocolVersion)

    # cipher info as bytes
    # tells server what cipher we want
    cipherBytes = cipherInfo.encode('utf-8')
    cipherLen = struct.pack('!H', len(cipherBytes))

    # message to sign = nonce + version + cipher info
    messageToSign = clientNonce + versionByte + cipherLen + cipherBytes

    # HMAC tag proves we have the PSK
    tag = computeHmac(pskKey, messageToSign)

    # final message: data + HMAC tag
    helloData = messageToSign + tag
    return (helloData, clientNonce)


# parse ClientHello from client, verify HMAC
# returns clientNonce if ok, None if bad PSK
def parseClientHello(pskKey, data):
    try:
        # min size: nonce(16) + version(1) + cipherLen(2) + tag(32) = 51
        if len(data) < handshakeNonceSize + 1 + 2 + 32:
            return None

        # extract client nonce
        clientNonce = data[0:handshakeNonceSize]

        # extract version byte
        pos = handshakeNonceSize
        versionByte = data[pos:pos+1]
        pos = pos + 1

        # cipher info length
        cipherLen = struct.unpack('!H', data[pos:pos+2])[0]
        pos = pos + 2

        # validate cipher info length (prevent out of bounds)
        if cipherLen > 256 or pos + cipherLen + 32 > len(data):
            print('  [security] ClientHello invalid cipher length')
            return None

        # cipher info string
        cipherBytes = data[pos:pos+cipherLen]
        pos = pos + cipherLen

        # HMAC tag (last 32 bytes)
        receivedTag = data[pos:pos+32]

        # reconstruct signed message
        messageToSign = clientNonce + versionByte + struct.pack('!H', cipherLen) + cipherBytes

        # check HMAC, wrong = bad PSK
        if not verifyHmac(pskKey, messageToSign, receivedTag):
            print('  [security] ClientHello HMAC FAILED!')
            print('  -> PSK mismatch. connection rejected.')
            return None

        print('  [security] ClientHello HMAC verified ok')
        return clientNonce

    except Exception as e:
        print('  [security] error parsing ClientHello: ' + str(e))
        return None

# build ServerHello response
# server sends: nonce + session ID + HMAC
def buildServerHello(pskKey, clientNonce):
    # returns: (helloData, serverNonce, sessionId)

    # random 16 bytes
    serverNonce = os.urandom(handshakeNonceSize)

    # random 8
    sessionId = os.urandom(sessionIdSize)

    # sign: serverNonce + sessionId + clientNonce
    # include clientNonce so this reply is tied to that client
    messageToSign = serverNonce + sessionId + clientNonce

    # HMAC using PSK
    tag = computeHmac(pskKey, messageToSign)

    # serverNonce + sessionId + HMAC tag
    helloData = serverNonce + sessionId + tag
    return (helloData, serverNonce, sessionId)


# parse and verify ServerHello from server
def parseServerHello(pskKey, data, clientNonce):
    # returns: (serverNonce, sessionId) if ok, (None, None) if bad PSK

    try:
        # expected size: serverNonce(16) + sessionId(8) + tag(32) = 56
        expectedSize = handshakeNonceSize + sessionIdSize + 32
        if len(data) < expectedSize:
            return (None, None)

        # server nonce
        serverNonce = data[0:handshakeNonceSize]

        # session ID
        pos = handshakeNonceSize
        sessionId = data[pos:pos+sessionIdSize]
        pos = pos + sessionIdSize

        # HMAC tag
        receivedTag = data[pos:pos+32]

        # reconstruct signed message
        # include clientNonce
        messageToSign = serverNonce + sessionId + clientNonce

        # check HMAC
        if not verifyHmac(pskKey, messageToSign, receivedTag):
            print('  [security] ServerHello HMAC FAILED!')
            print('  -> PSK mismatch. connection rejected.')
            return (None, None)

        print('  [security] ServerHello HMAC verified ok')
        return (serverNonce, sessionId)

    except Exception as e:
        print('  [security] error parsing ServerHello: ' + str(e))
        return (None, None)