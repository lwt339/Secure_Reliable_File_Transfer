# helper functions for packets, checksum, sockets, hashing, and security



import struct
import hashlib
import hmac as hmacLib
import os
import sys

from socket import *
from config import *
import config as _config

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# macOS ,Linux detection
isMac = (sys.platform == 'darwin')

# AEAD
_session_aead_cipher = None


def set_session_cipher(name):
    # called after handshake on client and server
    global _session_aead_cipher
    if name not in ALLOWED_CIPHERS:
        raise ValueError('unsupported session cipher: ' + repr(name))
    _session_aead_cipher = name


def get_session_cipher():
    if _session_aead_cipher is None:
        return CIPHER_AES_GCM
    return _session_aead_cipher

# IP packet ID, increments each packet
_ipPacketId = 0


# packet stats counter
checksumErrorCount = 0

def resetChecksumErrorCount():
    global checksumErrorCount
    checksumErrorCount = 0


# one complement checksum
def calcChecksum(data):
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

    # one's complement
    result = ~checksum & 0xFFFF
    return result


# receiver side verify checksum
# if result 0, no corruption
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
    versionAndIHL = (ipVersion << 4) | ipIHL

    # increment ID, wrap at 65535
    _ipPacketId = (_ipPacketId + 1) & 0xFFFF

    try:
        src_bin = inet_aton(srcIP)
        dst_bin = inet_aton(dstIP)
    except OSError as e:
        print('[error] buildIpHeader: invalid IPv4 address')
        print('        srcIP=' + repr(srcIP) + ', dstIP=' + repr(dstIP))
        print('        ' + str(e))
        raise

    if isMac:
        # macOS: host byte order
        part1 = struct.pack('BB', versionAndIHL, ipTOS)
        part2 = struct.pack('H', totalLen)       # host byte order
        part3 = struct.pack('!H', _ipPacketId)
        part4 = struct.pack('H', ipDontFragment)  # host order
        part5 = struct.pack('!BBH', ipTTL, ipProtocolUDP, 0)
        part6 = src_bin
        part7 = dst_bin
        header = part1 + part2 + part3 + part4 + part5 + part6 + part7
    else:
        # Linux: network byte order
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
            src_bin,
            dst_bin
        )
    return header


# UDP header
# 8 bytes: src port, dst port, length, checksum
# set checksum to 0 option for UDP
def buildUdpHeader(srcPort, dstPort, udpLen):
    udpCheck = 0
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

    tempHeader = struct.pack(srftFormat,
        pktType,
        seqNum,
        ackNum,
        # checksum placeholder
        0,
        dataLen
    )

    # checksum of header + data
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


# de-encapsulation
# receiver strips headers layer by layer
# IP - UDP - SRFT - data

def parseFullPacket(rawData, myPort=None):
    global checksumErrorCount
    try:
        # at least IP(20) + UDP(8) + SRFT(14) = 42 bytes
        if len(rawData) < ipHeaderLen + udpHeaderLen + srftHeaderLen:
            return None

        ipRaw = rawData[0:ipHeaderLen]
        ipFields = struct.unpack('!BBHHHBBH4s4s', ipRaw)
        versionAndIHL = ipFields[0]
        ihl = versionAndIHL & 0x0F
        ipActualLen = ihl * 4
        srcIP = inet_ntoa(ipFields[8])
        dstIP = inet_ntoa(ipFields[9])

        udpStart = ipActualLen
        if len(rawData) < udpStart + udpHeaderLen:
            return None
        udpRaw = rawData[udpStart:udpStart + udpHeaderLen]
        udpFields = struct.unpack('!HHHH', udpRaw)
        srcPort = udpFields[0]
        dstPort = udpFields[1]

        if myPort is not None and dstPort != myPort:
            return None

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

        # actual data
        dataStart = srftStart + srftHeaderLen

        # check dataLen
        if dataLen > len(rawData) - dataStart:
            return None

        data = rawData[dataStart:dataStart + dataLen]

        # verify checksum
        srftWithData = rawData[srftStart:dataStart + dataLen]
        if not verifyChecksum(srftWithData):
            # count
            checksumErrorCount = checksumErrorCount + 1
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
            # Linux/AWS: raw socket, build IP+UDP headers
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
# send full packet (we build)
def sendPacket(sock, dstIP, dstPort, srcIP, srcPort,
               pktType, seqNum, ackNum, data=b''):
    try:
        if isMac:
            # macOS: SRFT data through UDP socket
            payload = buildSrftPayload(pktType, seqNum, ackNum, data)
            sock.sendto(payload, (dstIP, dstPort))
        else:
            # Linux: send full packet (IP + UDP + SRFT) raw socket
            packet = buildFullPacket(
                srcIP, dstIP, srcPort, dstPort,
                pktType, seqNum, ackNum, data
            )
            sock.sendto(packet, (dstIP, 0))
    except OSError as e:
        print('[error] sendPacket: sendto failed')
        print('        dst ' + repr(dstIP) + ':' + str(dstPort) +
              '  src ' + repr(srcIP) + ':' + str(srcPort))
        print('        pktType=' + str(pktType) +
              ' seq=' + str(seqNum) + ' ack=' + str(ackNum) +
              ' dataLen=' + str(len(data)))
        print('        ' + str(e))
        raise


def recvPacket(sock, myPort, timeout=None):
    global checksumErrorCount
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        if isMac:
            # macOS: receive SRFT payload
            rawData, addr = sock.recvfrom(recvBufferSize)
            senderIP = addr[0]
            senderPort = addr[1]

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

            if dataLen > len(rawData) - srftHeaderLen:
                return None

            data = rawData[srftHeaderLen:srftHeaderLen + dataLen]

            # verify checksum
            if not verifyChecksum(rawData[0:srftHeaderLen + dataLen]):
                # count checksum errors
                checksumErrorCount = checksumErrorCount + 1
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
            # Linux: full IP+UDP+SRFT packet
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
def flushSocket(sock):
    # clean leftover packets
    oldTimeout = sock.gettimeout()
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
# MD5 for Phase 1
# SHA-256 for Phase 2 end to end verification
def calculateMD5(filepath):
    # MD5 hash
    md5 = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
    except OSError as e:
        print('[error] cannot read file for MD5: ' + repr(filepath))
        print('        ' + str(e))
        raise
    return md5.hexdigest()


def calculateSHA256(filepath):
    sha = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
    except OSError as e:
        print('[error] cannot read file for SHA-256: ' + repr(filepath))
        print('        ' + str(e))
        raise
    return sha.hexdigest()



#  break file into chunks for sliding window sender
def countChunks(filepath):
    # cchunks that file needs
    try:
        fileSize = os.path.getsize(filepath)
    except OSError as e:
        print('[error] cannot stat file for chunk count: ' + repr(filepath))
        print('        ' + str(e))
        raise
    # empty file
    if fileSize == 0:
        return 0
    numChunks = (fileSize + chunkSize - 1) // chunkSize
    return numChunks

# read one chunk from file at correct offset
def readChunk(filepath, seqNum):
    if seqNum < 0:
        raise ValueError('readChunk: seqNum must be >= 0, got ' + str(seqNum))
    offset = seqNum * chunkSize
    with open(filepath, 'rb') as f:
        f.seek(offset)
        data = f.read(chunkSize)
    return data

# read one chunk using an already open file handle
# no open/close each time
def readChunkFromHandle(fileHandle, seqNum):
    if seqNum < 0:
        raise ValueError(
            'readChunkFromHandle: seqNum must be >= 0, got ' + str(seqNum))
    offset = seqNum * chunkSize
    fileHandle.seek(offset)
    data = fileHandle.read(chunkSize)
    return data




# check filename is safe
def validateFilename(filename):
    # block path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        print('[error] invalid filename (path traversal attempt): ' + filename)
        return False
    # reject empty
    if len(filename) == 0 or len(filename) > 255:
        print('[error] invalid filename length: ' + str(len(filename)))
        return False

    if '\x00' in filename:
        print('[error] invalid filename (null byte)')
        return False
    return True


# PSK validation,
def validatePsk(pskKey):
    if not isinstance(pskKey, bytes):
        print('[warning] PSK must be bytes, got ' + str(type(pskKey)))
        return False
    if len(pskKey) != 32:
        print('[warning] PSK should be exactly 32 bytes for AES-256')
        print('  current PSK length: ' + str(len(pskKey)) + ' bytes')
        return False
    return True



def formatTime(seconds):
    # hh:mm:ss
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return str(h).zfill(2) + ':' + str(m).zfill(2) + ':' + str(s).zfill(2)


# readable name
def getTypeName(pktType):
    if pktType in typeNames:
        return typeNames[pktType]
    return 'UNKNOWN(0x' + hex(pktType) + ')'


# Phase 2 security functions

# HMAC
def computeHmac(key, message):
    # HMAC-SHA256, returns 32
    tag = hmacLib.new(key, message, hashlib.sha256).digest()
    return tag

# verify HMAC matches
def verifyHmac(key, message, expectedTag):
    # constant time
    computedTag = hmacLib.new(key, message, hashlib.sha256).digest()
    return hmacLib.compare_digest(computedTag, expectedTag)


# key derivation with HKDF-SHA256
def deriveSessionKey(pskKey, clientNonce, serverNonce):
    salt = clientNonce + serverNonce

    info = b'srft-session-encryption-key'

    # HKDF extract then expand
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    sessionKey = hkdf.derive(pskKey)
    return sessionKey



# AAD (Additional Authenticated Data) for AEAD
# session_id, seq, ack, type
def buildAad(sessionId, pktType, seqNum, ackNum):
    # if an attacker changes any of these, decryption fails
    aad = sessionId + struct.pack('!BII', pktType, seqNum, ackNum)
    return aad

# encrypt AEAD
# returns: nonce(12 bytes) + ciphertext + tag(16 bytes)
def encryptData(sessionKey, plaintext, sessionId, pktType, seqNum, ackNum):
    mode = get_session_cipher()

    nonce = os.urandom(nonceSize)

    aad = buildAad(sessionId, pktType, seqNum, ackNum)

    if mode == CIPHER_AES_GCM:
        aesgcm = AESGCM(sessionKey)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    elif mode == CIPHER_CHACHA:
        chacha = ChaCha20Poly1305(sessionKey)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)
    else:
        raise ValueError('encryptData: unknown session cipher ' + repr(mode))

    # receiver knows what nonce we used
    encrypted = nonce + ciphertext
    return encrypted


# decrypt AEAD (must match)
def decryptData(sessionKey, encryptedData, sessionId, pktType, seqNum, ackNum):

    try:
        # min length
        if len(encryptedData) < nonceSize + tagSize:
            return None

        # split
        nonce = encryptedData[0:nonceSize]
        ciphertext = encryptedData[nonceSize:]

        mode = get_session_cipher()

        # AAD match
        aad = buildAad(sessionId, pktType, seqNum, ackNum)

        if mode == CIPHER_AES_GCM:
            aesgcm = AESGCM(sessionKey)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        elif mode == CIPHER_CHACHA:
            chacha = ChaCha20Poly1305(sessionKey)
            plaintext = chacha.decrypt(nonce, ciphertext, aad)
        else:
            return None

        return plaintext

    except Exception:
        # decryption failed = tampered, forged, or wrong key
        return None




# handshake message builders

def buildClientHello(pskKey):

    clientNonce = os.urandom(handshakeNonceSize)

    # protocol
    versionByte = struct.pack('!B', protocolVersion)

    # cipher info
    cipherBytes = _config.cipherInfo.encode('utf-8')
    cipherLen = struct.pack('!H', len(cipherBytes))

    messageToSign = clientNonce + versionByte + cipherLen + cipherBytes

    # proves PSK
    tag = computeHmac(pskKey, messageToSign)

    # data + HMAC tag
    helloData = messageToSign + tag
    return (helloData, clientNonce)


# parse ClientHello from client, verify HMAC
def parseClientHello(pskKey, data):
    try:
        if len(data) < handshakeNonceSize + 1 + 2 + 32:
            return None

        clientNonce = data[0:handshakeNonceSize]

        pos = handshakeNonceSize
        versionByte = data[pos:pos+1]
        pos = pos + 1

        cipherLen = struct.unpack('!H', data[pos:pos+2])[0]
        pos = pos + 2

        # validate cipher
        if cipherLen > 256 or pos + cipherLen + 32 > len(data):
            print('  [security] ClientHello invalid cipher length')
            return None

        # cipher info
        cipherBytes = data[pos:pos+cipherLen]
        pos = pos + cipherLen

        try:
            cipher_str = cipherBytes.decode('utf-8')
        except UnicodeDecodeError:
            print('  [security] ClientHello cipher info not valid UTF-8')
            return None

        if cipher_str not in ALLOWED_CIPHERS:
            print('  [security] ClientHello unknown cipher: ' + repr(cipher_str))
            print('  allowed: ' + str(ALLOWED_CIPHERS))
            return None

        # HMAC tag
        receivedTag = data[pos:pos+32]

        # reconstruct
        messageToSign = clientNonce + versionByte + struct.pack('!H', cipherLen) + cipherBytes

        # check HMAC, wrong = bad PSK
        if not verifyHmac(pskKey, messageToSign, receivedTag):
            print('  [security] ClientHello HMAC FAILED!')
            print('  -> PSK mismatch. connection rejected.')
            return None

        print('  [security] ClientHello HMAC verified ok')
        return (clientNonce, cipher_str)

    except Exception as e:
        print('  [security] error parsing ClientHello: ' + str(e))
        return None

# build ServerHello response
def buildServerHello(pskKey, clientNonce):

    serverNonce = os.urandom(handshakeNonceSize)

    sessionId = os.urandom(sessionIdSize)

    messageToSign = serverNonce + sessionId + clientNonce

    tag = computeHmac(pskKey, messageToSign)

    helloData = serverNonce + sessionId + tag
    return (helloData, serverNonce, sessionId)


# parse and verify
def parseServerHello(pskKey, data, clientNonce):

    try:
        # serverNonce(16) + sessionId(8) + tag(32) = 56
        expectedSize = handshakeNonceSize + sessionIdSize + 32
        if len(data) < expectedSize:
            return (None, None)

        serverNonce = data[0:handshakeNonceSize]

        # session ID
        pos = handshakeNonceSize
        sessionId = data[pos:pos+sessionIdSize]
        pos = pos + sessionIdSize

        # HMAC
        receivedTag = data[pos:pos+32]

        # reconstruct
        messageToSign = serverNonce + sessionId + clientNonce

        # check HMAC
        if not verifyHmac(pskKey, messageToSign, receivedTag):
            print('  [security] ServerHello HMAC Failed')
            print('  -> PSK mismatch. connection rejected.')
            return (None, None)

        print('  [security] ServerHello HMAC verified ok')
        return (serverNonce, sessionId)

    except Exception as e:
        print('  [security] error parsing ServerHello: ' + str(e))
        return (None, None)