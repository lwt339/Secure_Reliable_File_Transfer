# all settings

# server IP
serverIP = '127.0.0.1'

# client IP
clientIP = '127.0.0.1'

# True = encrypted (Phase 2), False = plain (Phase 1)
securityEnabled = False


# Pre Shared Key (PSK)
# AES-256-GCM
psk = b'cs5700-group2-srft-secret-key32!'

# port
serverPort = 12000
clientPort = 12001


# IPv4 header settings
# version, IHL, TOS, total length, ID, flags, TTL, protocol, checksum, source IP, destination IP
ipVersion = 4
# 5 x 4 = 20B
ipIHL = 5
# type of service
ipTOS = 0
# time to live
ipTTL = 64
# UDP
ipProtocolUDP = 17
# IP header size
ipHeaderLen = 20
# flags dont fragment
ipDontFragment = 0x4000

# UDP header settings
# 8 bytes = src port, dst port, length, checksum
udpHeaderLen = 8


# custom SRFT protocol header on top of UDP payload
# B = packet type (1 byte)
# I = seq number (4 b)
# x = padding (1, for alignment)
# I = ack number (4)
# H = checksum (2)
# H = data length (2)
srftFormat = '!BIxIHH'
# 14 total
srftHeaderLen = 14


# packet type codes
# Phase 1
# client send filename to request
typeFilename    = 0x01
# server file metadata back
typeFileInfo    = 0x02
# server file data chunks
typeData        = 0x03
# client cumulative acknowledgment
typeAck         = 0x04
# server transfer done
typeFin         = 0x05
# client confirms finish
typeFinAck      = 0x06

# Phase 2 types
# client starts security handshake
typeClientHello = 0x10
# server respond
typeServerHello = 0x11
# server sends SHA-256
typeShaVerify   = 0x12
# client confirm SHA 256
typeShaConfirm  = 0x13

# readable names
typeNames = {
    0x01: 'FILENAME',      0x02: 'FILE_INFO',
    0x03: 'DATA',          0x04: 'ACK',
    0x05: 'FIN',           0x06: 'FIN_ACK',
    0x10: 'CLIENT_HELLO',  0x11: 'SERVER_HELLO',
    0x12: 'SHA_VERIFY',    0x13: 'SHA_CONFIRM',
}


# reliable transfer settings
# max data bytes
chunkSize = 1024
# socket receive buffer
recvBufferSize = 65535
# retransmission timeout
timeoutValue = 0.1
# sliding window size
windowSize = 64

ackEvery = 3
# handshake or FIN
maxRetry = 15
# recv timeout
maxTimeouts = 30

# receiver window limit
# seqNum > expectedSeq + 5000
recvWindowLimit = 5000


# file paths

# test files
serverDir = './server/'
# received file
clientDir = './client/'

reportPath = 'Server_Report.txt'
clientReportPath = 'Client_Report.txt'



# debug
showDebug = True
printEvery = 500


# AEAD
nonceSize = 12
# 16B auth tag
tagSize = 16

# handshake sizes

# nonce
handshakeNonceSize = 16
# random session ID
sessionIdSize = 8
protocolVersion = 1

# AEAD
CIPHER_AES_GCM = 'AES-256-GCM'
CIPHER_CHACHA = 'ChaCha20-Poly1305'
ALLOWED_CIPHERS = (CIPHER_AES_GCM, CIPHER_CHACHA)

# default AES-256-GCM
cipherInfo = CIPHER_AES_GCM


attackMode = 'none'

# valid
validAttackModes = ['none', 'tamper', 'replay', 'inject', 'wrongpsk']