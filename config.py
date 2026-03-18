# Project Setting


#  Network Address Settings

# Server IP address
# test local : 127.0.0.1
# AWS: change to server EC2 private IP
serverIP = '127.0.0.1'

# Client IP address
# Test local : 127.0.0.1
# AWS: change to client EC2 private IP
clientIP = '127.0.0.1'

# Server port
serverPort = 12000

# Client port
clientPort = 12001


#  IPv4 Header

ipVersion = 4           # IPv4
ipIHL = 5               # Header Length = 5 words
ipTOS = 0               # Type of Service
ipTTL = 64              # Time to Live
ipProtocolUDP = 17      # UDP
ipHeaderLen = 20        # IP header size = 5 x 4 = 20 bytes
ipDontFragment = 0x4000 # Dont Fragment flag


#  UDP Header
udpHeaderLen = 8  # always 8


#  Custom SRFT Protocol Header

# ! = network byte order
# Packet Type (1 byte) = B ( unsigned char )
# Seq Number (4 bytes) = I ( unsigned int )
# alignment padding (1 byte) = x ( pad byte )
# Ack Number (4 bytes) = I ( unsigned int )
# Checksum (2 bytes) = H ( unsigned short )
# Data Length (2 bytes) = H ( unsigned short )
srftFormat = '!BIxIHH'
# 1 + 4 + 1 + 4 + 2 + 2 = 14 bytes
srftHeaderLen = 14



#  Packet Type

# client requests to download a file
typeFilename = 0x01
typeFileInfo = 0x02    # file info reply (server to client)
typeData     = 0x03    # data packet (server to client)
typeAck      = 0x04    # acknowledgment (client to server)
typeFin      = 0x05    # finish signal (server to client)
typeFinAck   = 0x06    # finish confirm (client to server)

# printing readable names
# debug
typeNames = {
    0x01: 'FILENAME', 0x02: 'FILE_INFO', 0x03: 'DATA',
    0x04: 'ACK',      0x05: 'FIN',       0x06: 'FIN_ACK',
}


# Reliable Transfer
# checksum, sequence number, cumulative ACK, retransmission

# MSS file data each packet can carry
# data has to <= 1500 ( MTU ) - IP(20) + UDP(8) + SRFT(14)
chunkSize = 1024 # 1024 fit good size

# Receive buffer size
# 65535 maximum IP datagram size
recvBufferSize = 65535

# Timeout interval wait before retransmitting a packet
# fixed value
timeoutValue = 2.0

# Sliding window size ( can send 10 packet  before waiting for an ACK )
windowSize = 10

# Cumulative ACK interval (send ACK every 3 packets received)
ackEvery = 3

# Maximum retry counts
maxRetry = 15
maxTimeouts = 30


#  File Path

serverDir = './server/'
clientDir = './client/'
reportPath = 'report.txt'



#  Debug

showDebug = True # debug messages
printEvery = 50  # progress every 50 packet