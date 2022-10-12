from socket import * 
import os
import sys
import struct
import time 
import select 
import binascii
ICMP_ECHO_REQUEST = 8

def checksum(string):
    # Calculate checksum for given hex string
    # Rules to follow: http://www.faqs.org/rfcs/rfc1071.html
    csum = 0

    #pair 2 adjacent to form 16 bits integer
    countTo = (len(string) // 2) * 2
    for count in range(0, countTo, 2):
        thisVal = string[count+1] *256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(string):
        csum = csum + string[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Destination unreachable."
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #Fetch the ICMP header from the IP packet
        type, code, checksum, packet_id, seq = struct.unpack('bbHHh', recPacket[20:28])
        if type == 0 and packet_id == ID:
            send_time,  = struct.unpack('d', recPacket[28:])
            ip_header = struct.unpack('!BBHHHBBH4s4s' , recPacket[:20])
            ttl = ip_header[5]
            saddr = inet_ntoa(ip_header[8])
            length = len(recPacket) - 20
            rtt = (timeReceived - send_time) * 1000
            return '{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(length, saddr, seq, ttl, rtt)

        #If no reply from server for current packet
        timeLeft = timeLeft - howLongInSelect 
        if timeLeft <= 0:
            return "Request timed out for icmp seq {}.".format(seq)



def sendOnePing(mySocket, destAddr, ID, sequence):
    # Dummy Header is type (8), code (0), checksum (0), id (ID), sequence (i)
    myChecksum = 0
    # Create packet header with defined data and 0 checksum
    # Convert Python datatype into byte formatted string 
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, sequence) 
    #payload
    data = struct.pack("d", time.time())
    # Calculate the checksum for the data and dummy header
    myChecksum = checksum(header + data)
    # Assign correct value for checksum
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff  # htons: convert to network byte order Big Endian
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, sequence) 
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) 

def doOnePing(destAddr, sequence, timeout):
    icmp = getprotobyname("icmp")
    mySocket = socket(AF_INET, SOCK_DGRAM, icmp) #sending PING using UDP
    myID = os.getpid() & 0xFFFF #get process ID for PING
    sendOnePing(mySocket,destAddr,myID, sequence)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close() 
    return delay

def ping(host, timeout=1):
    # timeout: if cannot receive reply within 1 second, consider the packet
    # as loss
    dest = gethostbyname(host)
    loss = 0
    print(f"PING {host} ({dest}): ")
    # Send seperately 4 ping request in approx 1 sec
    for i in range(1,5):
        result = doOnePing(dest, i, timeout)
        if not result:
            print("Request time out")
            loss += 1
        else:
            print(result)
        time.sleep(1)
    print(f"Packet: sent = {4} received = {4-loss} lost = {loss} ")

print("#1 PING")
ping("google.com")

print("#2 PING")
ping("deakin.edu.au")