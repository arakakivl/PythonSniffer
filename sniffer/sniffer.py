'''
Coding For Security - CP 6 - Python sniffer & API for capturing raw frames.
Guilherme Valloto, RM550353,
Victória Ventrilho, RM94872,
Vitor Arakaki, RM98824
'''

import socket
import os
from datetime import datetime
from struct import *
import struct
import json
from json import JSONEncoder
from typing import Any
import sys
import requests
sys.path.insert(1, "../common")
from frame import *
from packet import *
from segment import *

def format_mac(mac_addr):
    mac  = ""
    for n in mac_addr:
        mac += f"{str(hex(n)[2:]).zfill(2)}{':' if len(mac) != 15 else ''}"
    
    return mac

def format_ip(ip_addr):
    ip = ""
    for n in ip_addr:
        ip += f"{str(n)}."
    
    return ip[0:len(ip) - 1]

'''
A little of theory:
Everything starts at the layer one, the physical layer, where data is being transmitted as sets of zeros and ones.
In the second layer, data-link layer, things become more interesting. Now the data isn't zeros and ones anymore: they become a frame.
By building a socket that can handle these frames and return it in its most pure form, we can take the frame values. With that, we can do whatever we want.
The big problem is converting it and getting all of its fields, specially when we're getting all packets from all protocols (TCP, UDP, ICMP, etc.)
'''

# Constant variables
LOGS_PATH = os.path.join(os.getcwd(), "sniffer_logs")
MAXIMUM_UDP_DATAGRAM_SIZE = 65535
ETHERNET_HEADER_SIZE = 14
API_URL = "http://127.0.0.1:5000/"
PDUS_ENDPOINT = API_URL + "pdus"

# Building a socket with SOCK_RAW constant. With this we can take TCP, UDP, ICMP and other protocols packets.
# Anyway, the stuff that does not chage in the beginning is the ethernet frame, at the second layer of the Open Systems Interconnection model.
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# Starting packet capture.
print("Starting the application...")
while True:
    try:
        # Receiving a maximum of 65535 bytes, the same max length of a UDP frame.
        frame = raw_socket.recvfrom(MAXIMUM_UDP_DATAGRAM_SIZE)[0]

        # The following structure represents an ethernet II header: destination MAC address - source MAC address - Ethertype
        frame_header = frame[:ETHERNET_HEADER_SIZE]
        dest_mac, src_mac, ethertype = frame_header[:6], frame_header[6:12], frame_header[12:]

        # Constructing frame header
        frame_header_obj = FrameHeader(format_mac(dest_mac), format_mac(src_mac), "0x" + str(ethertype.hex()))
        
        # Getting Frame data (an encapsulated layer three packet)
        packet = frame[ETHERNET_HEADER_SIZE:]
        
        # Getting fields from packet
        version, ihl = str(packet[:1].hex())[:1], str(packet[:1].hex())[1]
        dscp = int.from_bytes(packet[1:2], byteorder='big') & int.from_bytes(b'\xfc', byteorder='big')
        ecn = int.from_bytes(packet[1:2], byteorder='big') & int.from_bytes(b'\x03', byteorder='big')
        total_length = int.from_bytes(packet[2:4], byteorder='big')
        identification = int.from_bytes(packet[4:6], byteorder='big')
        flags = {
            "0": int.from_bytes(packet[6:7], byteorder='big') & int.from_bytes(b'\x80', byteorder='big'),
            "DF": int.from_bytes(packet[6:7], byteorder='big') & int.from_bytes(b'\x40', byteorder='big'),
            "MF": int.from_bytes(packet[6:7], byteorder='big') & int.from_bytes(b'\x20', byteorder='big')
        }
        fragment_offset = int.from_bytes(packet[6:8], byteorder='big') & int.from_bytes(b'\x1f\xff', byteorder='big')
        ttl, protocol = int.from_bytes(packet[8:9], byteorder='big'), int.from_bytes(packet[9:10], byteorder='big')
        checksum = int.from_bytes(packet[10:12], byteorder='big')
        source_ip, dest_ip = format_ip(packet[12:16]), format_ip(packet[16:20])
        options = ""

        # Constructing packet header
        packet_header_obj = PacketHeader(version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, checksum, source_ip, dest_ip)
        
        # Getting data. Here we're using only ICMP, TCP and UDP protocols, but more protocols could be covered.
        segment = packet[int(ihl) * 4:]
        if protocol == 1:
            segment_obj = IcmpSegment(segment[0], segment[1], int.from_bytes(segment[2:4], byteorder='big'), str(segment[4:]))
        
        elif protocol == 6:
            segment_obj = TcpSegment(int.from_bytes(segment[0:2], byteorder='big'), int.from_bytes(segment[2:4], byteorder='big'), int.from_bytes(segment[4:8], byteorder='big'), int.from_bytes(segment[8:12], byteorder='big'), int.from_bytes(segment[12:13], byteorder='big') & 0xF0, str(segment[int.from_bytes(segment[12:13], byteorder='big') & 0xF0:]))
       
        elif packet_header_obj.Protocol == 17:
            segment_obj = UdpSegment(int.from_bytes(segment[0:2], byteorder='big'), int.from_bytes(segment[2:4], byteorder='big'), int.from_bytes(segment[4:6], byteorder='big'), int.from_bytes(segment[6:8], byteorder='big'), str(segment[8:]))
        else:
            segment_obj = { }
            print("Handling unknown protocol.")

        # Building packet
        packet_obj = Packet(packet_header_obj, segment_obj)

        # Building frame
        frame_obj = Frame(frame_header_obj, packet_obj)

        # Sending to our API
        print("Sending data to our api...")
        requests.post(PDUS_ENDPOINT, json.dumps(frame_obj, indent=4, cls=FrameEncoder))

    except Exception as exception:
        print("An error ocurred. See more details about it in the log file.")
        log_name = f"{datetime.now().strftime('%d%m%Y_%H%M%S')}.log"

        with open(log_name, 'w') as writing_stream:
            writing_stream.write(str(exception) )
