#!/usr/bin/env python

from scapy.all import *
import zlib
import struct

PA = 24
packets = rdpcap('./syc_security_system_traffic3.pcap')
client = '192.168.1.180'
list_n = []
list_m = []
list_id = []
data = []
for packet in packets:
    # TCP Flag PA 24 means carry data
    if packet[TCP].flags == PA or packet[TCP].flags == PA + 1:
        src = packet[IP].src
        raw_data = packet[TCP].load
        head = raw_data.strip()[:7]
        if head == "We have":
            n, e = raw_data.strip().replace("We have got N is ",
                                            "").split('\ne is ')
            data.append(n.strip())
        if head == "encrypt":
            m = raw_data.replace('encrypted messages is 0x', '').strip()
            data.append(str(int(m, 16)))

with open('./data.txt', 'w') as f:
    for i in range(0, len(data), 2):
        tmp = ','.join(s for s in data[i:i + 2])
        f.write(tmp + '\n')
