#!/usr/bin/env python3
import argparse
import random
import socket
import sys
import struct

from scapy.all import IP, TCP, Ether, UDP
from scapy.all import get_if_hwaddr, get_if_list, bind_layers, send, sendp, hexdump
from scapy.all import Packet, IntField
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from scapy.sendrecv import sr

import readline
TYPE_ENCRYPT = 0x1212

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class Payload(Packet):
      try:
           name = "Payload"
           #fields_desc = [IntField("data",int(sys.argv[2])),
           #               IntField("type",int(sys.argv[3])),
           #               IntField("index",int(sys.argv[4])),
           #               IntField("skey",int(sys.argv[5])),
           #               IntField("cypher",None),
           #               IntField("org_data",None)]
           fields_desc = [IntField("data",int(sys.argv[2])),
                          IntField("encrypt",1),
                          IntField("cypher",None),
                          IntField("skey",int(sys.argv[3]))]
           def mysummary(self):
               return self.sprintf("data=%data%, skey=%skey")

      except:
            print("No command-line arguments provided")

bind_layers(TCP,Payload,encrypt=1)

def main():
    if len(sys.argv) < 3 :
        print("Need to pass more arguments")
        exit(1)
    #arguments - hostip, data , encryption type , key index
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("Sending on interface %s to %s"%(iface,str(addr)))

    pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr)
    pkt = pkt / TCP(dport=1234,sport=random.randint(12345,54321))
    pkt = pkt / Payload(encrypt=1)
    pkt.show()
    #pkt.show2()
    #print(pkt.summary())
    #data=pkt[TCP].payload
    #print("pkt data =",data)
    hexdump(pkt)
    print ("len(pkt) =", len(pkt))
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
