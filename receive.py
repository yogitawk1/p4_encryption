#!/usr/bin/env python
import argparse
import os
import sys
import struct
import random

from scapy.all import get_if_hwaddr,get_if_list,bind_layers, sendp,sniff, hexdump
from scapy.all import Packet, IPOption
from scapy.all import IP, TCP, UDP
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class Payload(Packet):
    name ="Payload"
    fields_desc = [ShortField("data",None),
                   IntField("encrypt",None),
                   IntField("type",None),
                   IntField("index",None),
                   IntField("skey",None),
                   IntField("cypher",None),
                   IntField("org_data",None)]

    def mysummary(self):
        return self.sprintf("data=%data%, encrypt=%encrypt%, type=%type%,index=%index%, skey=%skey%, cypher=%cypher%, org_data=%org_data%")




def handle_pkt(pkt):
    bind_layers(TCP,Payload,encrypt=1)
    if ( Raw in pkt):
        print("got a packet")
        pkt.show()
        last = pkt.getlayer(Raw)
        info = [last.load[i:i+4] for i in range(0,len(last.load),4)]
        print("Payload = ")
        int_data = int.from_bytes(info[0],"big")
        Encrypt = int.from_bytes(info[1],"big")
        Type = int.from_bytes(info[2],"big")
        Index = int.from_bytes(info[3],"big")
        skey = int.from_bytes(info[4],"big")
        cypher = int.from_bytes(info[5],"big")
        org_data = int.from_bytes(info[6],"big")
        print("Data =", int_data)
        print("Encrypt =",Encrypt) 
        print("Type =", Type) 
        print("Index =", Index) 
        print("skey =", skey) 
        print("cypher =",cypher) 
        print("org_data =", org_data)
        hexdump(pkt)
        sys.stdout.flush()

        print("Decrypting ...")
        decrypted_data = cypher ^ skey
        print(decrypted_data)

def main():
    #ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
