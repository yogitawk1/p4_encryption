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

bind_layers(TCP,Payload,encrypt=1)



def handle_pkt(pkt):
    if ( Raw in pkt):
        print("got a packet")
        pkt.show()
        #last = pkt.getlayer(Raw)
        #print(last.load(Payload(encrypt=1)))
        hexdump(pkt)
        sys.stdout.flush()


def main():
    #ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
