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

class AES_Payload(Packet):
      try:
           name = "AES_Payload"
 
           fields_desc = [
                          ByteField("b0",1),
                          ByteField("b1",2),
                          ByteField("b2",3),
                          ByteField("b3",4),                                                    
                          ByteField("b4",5),
                          ByteField("b5",6),                          
                          ByteField("b6",7),
                          ByteField("b7",8),
                          ByteField("b8",9),
                          ByteField("b9",10),
                          ByteField("b10",11),
                          ByteField("b11",12),
                          ByteField("b12",13),
                          ByteField("b13",14),
                          ByteField("b14",15),
                          ByteField("b15",16),                
                          ByteField("k0",2),
                          ByteField("k1",3),
                          ByteField("k2",4),
                          ByteField("k3",5),                                                    
                          ByteField("k4",6),
                          ByteField("k5",7),                          
                          ByteField("k6",8),
                          ByteField("k7",9),
                          ByteField("k8",10),
                          ByteField("k9",11),
                          ByteField("k10",12),
                          ByteField("k11",13),
                          ByteField("k12",14),
                          ByteField("k13",15),
                          ByteField("k14",16),
                          ByteField("k15",1),    
                          ByteField("s0",None),
                          ByteField("s1",None),
                          ByteField("s2",None),
                          ByteField("s3",None),                                                    
                          ByteField("s4",None),
                          ByteField("s5",None),                          
                          ByteField("s6",None),
                          ByteField("s7",None),
                          ByteField("s8",None),
                          ByteField("s9",None),
                          ByteField("s10",None),
                          ByteField("s11",None),
                          ByteField("s12",None),
                          ByteField("s13",None),
                          ByteField("s14",None),
                          ByteField("s15",None)]                               
                                                                                                                                                                            
           def mysummary(self):
               return self.sprintf("b0=%b0%, b1=%b1% b2=%b2% b3=%b3% b4=%b4% b5=%b5% b6=%b6% b7=%b7% b8=%b8%\
                                    b9=%b9%, b10=%b10% b11=%b11% b12=%b12% b13=%b13% b14=%b14% b15=%b15%\
                                    k0=%k0%, k1=%k1% k2=%k2% k3=%k3% k4=%k4% k5=%k5% k6=%k6% k7=%k7% k8=%k8%\
                                    k9=%k9%, k10=%k10% k11=%k11% k12=%k12% k13=%k13% k14=%k14% k15=%k15%\
                                    s0=%s0%, s1=%s1% s2=%s2% s3=%s3% s4=%s4% s5=%s5% s6=%s6% s7=%s7% s8=%s8%\
                                    s9=%s9%, s10=%s10% s11=%s11% s12=%s12% s13=%s13% s14=%s14% s15=%s15% ")

      except:
            print("No command-line arguments provided")
            
#bind_layers(TCP,Payload,encrypt=1)
bind_layers(TCP,AES_Payload)
def main():
    #arguments - hostip, data , encryption type , key index
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("Sending on interface %s to %s"%(iface,str(addr)))

    pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr)
    pkt = pkt / TCP(dport=1234,sport=random.randint(12345,54321))
    #pkt = pkt / Payload(encrypt=1)
    pkt = pkt / AES_Payload()
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
