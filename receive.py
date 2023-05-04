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

    #fields_desc = [ShortField("data",None),
    #               IntField("encrypt",None),
    #               IntField("type",None),
    #               IntField("index",None),
    #               IntField("skey",None),
    #               IntField("cypher",None),
    #               IntField("org_data",None)]
    fields_desc = [IntField("data",None),
                   IntField("encrypt",None),
                   IntField("cypher",None),
                   IntField("skey",None)]

    def mysummary(self):
        return self.sprintf("data=%data%, encrypt=%encrypt%, cypher=%cypher% skey=%skey%")


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
            
decrypted = []
cipher =[]
k =[]
def decryption():
    print("test")

def handle_pkt(pkt):
    #bind_layers(TCP,Payload,encrypt=1)
    bind_layers(TCP,AES_Payload)
    print("got a packet")
    pkt.show()
    #if (Raw in pkt):
       #aes = Ether()/IP()/TCP()/Raw(load=AES_Payload)
       #aes.show()
       #print("b0=",aes.b0)
    if (Raw in pkt):
       hexdump(pkt)
       last = pkt.getlayer(Raw)
       info = [last.load[i:i+1] for i in range(0,len(last.load),1)]
       print("Received Payload: ",info)
       b0 = int.from_bytes(info[0],"big")
       b1 = int.from_bytes(info[1],"big")
       b2 = int.from_bytes(info[2],"big")
       b3 = int.from_bytes(info[3],"big")
       b4 = int.from_bytes(info[4],"big")
       b5 = int.from_bytes(info[5],"big")
       b6 = int.from_bytes(info[6],"big")
       b7 = int.from_bytes(info[7],"big")
       b8 = int.from_bytes(info[8],"big")
       b9 = int.from_bytes(info[9],"big")
       b10 = int.from_bytes(info[10],"big")
       b11 = int.from_bytes(info[11],"big")
       b12 = int.from_bytes(info[12],"big")
       b13 = int.from_bytes(info[13],"big")
       b14 = int.from_bytes(info[14],"big")
       b15 = int.from_bytes(info[15],"big")
       print("b0=",b0,"b1=",b1,"b2=",b2,"b3=",b3,"b4=",b4,"b5=",b5,"b6=",b6,"b7=",b7,"b8=",b8)
       print("b9=",b9,"b10=",b10,"b11=",b11,"b12=",b12,"b13=",b13,"b14=",b14,"b15=",b15)

       k0 = int.from_bytes(info[16],"big")
       k1 = int.from_bytes(info[17],"big")
       k2 = int.from_bytes(info[18],"big")
       k3 = int.from_bytes(info[19],"big")
       k4 = int.from_bytes(info[20],"big")
       k5 = int.from_bytes(info[21],"big")
       k6 = int.from_bytes(info[22],"big")
       k7 = int.from_bytes(info[23],"big")
       k8 = int.from_bytes(info[24],"big")
       k9 = int.from_bytes(info[25],"big")
       k10 = int.from_bytes(info[26],"big")
       k11 = int.from_bytes(info[27],"big")
       k12 = int.from_bytes(info[28],"big")
       k13 = int.from_bytes(info[29],"big")
       k14 = int.from_bytes(info[30],"big")
       k15 = int.from_bytes(info[31],"big")
       print("k0=",k0,"k1=",k1,"k2=",k2,"k3=",k3,"k4=",k4,"k5=",k5,"k6=",k6,"k7=",k7,"k8=",k8)
       print("k9=",k9,"k10=",k10,"k11=",k11,"k12=",k12,"k13=",k13,"k14=",k14,"k15=",k15)


       s0 = int.from_bytes(info[32],"big")
       s1 = int.from_bytes(info[33],"big")
       s2 = int.from_bytes(info[34],"big")
       s3 = int.from_bytes(info[35],"big")
       s4 = int.from_bytes(info[36],"big")
       s5 = int.from_bytes(info[37],"big")
       s6 = int.from_bytes(info[38],"big")
       s7 = int.from_bytes(info[39],"big")
       s8 = int.from_bytes(info[40],"big")
       s9 = int.from_bytes(info[41],"big")
       s10 = int.from_bytes(info[42],"big")
       s11 = int.from_bytes(info[43],"big")
       s12 = int.from_bytes(info[44],"big")
       s13 = int.from_bytes(info[45],"big")
       s14 = int.from_bytes(info[46],"big")
       s15 = int.from_bytes(info[47],"big")
       print("s0=",s0,"s1=",s1,"s2=",s2,"s3=",s3,"s4=",s4,"s5=",s5,"s6=",s6,"s7=",s7,"s8=",s8)
       print("s9=",s9,"s10=",s10,"s11=",s11,"s12=",s12,"s13=",s13,"s14=",s14,"s15=",s15)
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
