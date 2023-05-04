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
from copy import copy


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
info=[]
roundkey=[]
sboxInv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

def InvsubBytes(state):
    for i in range(len(state)):
        #print("state[i]=",hex(state[i]), "sboxInv[state[i]=",hex(sboxInv[state[i]]))
        state[i] = sboxInv[state[i]]
        
def addRoundKey(state, roundkey):
    for i in range(len(state)):
        state[i] = state[i] ^ roundkey[i]
        
def InvShiftRows(state):
    #print("Shifted State=",state)
    #Second row has a one-byte circular left shift.
    #124, 118, 124, 123 -- > 123, 124, 118, 124
    temp=[0,0,0,0]
    temp[0] = state[4]
    temp[1]= state[5]
    temp[2]= state[6]
    temp[3] = state[7]
    #print(temp)
    state[4] = temp[3]
    state[5]= temp[0]
    state[6]=temp[1]
    state[7]= temp[2]
    #print("second row inv = ",state)

    #Third row has a two-byte circular left shift.
    #5A 73 D5 52->D5 52 5A 73
    temp=[0,0,0,0]
    temp[0] = state[8]
    temp[1]= state[9]
    temp[2]= state[10]
    temp[3] = state[11]
    #print(temp)
    state[8] = temp[2]
    state[9]= temp[3]
    state[10]=temp[0]
    state[11]= temp[1]
   # print(state)

    #Fourth row has a three-byte circular left shift.
    #31 91 CC 98  98 31 91 CC
    #
    temp=[0,0,0,0]
    temp[0] = state[12]
    temp[1]= state[13]
    temp[2]= state[14]
    temp[3] = state[15]
 #   print(temp)
    state[12] = temp[1]
    state[13]= temp[2]
    state[14]=temp[3]
    state[15]= temp[0]   
    
#last operation is mixing columns
from copy import copy


def galoisMult(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256




def mixColumnInv(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],14) ^ galoisMult(temp[3],9) ^ \
                galoisMult(temp[2],13) ^ galoisMult(temp[1],11)
    column[1] = galoisMult(temp[1],14) ^ galoisMult(temp[0],9) ^ \
                galoisMult(temp[3],13) ^ galoisMult(temp[2],11)
    column[2] = galoisMult(temp[2],14) ^ galoisMult(temp[1],9) ^ \
                galoisMult(temp[0],13) ^ galoisMult(temp[3],11)
    column[3] = galoisMult(temp[3],14) ^ galoisMult(temp[2],9) ^ \
    galoisMult(temp[1],13) ^ galoisMult(temp[0],11)



def InvSplitAndMixColumn(state):    
    #print("State[]=",state)
    column1 = [0,0,0,0]
    column1[0] = state[0]
    column1[1] = state[4]
    column1[2] = state[8]
    column1[3] = state[12]
    #print("column 1 =",column1)
    #mixColumn(column1)
    #print('Mixed: ',column1)
    mixColumnInv(column1)
    #print('Inverse mixed', column1)

    column2 = [0,0,0,0]
    column2[0] = state[1]
    column2[1] = state[5]
    column2[2] = state[9]
    column2[3] = state[13]

    #print("column 2 =",column2)
    #mixColumn(column2)
    #print('Mixed: ',column2)
    mixColumnInv(column2)
    #print('Inverse mixed', column2)

    column3 = [0,0,0,0]
    column3[0] = state[2]
    column3[1] = state[6]
    column3[2] = state[10]
    column3[3] = state[14]

    #print("column 3 =",column3)
    #mixColumn(column3)
    #print('Mixed: ',column3)
    mixColumnInv(column3)
    #print('Inverse mixed', column3)

    column4 = [0,0,0,0]
    column4[0] = state[3]
    column4[1] = state[7]
    column4[2] = state[11]
    column4[3] = state[15]

    #print("column 4 =",column4)
    #mixColumn(column4)
    #print('Mixed: ',column4)
    mixColumnInv(column4)
    #print('Inverse mixed', column4)

    state = [column1[0],column2[0],column3[0],column4[0],
             column1[1],column2[1],column3[1],column4[1],
             column1[2],column2[2],column3[2],column4[2],
             column1[3],column2[3],column3[3],column4[3]]

         
def decrypt_block():
    print("cipher =", cipher)
    print("roundkey=",roundkey)
    addRoundKey(cipher,roundkey)
    print("After addRoundKey cipher =", cipher)
    
    #First Round 
    InvsubBytes(cipher)
    print("After InvsubBytes =", cipher)
    InvShiftRows(cipher)
    print("After InvShiftRows =",cipher)
    InvSplitAndMixColumn(cipher)
    addRoundKey(cipher,roundkey)

    #final operation
    InvsubBytes(cipher)
    print("after INV subbytes state =", cipher)
    InvShiftRows(cipher)
    addRoundKey(cipher,roundkey)
    print("Decrypted message =",cipher)

def handle_pkt(pkt):
    #bind_layers(TCP,Payload,encrypt=1)
    bind_layers(TCP,AES_Payload)
    print("got a packet")
    pkt.show()
    #if (Raw in pkt):
       #aes = Ether()/IP()/TCP()/Raw(load=AES_Payload)
       #aes.show()
       #print("b0=",aes.b0)
    try:
      if (pkt[IP].version == 4 ):
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
          roundkey.append(k0)
          roundkey.append(k1)
          roundkey.append(k2)
          roundkey.append(k3)
          roundkey.append(k4)
          roundkey.append(k5)
          roundkey.append(k6)
          roundkey.append(k7)
          roundkey.append(k8)
          roundkey.append(k9)
          roundkey.append(k10)
          roundkey.append(k11)
          roundkey.append(k12)
          roundkey.append(k13)
          roundkey.append(k14)
          roundkey.append(k15)


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
          cipher.append(s0)
          cipher.append(s1)
          cipher.append(s2)
          cipher.append(s3)
          cipher.append(s4)
          cipher.append(s5)
          cipher.append(s6)
          cipher.append(s7)
          cipher.append(s8)
          cipher.append(s9)
          cipher.append(s10)
          cipher.append(s11)
          cipher.append(s12)
          cipher.append(s13)
          cipher.append(s14)
          cipher.append(s15)
    except:
        print("IPv6 packet")
    sys.stdout.flush()
    print("Decrypting cipher")  
    decrypt_block()

def main():
    #ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
