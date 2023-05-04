from copy import copy

state=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
roundkey1=[2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1]
cipher = []
sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def print_hex(state):
    for i in range(len(state)):
        print(hex(state[i]))
        
def addRoundKey(state, roundKey):
    for i in range(len(state)):
        state[i] = state[i] ^ roundKey[i]
        
def subBytes(state):
    for i in range(len(state)):
        #print("state["+str(i)+"]=",hex(state[i]), "sbox[state[i]=",hex(sbox[state[i]]))
        state[i] = sbox[state[i]]

def ShiftRows(state):
    #print("State=",state)
    #Second row has a one-byte circular left shift.
    temp=[0,0,0,0]
    temp[0] = state[4]
    temp[1]= state[5]
    temp[2]= state[6]
    temp[3] = state[7]
    #print(temp)
    state[4] = temp[1]
    state[5]= temp[2]
    state[6]=temp[3]
    state[7]= temp[0]
    #print(state)

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
    #print(state)

    #Fourth row has a three-byte circular left shift.
    #31 91 CC 98  98 31 91 CC
    #123, 124, 192, 130  130,123,124,192
    temp=[0,0,0,0]
    temp[0] = state[12]
    temp[1]= state[13]
    temp[2]= state[14]
    temp[3] = state[15]
    #print(temp)
    state[12] = temp[3]
    state[13]= temp[0]
    state[14]=temp[1]
    state[15]= temp[2]
    #print("Shifted Rows = ", state)

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


def mixColumn(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],2) ^ galoisMult(temp[3],1) ^ \
                galoisMult(temp[2],1) ^ galoisMult(temp[1],3)
    column[1] = galoisMult(temp[1],2) ^ galoisMult(temp[0],1) ^ \
                galoisMult(temp[3],1) ^ galoisMult(temp[2],3)
    column[2] = galoisMult(temp[2],2) ^ galoisMult(temp[1],1) ^ \
                galoisMult(temp[0],1) ^ galoisMult(temp[3],3)
    column[3] = galoisMult(temp[3],2) ^ galoisMult(temp[2],1) ^ \
                galoisMult(temp[1],1) ^ galoisMult(temp[0],3)

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

def SplitAndMixColumn(state):    
    #print("State[]=",state)
    column1 = [0,0,0,0]
    column1[0] = state[0]
    column1[1] = state[4]
    column1[2] = state[8]
    column1[3] = state[12]
    #print("column 1 =",column1)
    mixColumn(column1)
    #print('Mixed: ',column1)
    #mixColumnInv(column1)
    #print('Inverse mixed', column1)

    column2 = [0,0,0,0]
    column2[0] = state[1]
    column2[1] = state[5]
    column2[2] = state[9]
    column2[3] = state[13]

    #print("column 2 =",column2)
    mixColumn(column2)
    #print('Mixed: ',column2)
    #mixColumnInv(column2)
    #print('Inverse mixed', column2)

    column3 = [0,0,0,0]
    column3[0] = state[2]
    column3[1] = state[6]
    column3[2] = state[10]
    column3[3] = state[14]

    #print("column 3 =",column3)
    mixColumn(column3)
    #print('Mixed: ',column3)
    #mixColumnInv(column3)
    #print('Inverse mixed', column3)

    column4 = [0,0,0,0]
    column4[0] = state[3]
    column4[1] = state[7]
    column4[2] = state[11]
    column4[3] = state[15]

    #print("column 4 =",column4)
    mixColumn(column4)
    #print('Mixed: ',column4)
    #mixColumnInv(column4)
    #print('Inverse mixed', column4)

    state = [column1[0],column2[0],column3[0],column4[0],
            column1[1],column2[1],column3[1],column4[1],
            column1[2],column2[2],column3[2],column4[2],
            column1[3],column2[3],column3[3],column4[3]]

    return state
    
    def encrypt_block(state):
    # AES is block Algorithm.
    # Encrypts a single block of 16 byte long plaintext.
    # Since we are not bale to acces payload in p4, aes128_t payload is 
    # is created to demonstrate functionality and this is considered as 
    # plain text here
    #
    print("plaintext=",state)
    print_hex(state)
    
    #First Operation
    addRoundKey(state,roundkey1)
    print("Add round key =",state)
    print_hex(state)


    # First round #
    subBytes(state)
    print("after subbytes state =", state)
    print_hex(state)
    ShiftRows(state) 
    print("after shift rows =",state)
    print_hex(state)
    SplitAndMixColumn(state)
    print("after Mix columns =",state)
    print_hex(state)
    addRoundKey(state,roundkey1)
    print("Add round key =",state)
    print_hex(state)

    
    #final operation
    subBytes(state)
    print("after subbytes state =",state)
    print_hex(state)
    ShiftRows(state)
    print("after shift rows =",state)
    print_hex(state)
    addRoundKey(state,roundkey1)
    print("Add round key =",state)
    print_hex(state)
    return state


cipher = encrypt_block(state)
print("cipher =",cipher)
print_hex(cipher)


