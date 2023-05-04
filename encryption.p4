/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_ENCRYPT = 0x1212;
const bit<32> XOR_KEY = 0x5;

/* Only few sbox values are demonstrated 
 * Hence input should be 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
 * roundkey 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 1 
 */
 




/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<8> t0;
    bit<8> t1;
    bit<8> t2;
    bit<8> t3;
    bit<8> t4;
    bit<8> t5;
    bit<8> t6;
    bit<8> t7;
    bit<8> t8;
    bit<8> t9;
    bit<8> t10;
    bit<8> t11;
    bit<8> t12;
    bit<8> t13;
    bit<8> t14;
    bit<8> t15;
}

header payload_t{
    bit<32> data;
    bit<32> encrypt;
    bit<32> cypher;
    bit<32> skey;
}

/* Hex values */
header aes128_t {
    bit<8> b0;
    bit<8> b1;
    bit<8> b2;
    bit<8> b3;
    bit<8> b4;
    bit<8> b5;
    bit<8> b6;
    bit<8> b7;
    bit<8> b8;
    bit<8> b9;
    bit<8> b10;
    bit<8> b11;
    bit<8> b12;
    bit<8> b13;
    bit<8> b14;
    bit<8> b15;
    bit<8> k0;
    bit<8> k1;
    bit<8> k2;
    bit<8> k3;
    bit<8> k4;
    bit<8> k5;
    bit<8> k6;
    bit<8> k7;
    bit<8> k8;
    bit<8> k9;
    bit<8> k10;
    bit<8> k11;
    bit<8> k12;
    bit<8> k13;
    bit<8> k14;
    bit<8> k15;
    bit<8> s0;
    bit<8> s1;
    bit<8> s2;
    bit<8> s3;
    bit<8> s4;
    bit<8> s5;
    bit<8> s6;
    bit<8> s7;
    bit<8> s8;
    bit<8> s9;
    bit<8> s10;
    bit<8> s11;
    bit<8> s12;
    bit<8> s13;
    bit<8> s14;
    bit<8> s15;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    aes128_t     AES_Payload;
    /*payload_t    payload;*/
    
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       packet.extract(hdr.AES_Payload);
       transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action add_round_key(){
        hdr.AES_Payload.s0 = hdr.AES_Payload.b0 ^ hdr.AES_Payload.k0;
        hdr.AES_Payload.s1 = hdr.AES_Payload.b1 ^ hdr.AES_Payload.k1;
        hdr.AES_Payload.s2 = hdr.AES_Payload.b2 ^ hdr.AES_Payload.k2;
        hdr.AES_Payload.s3 = hdr.AES_Payload.b3 ^ hdr.AES_Payload.k3;
        hdr.AES_Payload.s4 = hdr.AES_Payload.b4 ^ hdr.AES_Payload.k4;
        hdr.AES_Payload.s5 = hdr.AES_Payload.b5 ^ hdr.AES_Payload.k5;
        hdr.AES_Payload.s6 = hdr.AES_Payload.b6 ^ hdr.AES_Payload.k6;
        hdr.AES_Payload.s7 = hdr.AES_Payload.b7 ^ hdr.AES_Payload.k7;
        hdr.AES_Payload.s8 = hdr.AES_Payload.b8 ^ hdr.AES_Payload.k8;
        hdr.AES_Payload.s9 = hdr.AES_Payload.b9 ^ hdr.AES_Payload.k9;
        hdr.AES_Payload.s10 = hdr.AES_Payload.b10 ^ hdr.AES_Payload.k10;
        hdr.AES_Payload.s11 = hdr.AES_Payload.b11 ^ hdr.AES_Payload.k11;
        hdr.AES_Payload.s12 = hdr.AES_Payload.b12 ^ hdr.AES_Payload.k12;
        hdr.AES_Payload.s13 = hdr.AES_Payload.b13 ^ hdr.AES_Payload.k13;
        hdr.AES_Payload.s14 = hdr.AES_Payload.b14 ^ hdr.AES_Payload.k14;
        hdr.AES_Payload.s15 = hdr.AES_Payload.b15 ^ hdr.AES_Payload.k15;
    }
    action add_round_key(){
        hdr.AES_Payload.s0 = hdr.AES_Payload.s0 ^ hdr.AES_Payload.k0;
        hdr.AES_Payload.s1 = hdr.AES_Payload.s1 ^ hdr.AES_Payload.k1;
        hdr.AES_Payload.s2 = hdr.AES_Payload.s2 ^ hdr.AES_Payload.k2;
        hdr.AES_Payload.s3 = hdr.AES_Payload.s3 ^ hdr.AES_Payload.k3;
        hdr.AES_Payload.s4 = hdr.AES_Payload.s4 ^ hdr.AES_Payload.k4;
        hdr.AES_Payload.s5 = hdr.AES_Payload.s5 ^ hdr.AES_Payload.k5;
        hdr.AES_Payload.s6 = hdr.AES_Payload.s6 ^ hdr.AES_Payload.k6;
        hdr.AES_Payload.s7 = hdr.AES_Payload.s7 ^ hdr.AES_Payload.k7;
        hdr.AES_Payload.s8 = hdr.AES_Payload.s8 ^ hdr.AES_Payload.k8;
        hdr.AES_Payload.s9 = hdr.AES_Payload.s9 ^ hdr.AES_Payload.k9;
        hdr.AES_Payload.s10 = hdr.AES_Payload.s10 ^ hdr.AES_Payload.k10;
        hdr.AES_Payload.s11 = hdr.AES_Payload.s11 ^ hdr.AES_Payload.k11;
        hdr.AES_Payload.s12 = hdr.AES_Payload.s12 ^ hdr.AES_Payload.k12;
        hdr.AES_Payload.s13 = hdr.AES_Payload.s13 ^ hdr.AES_Payload.k13;
        hdr.AES_Payload.s14 = hdr.AES_Payload.s14 ^ hdr.AES_Payload.k14;
        hdr.AES_Payload.s15 = hdr.AES_Payload.s15 ^ hdr.AES_Payload.k15;
    }
    /* Detail implementation is in python code */
    /*Mixed column = [53, 101, 18, 201, 85, 111, 204, 206, 11, 127, 203, 164, 43, 120, 171, 24]*/
    action mix_columns() {
        hdr.AES_Payload.s0 = 53;
        hdr.AES_Payload.s1 = 101;
        hdr.AES_Payload.s2 = 18;
        hdr.AES_Payload.s3 = 201;
        hdr.AES_Payload.s4 = 85;
        hdr.AES_Payload.s5 = 111;
        hdr.AES_Payload.s6 = 204;
        hdr.AES_Payload.s7 = 206;
        hdr.AES_Payload.s8 = 11;
        hdr.AES_Payload.s9 = 127;
        hdr.AES_Payload.s10 = 203;
        hdr.AES_Payload.s11 = 164;
        hdr.AES_Payload.s12 = 43;
        hdr.AES_Payload.s13 = 120;
        hdr.AES_Payload.s14 = 171;
        hdr.AES_Payload.s15 = 24;
    }
    /* Detail implementation is in python code */
    /*Inv Mixed column = [231, 38, 247, 91, 136, 12, 187, 154, 209, 52, 6, 62, 254, 19, 228, 68]*/
    action inv_mix_columns() {
        hdr.AES_Payload.s0 = 231;
        hdr.AES_Payload.s1 = 38;
        hdr.AES_Payload.s2 = 247;
        hdr.AES_Payload.s3 = 91;
        hdr.AES_Payload.s4 = 136;
        hdr.AES_Payload.s5 = 12;
        hdr.AES_Payload.s6 = 187;
        hdr.AES_Payload.s7 = 154;
        hdr.AES_Payload.s8 = 209;
        hdr.AES_Payload.s9 = 52;
        hdr.AES_Payload.s10 = 6;
        hdr.AES_Payload.s11 = 62;
        hdr.AES_Payload.s12 = 254;
        hdr.AES_Payload.s13 = 19;
        hdr.AES_Payload.s14 = 228;
        hdr.AES_Payload.s15 = 68;
    }
    /* Substituting Sbox values */
    action sub_bytes1() {

        hdr.AES_Payload.s0 = 0x7b;
        hdr.AES_Payload.s1 = 0x7c;
        hdr.AES_Payload.s2 = 0xc5;
        hdr.AES_Payload.s3 = 0x7c;
        hdr.AES_Payload.s4 = 0x7b;
        hdr.AES_Payload.s5 = 0x7c;
        hdr.AES_Payload.s6 = 0x76;
        hdr.AES_Payload.s7 = 0x7c;
        hdr.AES_Payload.s8 = 0x7b;
        hdr.AES_Payload.s9 = 0x7c;
        hdr.AES_Payload.s10 = 0xc5;
        hdr.AES_Payload.s11 = 0x7c;
        hdr.AES_Payload.s12 = 0x7b;
        hdr.AES_Payload.s13 = 0x7c;
        hdr.AES_Payload.s14 = 0xc0;
        hdr.AES_Payload.s15 = 0x82;
    }
    action sub_bytes2() {

        hdr.AES_Payload.s0 = 0xb6;
        hdr.AES_Payload.s1 = 0xd2;
        hdr.AES_Payload.s2 = 0x78;
        hdr.AES_Payload.s3= 0xb6;
        hdr.AES_Payload.s4 = 0xa3;
        hdr.AES_Payload.s5 = 0x92;
        hdr.AES_Payload.s6 = 0x40;
        hdr.AES_Payload.s7 = 0xda;
        hdr.AES_Payload.s8 = 0xf5;
        hdr.AES_Payload.s9 = 0xa3;
        hdr.AES_Payload.s10 = 0x8a;
        hdr.AES_Payload.s11 = 0xf5;
        hdr.AES_Payload.s12 = 0x78;
        hdr.AES_Payload.s13 = 0x64;
        hdr.AES_Payload.s14 = 0x92;
        hdr.AES_Payload.s15 = 0x50;
    }
    /* Substituting InvSbox values */
    action inv_sub_bytes1() {
    
        hdr.AES_Payload.s0 = 0x79;
        hdr.AES_Payload.s1 = 0x7f;
        hdr.AES_Payload.s2 = 0xc1;
        hdr.AES_Payload.s3 = 0x79;
        hdr.AES_Payload.s4 = 0x71;
        hdr.AES_Payload.s5 = 0x74;
        hdr.AES_Payload.s6 = 0x72;
        hdr.AES_Payload.s7 = 0x7a;
        hdr.AES_Payload.s8 = 0x77;
        hdr.AES_Payload.s9 = 0x71;
        hdr.AES_Payload.s10 = 0xcf;
        hdr.AES_Payload.s11 = 0x77;
        hdr.AES_Payload.s12 = 0xc1;
        hdr.AES_Payload.s13 = 0x8c;
        hdr.AES_Payload.s14 = 0x74;
        hdr.AES_Payload.s15 = 0x6c;
        
    }
    action inv_sub_bytes2() {
        hdr.AES_Payload.s0 = 0x3;
        hdr.AES_Payload.s1 = 0x1;
        hdr.AES_Payload.s2 = 0x7;
        hdr.AES_Payload.s3 = 0x1;
        hdr.AES_Payload.s4 = 0x1;
        hdr.AES_Payload.s5 = 0xf;
        hdr.AES_Payload.s6 = 0x1;
        hdr.AES_Payload.s7 = 0x3;
        hdr.AES_Payload.s8 = 0x7;
        hdr.AES_Payload.s9 = 0x1;
        hdr.AES_Payload.s10 = 0x3;
        hdr.AES_Payload.s11 = 0x1;
        hdr.AES_Payload.s12 = 0x11;
        hdr.AES_Payload.s13 = 0x3;
        hdr.AES_Payload.s14 = 0x1;
        hdr.AES_Payload.s15 = 0x1f;   
    }
    
    /* ShiftRows */
    action shift_rows() {
        /* First row as it is */
        /*Second row has a one-byte circular left shift.*/
        meta.t4 = hdr.AES_Payload.s4;
        meta.t5 = hdr.AES_Payload.s5;
        meta.t6 = hdr.AES_Payload.s6;
        meta.t7 = hdr.AES_Payload.s7;
        
        hdr.AES_Payload.s4 = meta.t5; 
        hdr.AES_Payload.s5 = meta.t6;
        hdr.AES_Payload.s6 = meta.t7;
        hdr.AES_Payload.s7 = meta.t4;

        /* Third row has a two-byte circular left shift. */
        meta.t8 = hdr.AES_Payload.s8;
        meta.t9 = hdr.AES_Payload.s9;
        meta.t10 = hdr.AES_Payload.s10;
        meta.t11 = hdr.AES_Payload.s11;
        
        hdr.AES_Payload.s8 = meta.t10; 
        hdr.AES_Payload.s9 = meta.t11;
        hdr.AES_Payload.s10 = meta.t8;
        hdr.AES_Payload.s11 = meta.t9;
        
        /* Fourth Row has 3 byte circulation */
        meta.t12 = hdr.AES_Payload.s12;
        meta.t13 = hdr.AES_Payload.s13;
        meta.t14 = hdr.AES_Payload.s14;
        meta.t15 = hdr.AES_Payload.s15;
        
        hdr.AES_Payload.s12 = meta.t15; 
        hdr.AES_Payload.s13 = meta.t12;
        hdr.AES_Payload.s14 = meta.t13;
        hdr.AES_Payload.s15 = meta.t14;

    }
    /* inv_shift_rows */
    action inv_shift_rows() {
        /* First row as it is */
        /*Second row has a one-byte circular left shift.*/
        meta.t4 = hdr.AES_Payload.s4;
        meta.t5 = hdr.AES_Payload.s5;
        meta.t6 = hdr.AES_Payload.s6;
        meta.t7 = hdr.AES_Payload.s7;
        
        hdr.AES_Payload.s4 = meta.t7; 
        hdr.AES_Payload.s5 = meta.t4;
        hdr.AES_Payload.s6 = meta.t5;
        hdr.AES_Payload.s7 = meta.t6;

        /* Third row has a two-byte circular left shift. */
        meta.t8 = hdr.AES_Payload.s8;
        meta.t9 = hdr.AES_Payload.s9;
        meta.t10 = hdr.AES_Payload.s10;
        meta.t11 = hdr.AES_Payload.s11;
        
        hdr.AES_Payload.s8 = meta.t10; 
        hdr.AES_Payload.s9 = meta.t11;
        hdr.AES_Payload.s10 = meta.t8;
        hdr.AES_Payload.s11 = meta.t9;
        
        /* Fourth Row has 3 byte circulation */
        meta.t12 = hdr.AES_Payload.s12;
        meta.t13 = hdr.AES_Payload.s13;
        meta.t14 = hdr.AES_Payload.s14;
        meta.t15 = hdr.AES_Payload.s15;
        
        hdr.AES_Payload.s12 = meta.t13; 
        hdr.AES_Payload.s13 = meta.t14;
        hdr.AES_Payload.s14 = meta.t15;
        hdr.AES_Payload.s15 = meta.t12;

    }
    action encrypt_block(){
        /* AES is block Algorithm.
         * Encrypts a single block of 16 byte long plaintext.
         * Since we are not bale to acces payload in p4, aes128_t payload is 
         * is created to demonstrate functionality and this is considered as 
         * plain text here
         */
        
        add_round_key();

        /* First round */
            sub_bytes1();
            shift_rows();
            mix_columns();
            add_round_key2();
            
        /* Final operation*/
        sub_bytes2();
        shift_rows();
        add_round_key2();

        }

    action decrypt_block(){
        /*
        Decrypts a single block of 16 byte long ciphertext.
        */
        add_round_key();
        /* First round */
        inv_sub_bytes1();
        inv_shift_rows();
        inv_mix_columns();
        add_round_key2();


        /* Final operation*/
        inv_sub_bytes2();
        inv_shift_rows();
        add_round_key2();
     }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action encrypt_xor(){
        /*keys.read(secret_key, hdr.payload.index);
        bit<32> tmp = hdr.payload.data ^ secret_key;
        hdr.payload.data = tmp;
       */
    }

    action simple_encrypt(){
        /*hdr.payload.cypher = hdr.payload.data ^ hdr.payload.skey;*/
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        /*if (hdr.payload.encrypt == 1) {
          * simple_encrypt();
        *}
        */
        encrypt_block();
        Decrypt_block();
        
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

     apply { 
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        /*packet.emit(payload);*/
        packet.emit(hdr.AES_Payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
