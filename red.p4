/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<16> TYPE_IPV4 = 0x800;
const bit<19> ECN_THRESHOLD = 10;
const bit<19> Wq = 10;
const bit<19> MinTh = 230000;
const bit<19> MaxTh = 375000;

#define REGISTER_LENGTH 30000


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

/*
 * TODO: split tos to two fields 6 bit diffserv and 2 bit ecn
 */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    diffserv;
    bit<2>    ecn;
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

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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



    action drop() {
        mark_to_drop(standard_metadata);
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
        }
        size = 1024;
        default_action = drop;
    }

    apply {
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

     action drop() {
         mark_to_drop(standard_metadata);
     }

    register<bit<19>>(REGISTER_LENGTH) avg_r;
    register<bit<11>>(1) dp_r;

    apply {

        bit<32>reg_pos_zero = 0;
        bit<19> queue_size_now = standard_metadata.enq_qdepth;
        bit<19> Old_AVG;
        bit<19> position_to_read = 0;
        avg_r.read(position_to_read,reg_pos_zero);
        bit<32> readOn = (bit<32>) position_to_read;
        avg_r.read(Old_AVG,readOn);
        /*bit<19> new_AVG = (10-Wq)*Old_AVG + Wq * queue_size_now;*/ /* algoritmo do red */
        bit<19> new_AVG = (Old_AVG*98)+(queue_size_now*2); /*algoritmo do wred by cisco */
        bit<19> position_to_write = position_to_read + 1;
        bit<32> writeOn = (bit<32>) position_to_write;
        avg_r.write(writeOn,new_AVG);
        /*avg_r.write(writeOn,1);*/ /* para verificar que nao esta pulando casas*/
        avg_r.write(reg_pos_zero,position_to_write);

        if (new_AVG > MinTh && new_AVG < MaxTh) {
            hdr.ipv4.ecn = 3;
            bit<32> pos_zero = 0;
            bit<11> drop_prob_read = 0;
            dp_r.read(drop_prob_read,pos_zero);
            if (drop_prob_read == 0){
                drop_prob_read = 1;
            };
            bit<11> drop_prob_write = drop_prob_read * 2;
            dp_r.write(pos_zero,drop_prob_write);
            bit<11> rand_val;
            random<bit<11>>(rand_val, 0, 2047);
            if (drop_prob_write > rand_val){
                drop();
            }


        }

        if (new_AVG > MaxTh) {
            drop();

        }

/*
        if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2) {
            if (standard_metadata.enq_qdepth >= ECN_THRESHOLD){
                hdr.ipv4.ecn = 3;
            }
        }
*/

        /*
         * TODO:
         * - if ecn is 1 or 2
         *   - compare standard_metadata.enq_qdepth with threshold
         *     and set hdr.ipv4.ecn to 3 if larger
         */
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* TODO: replace tos with diffserve and ecn */
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.ecn,
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
