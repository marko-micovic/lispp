/*
 *   LISPP - Lightweight stateless network layer privacy protection system
 *   Copyright (C) 2023 Marko Micovic, Uros Radenkovic, Pavle Vuletic, 
 *                      University of Belgrade, School of Electrical Engineering
 *
 *   This file is part of LISPP.
 *
 *   LISPP is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   LISPP is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with LISPP. If not, see <https://www.gnu.org/licenses/>.
 */

// Standard headers
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL         0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE  1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE   2
#define PKT_INSTANCE_TYPE_COALESCED      3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION    5
#define PKT_INSTANCE_TYPE_RESUBMIT       6

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
#include "config.p4.h"

header Ethernet_h {
    bit<48>    dstAddr;
    bit<48>    srcAddr;
    bit<16>    etherType;
}

header Vlan_h {
    bit<3>     pcp;
    bit<1>     cfi;
    bit<12>    vid;
    bit<16>    etherType;
}

header Ipv4_h {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    totalLen;
    bit<16>    identification;
    bit<3>     flags;
    bit<13>    fragOffset;
    bit<8>     ttl;
    bit<8>     protocol;
    bit<16>    hdrChecksum;
    bit<32>    srcAddr;
    bit<32>    dstAddr;
}

header Ipv6_h {
    bit<4>     version;
    bit<8>     trafficClass;
    bit<20>    flowLabel;
    bit<16>    payloadLen;
    bit<8>     protocol; // nextHeader
    bit<8>     hopLimit;
    bit<128>   srcAddr;
    bit<128>   dstAddr;
}

header Tcp_h {
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<32>    seqNo;
    bit<32>    ackNo;
    bit<4>     dataOffset;
    bit<4>     res;
    bit<8>     flags;
    bit<16>    window;
    bit<16>    checksum;
    bit<16>    urgentPtr;
}

header Udp_h {
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<16>    len;
    bit<16>    checksum;
}

struct MyHeaders_t {
    Ethernet_h ethernet;
    Vlan_h     vlan;
    Ipv4_h     ipv4;
    Ipv6_h     ipv6;
    Tcp_h      tcp;
    Udp_h      udp;
}

#define W_8     8
#define W_16   16
#define W_32   32
#define W_64   64
#define W_128 128

struct Help_t {
    bit<W_32>  ff3_i00;
    bit<W_32>  ff3_i01;
    bit<W_32>  ff3_i02;
    bit<W_32>  ff3_i03;
    bit<W_32>  ff3_o00;
    bit<W_32>  ff3_o01;
    bit<W_32>  ff3_o02;
    bit<W_32>  ff3_o03;
    bit<16>  transportLayerLenIpv4;
    bit<32>  transportLayerLenIpv6;
}

struct MyMetadata_t {
    Help_t     help;
}

const bit<16> ETHERNET_TYPE_VLAN = 0x8100;
const bit<16> ETHERNET_TYPE_IPV4 = 0x0800;
const bit<16> ETHERNET_TYPE_IPV6 = 0x86DD;

const bit<8>  IP_PROTOCOL_ICMP = 0x01;
const bit<8>  IP_PROTOCOL_TCP  = 0x06;
const bit<8>  IP_PROTOCOL_UDP  = 0x11;

parser MyParser(
    packet_in                 packet,
    out   MyHeaders_t         hdrs,
    inout MyMetadata_t        meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdrs.ethernet);
        transition select(hdrs.ethernet.etherType) {
            ETHERNET_TYPE_VLAN: parse_vlan;
            ETHERNET_TYPE_IPV4: parse_ipv4;
            ETHERNET_TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdrs.vlan);
        transition select(hdrs.vlan.etherType) {
            ETHERNET_TYPE_IPV4: parse_ipv4;
            ETHERNET_TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdrs.ipv4);
        transition select(hdrs.ipv4.protocol) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdrs.ipv6);
        transition select(hdrs.ipv6.protocol) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdrs.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdrs.udp);
        transition accept;
    }
}

control MyVerifyChecksum(
    inout MyHeaders_t  hdrs,
    inout MyMetadata_t meta)
{
    apply {  }
}

// *****************************************************************************
// HEADERS HELPERS
// *****************************************************************************

#define ETHERNET_TYPE_IP(version) ETHERNET_TYPE_IP_EXPANDED(version)
#define ETHERNET_TYPE_IP_EXPANDED(version) ETHERNET_TYPE_IPV##version

#if IP_VERSION == 4 && TRANSPORT_PROTOCOL == 0x11
#define HDRS_IP hdrs.ipv4
#define HDRS_TRANSPORT hdrs.udp
#elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x11
#define HDRS_IP hdrs.ipv6
#define HDRS_TRANSPORT hdrs.udp
#elif IP_VERSION == 4 && TRANSPORT_PROTOCOL == 0x06
#define HDRS_IP hdrs.ipv4
#define HDRS_TRANSPORT hdrs.tcp
#elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x06
#define HDRS_IP hdrs.ipv6
#define HDRS_TRANSPORT hdrs.tcp
#endif

// *****************************************************************************
// FF3-1 HELPERS
// *****************************************************************************

extern void ff3_encrypt();
extern void ff3_decrypt();

#define FF3_GET_INPUT(ipAddress, portNumber) ( ipAddress[(W_N - 16 - 1):0] ++ portNumber )

#define FF3_INVOKE(ff3_operation) \
    meta.help.ff3_i00 = ff3_input[127:96]; \
    meta.help.ff3_i01 = ff3_input[ 95:64]; \
    meta.help.ff3_i02 = ff3_input[ 63:32]; \
    meta.help.ff3_i03 = ff3_input[ 31: 0]; \
    ff3_operation(); \
    ff3_output[127:96] = meta.help.ff3_o00; \
    ff3_output[ 95:64] = meta.help.ff3_o01; \
    ff3_output[ 63:32] = meta.help.ff3_o02; \
    ff3_output[ 31: 0] = meta.help.ff3_o03;

#define FF3_HANDLE_PACKET() \
    if (hdrs.vlan.etherType == ETHERNET_TYPE_IP(IP_VERSION) && HDRS_IP.protocol == TRANSPORT_PROTOCOL) { \
        bit<W_128> ff3_input = 0; \
        bit<W_128> ff3_output = 0; \
        if (standard_metadata.ingress_port == 1) { \
            /* packet arrived from port 1 (iperf client) */ \
            ff3_input[(W_N - 1):0] = FF3_GET_INPUT(HDRS_IP.srcAddr, HDRS_TRANSPORT.srcPort); \
            FF3_INVOKE(ff3_encrypt); \
            HDRS_IP.srcAddr[(W_N - 16 - 1):0] = ff3_output[(W_N - 1):16]; \
            HDRS_TRANSPORT.srcPort = ff3_output[15:0]; \
        } else if (standard_metadata.ingress_port == 0) { \
            /* packet arrived from port 0 (iperf server) */ \
            ff3_input[(W_N - 1):0] = FF3_GET_INPUT(HDRS_IP.dstAddr, HDRS_TRANSPORT.dstPort); \
            FF3_INVOKE(ff3_decrypt); \
            HDRS_IP.dstAddr[(W_N - 16 - 1):0] = ff3_output[(W_N - 1):16]; \
            HDRS_TRANSPORT.dstPort = ff3_output[15:0]; \
        } \
    }

control MyIngress(
    inout MyHeaders_t         hdrs,
    inout MyMetadata_t        meta,
    inout standard_metadata_t standard_metadata)
{
    apply {
        FF3_HANDLE_PACKET();
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 0;
            hdrs.vlan.vid = 11;
        } else if (standard_metadata.ingress_port == 0) {
            standard_metadata.egress_spec = 1;
            hdrs.vlan.vid = 10;
        }
    }
}

control MyEgress(
    inout MyHeaders_t         hdrs,
    inout MyMetadata_t        meta,
    inout standard_metadata_t standard_metadata)
{
    apply {  }
}

control MyComputeChecksum(
    inout MyHeaders_t  hdrs,
    inout MyMetadata_t meta)
{
    apply {
        #if IP_VERSION == 4 && TRANSPORT_PROTOCOL == 0x11
        update_checksum(
            hdrs.ipv4.isValid(),
            {
                hdrs.ipv4.version,
                hdrs.ipv4.ihl,
                hdrs.ipv4.diffserv,
                hdrs.ipv4.totalLen,
                hdrs.ipv4.identification,
                hdrs.ipv4.flags,
                hdrs.ipv4.fragOffset,
                hdrs.ipv4.ttl,
                hdrs.ipv4.protocol,
                hdrs.ipv4.srcAddr,
                hdrs.ipv4.dstAddr
            },
            hdrs.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        update_checksum_with_payload(
            hdrs.udp.isValid(),
            {
                hdrs.ipv4.srcAddr,
                hdrs.ipv4.dstAddr,
                8w0,
                hdrs.ipv4.protocol,
                meta.help.transportLayerLenIpv4,
                hdrs.udp.srcPort,
                hdrs.udp.dstPort,
                hdrs.udp.len,
                16w0
            },
            hdrs.udp.checksum,
            HashAlgorithm.csum16
        );
        #elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x11
        update_checksum_with_payload(
            hdrs.udp.isValid(),
            {
                hdrs.ipv6.srcAddr,
                hdrs.ipv6.dstAddr,
                meta.help.transportLayerLenIpv6,
                24w0,
                hdrs.ipv6.protocol,
                hdrs.udp.srcPort,
                hdrs.udp.dstPort,
                hdrs.udp.len,
                16w0
            },
            hdrs.udp.checksum,
            HashAlgorithm.csum16
        );
        #elif IP_VERSION == 4 && TRANSPORT_PROTOCOL == 0x06
        update_checksum(
            hdrs.ipv4.isValid(),
            {
                hdrs.ipv4.version,
                hdrs.ipv4.ihl,
                hdrs.ipv4.diffserv,
                hdrs.ipv4.totalLen,
                hdrs.ipv4.identification,
                hdrs.ipv4.flags,
                hdrs.ipv4.fragOffset,
                hdrs.ipv4.ttl,
                hdrs.ipv4.protocol,
                hdrs.ipv4.srcAddr,
                hdrs.ipv4.dstAddr
            },
            hdrs.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        update_checksum_with_payload(
            hdrs.tcp.isValid(),
            {
                hdrs.ipv4.srcAddr,
                hdrs.ipv4.dstAddr,
                8w0,
                hdrs.ipv4.protocol,
                meta.help.transportLayerLenIpv4,
                hdrs.tcp.srcPort,
                hdrs.tcp.dstPort,
                hdrs.tcp.seqNo,
                hdrs.tcp.ackNo,
                hdrs.tcp.dataOffset,
                hdrs.tcp.res,
                hdrs.tcp.flags,
                hdrs.tcp.window,
                16w0,
                hdrs.tcp.urgentPtr
            },
            hdrs.tcp.checksum,
            HashAlgorithm.csum16
        );
        #elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x06
        update_checksum_with_payload(
            hdrs.tcp.isValid(),
            {
                hdrs.ipv6.srcAddr,
                hdrs.ipv6.dstAddr,
                meta.help.transportLayerLenIpv6,
                24w0,
                hdrs.ipv6.protocol,
                hdrs.tcp.srcPort,
                hdrs.tcp.dstPort,
                hdrs.tcp.seqNo,
                hdrs.tcp.ackNo,
                hdrs.tcp.dataOffset,
                hdrs.tcp.res,
                hdrs.tcp.flags,
                hdrs.tcp.window,
                16w0,
                hdrs.tcp.urgentPtr
            },
            hdrs.tcp.checksum,
            HashAlgorithm.csum16
        );
        #endif
    }
}

control MyDeparser(
    packet_out     packet,
    in MyHeaders_t hdrs)
{
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.vlan);
        packet.emit(hdrs.ipv4);
        packet.emit(hdrs.ipv6);
        packet.emit(hdrs.tcp);
        packet.emit(hdrs.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
