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
    bit<W_16>  ingressPort;
    bit<16>    transportLayerLenIpv4;
    bit<32>    transportLayerLenIpv6;
}

struct Aes_t {
    // arguments for extern function aes_encrypt
    bit<W_32>  r0;
    bit<W_32>  r1;
    bit<W_32>  r2;
    bit<W_32>  r3;
    // result from extern function aes_encrypt
    bit<W_32>  t0;
    bit<W_32>  t1;
    bit<W_32>  t2;
    bit<W_32>  t3;
}

struct Ff3_t {
    bit<W_8>   round;
    bit<W_U>   a;
    bit<W_U>   b;
}

struct MyMetadata_t {
    Help_t     help;
    Aes_t      aes;
    Ff3_t      ff3;
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
#define SET_TRANSPORT_LAYER_LEN() \
    meta.help.transportLayerLenIpv4 = hdrs.udp.len;
#elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x11
#define HDRS_IP hdrs.ipv6
#define HDRS_TRANSPORT hdrs.udp
#define SET_TRANSPORT_LAYER_LEN() \
    meta.help.transportLayerLenIpv6 = 0; \
    meta.help.transportLayerLenIpv6[15:0] = hdrs.udp.len;
#elif IP_VERSION == 4 && TRANSPORT_PROTOCOL == 0x06
#define HDRS_IP hdrs.ipv4
#define HDRS_TRANSPORT hdrs.tcp
#define SET_TRANSPORT_LAYER_LEN() \
    meta.help.transportLayerLenIpv4 = hdrs.ipv4.totalLen - (bit<16>) hdrs.tcp.dataOffset * 4;
#elif IP_VERSION == 6 && TRANSPORT_PROTOCOL == 0x06
#define HDRS_IP hdrs.ipv6
#define HDRS_TRANSPORT hdrs.tcp
#define SET_TRANSPORT_LAYER_LEN() \
    meta.help.transportLayerLenIpv6 = 0; \
    meta.help.transportLayerLenIpv6[15:0] = hdrs.ipv6.payloadLen - (bit<16>) hdrs.tcp.dataOffset * 4;
#endif

// *****************************************************************************
// FF3-1 HELPERS
// *****************************************************************************

extern void aes_encrypt();

#define FF3_IS_ENCRYPTION(ingressPort) ( ingressPort == 1 )

#define FF3_GET_INPUT(ipAddress, portNumber) ( ipAddress[(W_N - 16 - 1):0] ++ portNumber )

#define MODULO(number, powerOfTwo) (number & ((64w0 ++ (64w1 << powerOfTwo)) - 1))

#define REVERSE_BITS_WIDTH_U(dst, src) \
    tmp = 0; \
    tmp[(W_U - 1):0] = src; \
    msk = 0b11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000; \
    tmp = (tmp & msk) >> 64 | (tmp & ~msk) << 64; \
    msk = 0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000; \
    tmp = (tmp & msk) >> 32 | (tmp & ~msk) << 32; \
    msk = 0b11111111111111110000000000000000111111111111111100000000000000001111111111111111000000000000000011111111111111110000000000000000; \
    tmp = (tmp & msk) >> 16 | (tmp & ~msk) << 16; \
    msk = 0b11111111000000001111111100000000111111110000000011111111000000001111111100000000111111110000000011111111000000001111111100000000; \
    tmp = (tmp & msk) >>  8 | (tmp & ~msk) <<  8; \
    msk = 0b11110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000; \
    tmp = (tmp & msk) >>  4 | (tmp & ~msk) <<  4; \
    msk = 0b11001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100; \
    tmp = (tmp & msk) >>  2 | (tmp & ~msk) <<  2; \
    msk = 0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010; \
    tmp = (tmp & msk) >>  1 | (tmp & ~msk) <<  1; \
    dst = tmp[(W_128 - 1):(W_128 - W_U)];

#define REVERSE_BITS_WIDTH_V(dst, src) \
    tmp = 0; \
    tmp[(W_V - 1):0] = src; \
    msk = 0b11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000; \
    tmp = (tmp & msk) >> 64 | (tmp & ~msk) << 64; \
    msk = 0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000; \
    tmp = (tmp & msk) >> 32 | (tmp & ~msk) << 32; \
    msk = 0b11111111111111110000000000000000111111111111111100000000000000001111111111111111000000000000000011111111111111110000000000000000; \
    tmp = (tmp & msk) >> 16 | (tmp & ~msk) << 16; \
    msk = 0b11111111000000001111111100000000111111110000000011111111000000001111111100000000111111110000000011111111000000001111111100000000; \
    tmp = (tmp & msk) >>  8 | (tmp & ~msk) <<  8; \
    msk = 0b11110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000; \
    tmp = (tmp & msk) >>  4 | (tmp & ~msk) <<  4; \
    msk = 0b11001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100110011001100; \
    tmp = (tmp & msk) >>  2 | (tmp & ~msk) <<  2; \
    msk = 0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010; \
    tmp = (tmp & msk) >>  1 | (tmp & ~msk) <<  1; \
    dst = tmp[(W_128 - 1):(W_128 - W_V)];

#define REVERSE_BYTES(dst, src) \
{ \
    bit<W_128> result = 0; \
    result[( 1 * 8 - 1):( 0 * 8)] = src[(16 * 8 - 1):(15 * 8)]; \
    result[( 2 * 8 - 1):( 1 * 8)] = src[(15 * 8 - 1):(14 * 8)]; \
    result[( 3 * 8 - 1):( 2 * 8)] = src[(14 * 8 - 1):(13 * 8)]; \
    result[( 4 * 8 - 1):( 3 * 8)] = src[(13 * 8 - 1):(12 * 8)]; \
    result[( 5 * 8 - 1):( 4 * 8)] = src[(12 * 8 - 1):(11 * 8)]; \
    result[( 6 * 8 - 1):( 5 * 8)] = src[(11 * 8 - 1):(10 * 8)]; \
    result[( 7 * 8 - 1):( 6 * 8)] = src[(10 * 8 - 1):( 9 * 8)]; \
    result[( 8 * 8 - 1):( 7 * 8)] = src[( 9 * 8 - 1):( 8 * 8)]; \
    result[( 9 * 8 - 1):( 8 * 8)] = src[( 8 * 8 - 1):( 7 * 8)]; \
    result[(10 * 8 - 1):( 9 * 8)] = src[( 7 * 8 - 1):( 6 * 8)]; \
    result[(11 * 8 - 1):(10 * 8)] = src[( 6 * 8 - 1):( 5 * 8)]; \
    result[(12 * 8 - 1):(11 * 8)] = src[( 5 * 8 - 1):( 4 * 8)]; \
    result[(13 * 8 - 1):(12 * 8)] = src[( 4 * 8 - 1):( 3 * 8)]; \
    result[(14 * 8 - 1):(13 * 8)] = src[( 3 * 8 - 1):( 2 * 8)]; \
    result[(15 * 8 - 1):(14 * 8)] = src[( 2 * 8 - 1):( 1 * 8)]; \
    result[(16 * 8 - 1):(15 * 8)] = src[( 1 * 8 - 1):( 0 * 8)]; \
    dst = result; \
}

control MyIngress(
    inout MyHeaders_t         hdrs,
    inout MyMetadata_t        meta,
    inout standard_metadata_t standard_metadata)
{
    apply {
        if (hdrs.vlan.etherType == ETHERNET_TYPE_IP(IP_VERSION) && HDRS_IP.protocol == TRANSPORT_PROTOCOL) {
            bit<W_128> tmp = 0;
            bit<W_128> msk = 0;

            if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
                meta.help.ingressPort = standard_metadata.ingress_port;
                SET_TRANSPORT_LAYER_LEN();

                meta.ff3.round = 1;
                meta.ff3.a = 0;
                meta.ff3.b = 0;

                bit<W_N> ff3_input = 0;
                if (FF3_IS_ENCRYPTION(meta.help.ingressPort)) {
                    // [FF3-1] - step (2) : Let A = X[1..u]; B = X[u + 1..n]
                    ff3_input = FF3_GET_INPUT(HDRS_IP.srcAddr, HDRS_TRANSPORT.srcPort);
                } else {
                    // [FF3-1] - step (2) : Let A = X[1..u]; B = X[u + 1..n]
                    ff3_input = FF3_GET_INPUT(HDRS_IP.dstAddr, HDRS_TRANSPORT.dstPort);
                }
                meta.ff3.a[(W_U - 1):0] = ff3_input[(W_N - 1):(W_N - W_U)];
                meta.ff3.b[(W_V - 1):0] = ff3_input[(W_V - 1):0];
            }

            bool isEncryption = false;

            bit<W_8> iteration = 0;

            // [FF3-1] - step (3) : Let Tl = T[0..27] || 0*4 and Tr = T[32..55] || T[28..31] || 0*4
            bit<W_32> tl = FF3_TWEAK_L;
            bit<W_32> tr = FF3_TWEAK_R;

            isEncryption = FF3_IS_ENCRYPTION(meta.help.ingressPort);
            if (isEncryption) {
                // [FF3-1] encryption iteration goes from 0 to 7
                iteration = meta.ff3.round - 1;
            } else {
                // [FF3-1] decryption iteration goes from 7 down to 0
                iteration = FF3_ROUNDS - meta.ff3.round;
            }

            // [FF3-1] - step (4.i) : If i is even, let m = u and W = Tr, else let m = v and W = Tl
            bit<W_32> m = 0;
            bit<W_32> w = 0;
            if ((iteration & 1) == 0) {
                m = W_U;
                w = tr;
            } else {
                m = W_V;
                w = tl;
            }

            bit<W_128> p = 0;
            p[(W_128 - 1):(W_128 - 32)] = w ^ (8w0 ++ 8w0 ++ 8w0 ++ iteration);
            if (isEncryption) {
                // [FF3-1] - step (4.ii) : Let P = W ^ ([i]*4) || [NUMradix(REV(B))]*12
                if ((iteration & 1) == 0) {
                    bit<W_V> macroTargetTemp = 0;
                    REVERSE_BITS_WIDTH_V(macroTargetTemp, meta.ff3.b[(W_V - 1):0]);
                    p[(W_V - 1):0] = macroTargetTemp;
                } else {
                    bit<W_U> macroTargetTemp = 0;
                    REVERSE_BITS_WIDTH_U(macroTargetTemp, meta.ff3.b[(W_U - 1):0]);
                    p[(W_U - 1):0] = macroTargetTemp;
                }
            } else {
                // [FF3-1] - step (4.ii) : Let P = W ^ ([i]*4) || [NUMradix(REV(A))]*12
                if ((iteration & 1) == 0) {
                    bit<W_V> macroTargetTemp = 0;
                    REVERSE_BITS_WIDTH_V(macroTargetTemp, meta.ff3.a[(W_V - 1):0]);
                    p[(W_V - 1):0] = macroTargetTemp;
                } else {
                    bit<W_U> macroTargetTemp = 0;
                    REVERSE_BITS_WIDTH_U(macroTargetTemp, meta.ff3.a[(W_U - 1):0]);
                    p[(W_U - 1):0] = macroTargetTemp;
                }
            }

            // [FF3-1] - step (4.iii) : Let S = REVB(CIPHER(REVB(P)))
            bit<W_128> aesInput = 0;
            REVERSE_BYTES(aesInput, p);

            meta.aes.t0 = aesInput[127:96];
            meta.aes.t1 = aesInput[ 95:64];
            meta.aes.t2 = aesInput[ 63:32];
            meta.aes.t3 = aesInput[ 31: 0];

            aes_encrypt();

            bit<W_128> aesOutput = 0;
            aesOutput[127:96] = meta.aes.r0;
            aesOutput[ 95:64] = meta.aes.r1;
            aesOutput[ 63:32] = meta.aes.r2;
            aesOutput[ 31: 0] = meta.aes.r3;

            bit<W_128> s = 0;
            REVERSE_BYTES(s, aesOutput);

            // [FF3-1] - step (4.iv) : Let y = NUM(S)
            bit<W_128> y = s;
            bit<W_128> littleC = 0;
            bit<W_U> c = 0;
            bit<W_128> temp = 0;
            bit<W_U> macroTargetWidthU = 0;
            bit<W_V> macroTargetWidthV = 0;
            if (isEncryption) {
                if ((iteration & 1) == 0) {
                    // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(A)) + y) mod (radix^^m)
                    REVERSE_BITS_WIDTH_U(macroTargetWidthU, meta.ff3.a[(W_U - 1):0]);
                    temp[(W_U - 1):0] = macroTargetWidthU;
                    littleC = MODULO((temp + y), W_U);
                    // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
                    REVERSE_BITS_WIDTH_U(macroTargetWidthU, littleC[(W_U - 1):0]);
                    c[(W_U - 1):0] = macroTargetWidthU;
                } else {
                    // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(A)) + y) mod (radix^^m)
                    REVERSE_BITS_WIDTH_V(macroTargetWidthV, meta.ff3.a[(W_V - 1):0]);
                    temp[(W_V - 1):0] = macroTargetWidthV;
                    littleC = MODULO((temp + y), W_V);
                    // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
                    REVERSE_BITS_WIDTH_V(macroTargetWidthV, littleC[(W_V - 1):0]);
                    c[(W_V - 1):0] = macroTargetWidthV;
                }
                // [FF3-1] - step (4.vii) : Let A = B
                meta.ff3.a = meta.ff3.b;
                // [FF3-1] - step (4.viii) : Let B = C
                meta.ff3.b = c;
            } else {
                if ((iteration & 1) == 0) {
                    // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(B)) - y) mod (radix^^m)
                    REVERSE_BITS_WIDTH_U(macroTargetWidthU, meta.ff3.b[(W_U - 1):0]);
                    temp[(W_U - 1):0] = macroTargetWidthU;
                    littleC = MODULO((temp - y), W_U);
                    // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
                    REVERSE_BITS_WIDTH_U(macroTargetWidthU, littleC[(W_U - 1):0]);
                    c[(W_U - 1):0] = macroTargetWidthU;
                } else {
                    // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(B)) - y) mod (radix^^m)
                    REVERSE_BITS_WIDTH_V(macroTargetWidthV, meta.ff3.b[(W_V - 1):0]);
                    temp[(W_V - 1):0] = macroTargetWidthV;
                    littleC = MODULO((temp - y), W_V);
                    // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
                    REVERSE_BITS_WIDTH_V(macroTargetWidthV, littleC[(W_V - 1):0]);
                    c[(W_V - 1):0] = macroTargetWidthV;
                }
                // [FF3-1] - step (4.vii) : Let B = A
                meta.ff3.b = meta.ff3.a;
                // [FF3-1] - step (4.viii) : Let A = C
                meta.ff3.a = c;
            }

            if (meta.ff3.round < FF3_ROUNDS) {
                meta.ff3.round = meta.ff3.round + 1;
                // Resubmit the packet to the pipeline start saving meta fields
                resubmit(meta);
            } else {
                // [FF3-1] - step (5) : Return (A concat B)
                bit<W_N> ff3_output = meta.ff3.a[(W_U - 1):0] ++ meta.ff3.b[(W_V - 1):0];
                if (meta.help.ingressPort == 1) {
                    // packet arrived from port 1 (iperf client)
                    standard_metadata.egress_spec = 0;
                    hdrs.vlan.vid = 11;
                    HDRS_IP.srcAddr[(W_N - 16 - 1):0] = ff3_output[(W_N - 1):16];
                    HDRS_TRANSPORT.srcPort = ff3_output[15:0];
                } else if (meta.help.ingressPort == 0) {
                    // packet arrived from port 0 (iperf server)
                    standard_metadata.egress_spec = 1;
                    hdrs.vlan.vid = 10;
                    HDRS_IP.dstAddr[(W_N - 16 - 1):0] = ff3_output[(W_N - 1):16];
                    HDRS_TRANSPORT.dstPort = ff3_output[15:0];
                }
            }
        } else {
            if (standard_metadata.ingress_port == 1) {
                // packet arrived from port 1 (iperf client)
                standard_metadata.egress_spec = 0;
                hdrs.vlan.vid = 11;
            } else if (standard_metadata.ingress_port == 0) {
                // packet arrived from port 0 (iperf server)
                standard_metadata.egress_spec = 1;
                hdrs.vlan.vid = 10;
            }
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
