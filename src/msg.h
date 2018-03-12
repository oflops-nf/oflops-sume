/*
@NETFPGA_LICENSE_HEADER_START@

Licensed to NetFPGA Open Systems C.I.C. (NetFPGA) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. NetFPGA
licenses this file to you under the NetFPGA Hardware-Software License,
Version 1.0 (the License); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at:

http://www.netfpga-cic.org

Unless required by applicable law or agreed to in writing, Work distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

@NETFPGA_LICENSE_HEADER_END@
*/
#ifndef MSG_H
#define MSG_H 1

#ifndef  __BYTE_ORDER
    #define  __BYTE_ORDER == __LITTLE_ENDIAN
    #define __LITTLE_ENDIAN_BITFIELD 1
#endif

#include <stdint.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <openflow-1.3.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "log.h"
#include "utils.h"
#include "tlv.h"

//packet header size including ethernet/ip/udp
#define MEASUREMENT_PACKET_HEADER 46

// this file contains code that generates openflow packet. the code is pretty
// messed and need some extensive refactoring. hopefully this will happen in a later version.

typedef struct flow {
  uint32_t in_port;           /* Input switch port. */
  uint8_t dl_src[6];          /* Ethernet source address. */
  uint8_t dl_dst[6];          /* Ethernet destination address. */
  uint16_t dl_vlan;           /* Input VLAN. */
  uint16_t dl_type;           /* Ethernet frame type. */
  uint32_t nw_src;            /* IP source address. */
  uint32_t nw_dst;            /* IP destination address. */
  uint8_t nw_proto;           /* IP protocol. */
  uint16_t tp_src;            /* TCP/UDP source port. */
  uint16_t tp_dst;            /* TCP/UDP destination port. */
} flow_t;

/* A field is non zero iff the element should be wildcarded */
typedef struct wildcarded {
  uint8_t in_port;           /* Input switch port. */
  uint8_t dl_src;            /* Ethernet source address. */
  uint8_t dl_dst;            /* Ethernet destination address. */
  uint8_t dl_vlan;           /* Input VLAN. */
  uint8_t dl_type;           /* Ethernet frame type. */
  uint8_t nw_src;            /* IP source address. */
  uint8_t nw_dst;            /* IP destination address. */
  uint8_t nw_proto;          /* IP protocol. */
  uint8_t tp_src;            /* TCP/UDP source port. */
  uint8_t tp_dst;            /* TCP/UDP destination port. */
} wildcarded_t;


/* for each field, if wildcarded is non zero, wc is the mask value for
 * the wildcarding, else wc means nothing. */
typedef struct match {
    flow_t flow;
    wildcarded_t wildcarded;
    flow_t wc;
} match_t;

int match_to_payload(struct match* match, void** dest);
int payload_to_match(match_t * match, tlv_chain_t* tlv_chain);


struct ether_vlan_header {
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t tpid;
  uint8_t pcp:3;
  uint8_t cfi:1;
  uint16_t vid:12;
  u_int16_t ether_type;                 /* packet type ID field */
};

struct net_header{
  struct ether_header *ether;
  struct ether_vlan_header *ether_vlan;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
};

int make_ofp_hello(void **b);
int make_ofp_feat_req(void **b);
int make_ofp_flow_stat(void **b);
int make_ofp_flow_add(void **buferp,  flow_t *fl, flow_t * wildcards, uint32_t out_port,
		      uint32_t buffer_id, uint8_t table_id, uint16_t idle_timeout);
int make_ofp_flow_add_actions(void **, flow_t*, flow_t*, uint8_t *, uint8_t,
		  uint32_t, uint16_t);

int make_ofp_flow_modify(void **buferp, flow_t *fl,  flow_t *wildcards,
			 char *actions,  uint16_t action_len, uint32_t buffer_id,
			 uint16_t idle_timeout);

int make_ofp_flow_modify_output_port(void **buferp, flow_t *fl,
                     flow_t *wildcards,
				     uint32_t out_port, uint32_t buffer_id,
				     uint16_t idle_timeout);
int make_ofp_table_miss(void **bufferp);
int make_ofp_flow_del(void **buferp);
int make_ofp_flow_add_wildcard(void **buferp, uint32_t port);
int make_ofp_flow_get_stat(void **buferp, int xid);
int make_ofp_port_get_stat(void **buferp);
int make_ofp_aggr_flow_stats(void **buferp, int trans_id);
int make_ofp_echo_req(void **buferp);
//void print_ofp_msg(const void *b, size_t len);

char *generate_packet(struct flow fl, size_t len);
uint32_t extract_pkt_id(const char *b, int len);

#endif

