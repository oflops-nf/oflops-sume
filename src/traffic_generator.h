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
#ifndef TRAFFIC_GENERATOR_H
#define TRAFFIC_GENERATOR_H 1

#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <stdint.h>

#include "nf_pktgen.h"

#include "msg.h"
#include "oflops.h"
#include "channel_info.h"
#include "context.h"
#include "utils.h"

#define MAX_PACKETS 100000

struct traf_gen_det {
  char intf_name[20];
  char src_ip[20], dst_ip_max[20], dst_ip_min[20];
  char mac_dst_base[20], mac_src[20];
  uint32_t mac_dst_count;
  uint16_t udp_src_port, udp_dst_port;
  uint32_t pkt_size;
  uint16_t vlan;
  uint16_t vlan_p;
  uint16_t vlan_cfi;
  uint32_t delay;
  uint64_t pkt_count;
  char flags[1024];
};

#ifndef PKTGEN_HDR

#define PKTGEN_HDR 1
struct pktgen_hdr {
  uint32_t magic;
  uint32_t seq_num;
  uint32_t tv_sec;
  uint32_t tv_usec;
  struct timeval time;
};
#endif

int init_traf_gen(oflops_context *ctx);
int add_traffic_generator(oflops_context *ctx, int channel, struct traf_gen_det *det);
int del_traffic_generator(struct oflops_context *ctx, int channel);
int start_traffic_generator();
int stop_traffic_generator( oflops_context *ctx);

char *report_traffic_generator(oflops_context *ctx);

struct pktgen_hdr *extract_pktgen_pkt(oflops_context *ctx, int port,
				      unsigned char *b, int len, struct flow *fl);
void oflops_gettimeofday(oflops_context *ctx, struct timeval *ts);

#endif
