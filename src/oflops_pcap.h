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
#ifndef OFLOPS_PCAP_H
#define OFLOPS_PCAP_H

#include <pcap.h>
#include <stdint.h>

struct pcap_event;


typedef struct cap_filter {
    char* proto;
	uint8_t proto_mask;
	uint16_t port, port_mask;
	uint32_t src, src_mask, dst, dst_mask;

} cap_filter;


typedef struct pcap_event {
  struct pcap_pkthdr pcaphdr;
  // NOTE: full packet capture NOT guaranteed; need to check pcaphdr to see
  // 	how much was captured
  unsigned char * data;
} pcap_event;

// Silly hack to get around how pcap_dispatch() works
// 	must be a nicer way, but... <shrug>
struct pcap_event_wrapper
{
  pcap_event *pe;
};

/**
 * release an allocated pcap_event struct
 * \param pe a pointer to the memory location of the object
 */
void pcap_event_free(pcap_event * pe);

/**
 * a function to push a newly cpatured packet to the appropriate method
 * \param pcap_event_wrapper_arg an event wrapper struct to copy data into.
 * \param h the header of the pcap packet 
 * \param bytes the payload of the packet 
 */
void oflops_pcap_handler(u_char * pcap_event_wrapper_arg, const struct pcap_pkthdr *h, const u_char *bytes);
#endif
