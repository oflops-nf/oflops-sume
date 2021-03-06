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
#ifndef OF_PARSER_H
#define OF_PARSER_H 1

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

#include "msg.h"
#include "oflops_pcap.h"
#include "log.h"
#include "utils.h"

/*
 * FIXME: this code is not used anymore in oflops. I used it for a bit 
 * to improve the msgbuf structures, but it suffers from the problem that 
 * the pca plibrary may loose packets, resulting on hole in the reassembled data
 8 on which I don't know what i can do. 
 */

/**
 * initialize of parsing data
 */
void msg_init();

/**
 * insert in the flow reconstruction buffers new data
 * \param b data to e append
 * \param hdr pcap packet header of the data
 * \return the data of the flow where the data are stored
 */
int append_data_to_flow(const  void *b, struct pcap_pkthdr hdr);

/**
 * check if a full packet has been received on the buffer for a specific direction
 * \param dir the direction of the data
 * \return return true if a complete data has been received on the direction. otherwise 
 * false. 
 */
int contains_next_msg(int dir);

/**
* fetch a new pcap event structure from the buffer of flow for a direction of the control chanel.
* \param dir the direction of the control channel from which we read data
* \param opf the pcap event with the fata
* \return the size of the packet in the buffer, or a negative number if no data can be read.
*/
int get_next_msg(int dir, struct pcap_event **opf);

/**
* A deprecated method, that logged all packet received on control channel
*/
int ofp_msg_log(const void *b,  struct pcap_pkthdr hdr);

/*
 * A simple function to strip the ethernet/ip/tcp header from an 
 * openflow packet. 
 * @param b the data of the packet
 * @param len the size of the packet
 */
int parse_ip_packet_header(const void *b, int len, struct flow *fl);

#endif 
