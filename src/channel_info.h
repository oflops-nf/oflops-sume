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

#ifndef CHANNEL_INFO_H
#define CHANNEL_INFO_H

struct channel_info;

#include "test_module.h"

/**
 * \brief State for a specific control or data channel.
 */
typedef struct channel_info {
    char * dev;                     /**< The name of the local interface of a channel */
    uint8_t rx_measurement;
    pcap_t * pcap_handle;           /**< A pcap object to capture traffic. Initialized only a module defines appropriately a non length zero field */
    int pcap_fd;                    /**< A non blocking file descriptor from the pcap library. It allows to select over multiple channels */
    int raw_sock;                   /**< A raw socket that allows an application inject crafted packets */
    int sock;                       /**< A descriptor for the TCP socket of the control channel. */
    int ifindex;                    /**< The index of the interface of the channel. */
    int of_port;                    /**< The port number on which the channel is attached on the switch */
    int packet_len;                 /**< length of packet for equally chunked data transfer (0: don't chunk) */
    struct ptrack_list * timestamps; /**< (Deprecated) a list of buffers to store pcap packet timestamp */
    struct msgbuf * outgoing;       /**< a buffer to store data send out of the interface */
    struct traf_gen_det *det;       /**< a description of the artificial traffic generated on the channel (valid only for data channels). */
    pcap_dumper_t *dump;            /**< the structure that store the stores the state of the file, on which we dump pcap data(used only by the control channel) */
    //oid inOID[MAX_OID_LEN];         /**< SNMP oid of the input counter of the port on which the channel is attached on the switch */
    //size_t inOID_len;               /**< length of the input OID structure */
    //oid outOID[MAX_OID_LEN];        /**< SNMP oid of the output counter of the port on which the channel is attached on the switch */
    //size_t outOID_len;              /**< length of the output OID structure */
    int cap_type;
    struct nf_cap_t *nf_cap;
    uint32_t rcv_packets;             /**< Number of packets received on this channel */
} channel_info;

/**
 *  A function that initializes a strcut channel_info with null values
 *  \param channel a pointer to a memory object of a struct channel_info
 *  \param dev the name of the interface
 *  \return return 1 on success or 0 otherwise
 */
int channel_info_init(struct channel_info * channel, const char * dev);

/**
 * fill in a strct channel_ifno, based on the informations contained in
 * the current context of the module
 * \param ctx oflops context of the module
 * \param mod a pointer a struct storing information for the running module
 * \param ch the id of the initialized channel
 */
void setup_channel(oflops_context *ctx,
                   struct test_module *mod, enum oflops_channel_name ch);


void setup_channel_snmp(oflops_context *ctx, enum oflops_channel_name ch,
                        char *in_oid, char *out_oid);

void my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len);

#endif
