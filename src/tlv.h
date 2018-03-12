/*
# Copyright (c) 2017 University of Cambridge
# Copyright (c) 2017 Rémi Oudin
# All rights reserved.
#
# This software was developed by University of Cambridge Computer Laboratory
# under the ENDEAVOUR project (grant agreement 644960) as part of
# the European Union's Horizon 2020 research and innovation programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA Open Systems C.I.C. (NetFPGA) under one or more
# contributor license agreements. See the NOTICE file distributed with this
# work for additional information regarding copyright ownership. NetFPGA
# licenses this file to you under the NetFPGA Hardware-Software License,
# Version 1.0 (the License); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at:
#
# http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
*/
#ifndef TLV_TLV_CHAIN_H
#define TLV_TLV_CHAIN_H
#include <stdint.h>
#include <arpa/inet.h>


#define MAX_OXM 64

// TLV data structure
typedef struct tlv
{
    int16_t oxm_class;    // type
    int8_t field;
    int8_t hasmask;
    int8_t size;   // size of data
    int8_t* data;
} tlv_t;

// TLV chain data structure. Contains array of (50) tlv
// objects. 
typedef struct tlv_chain
{
    tlv_t object[MAX_OXM];
    uint8_t used; // keep track of tlv elements used
} tlv_chain_t;

typedef enum tlv_result {
    TLV_ERROR_NOT_EMPTY = -3,
    TLV_ERROR_NO_DATA = -2,
    TLV_ERROR_OOM = -1,
    TLV_SUCCESS = 0,
} tlv_result_t;

typedef enum hasmask {
    NOMASK = 0x0,
    HASMASK = 0x1 
} hasmask_t;

tlv_result_t tlv_chain_add_in_port(tlv_chain_t *oxm, uint32_t x, uint32_t*  mask);
tlv_result_t tlv_chain_add_dl_src(tlv_chain_t *oxm, uint8_t x[static 6], uint8_t mask[static 6]);
tlv_result_t tlv_chain_add_dl_dst(tlv_chain_t *oxm, uint8_t x[static 6], uint8_t mask[static 6]);
tlv_result_t tlv_chain_add_dl_vlan(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask);
tlv_result_t tlv_chain_add_dl_type(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask);
tlv_result_t tlv_chain_add_nw_src(tlv_chain_t *oxm, uint32_t x, uint32_t*  mask);
tlv_result_t tlv_chain_add_nw_dst(tlv_chain_t *oxm, uint32_t x, uint32_t*  mask);
tlv_result_t tlv_chain_add_nw_proto(tlv_chain_t *oxm, uint8_t x, uint8_t*  mask);
tlv_result_t tlv_chain_add_tp_src(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask);
tlv_result_t tlv_chain_add_tp_dst(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask);
tlv_result_t tlv_chain_add_raw(tlv_chain_t *oxm, unsigned char field, int16_t size, const void *bytes, uint8_t hasmask);
tlv_result_t tlv_chain_serialize(tlv_chain_t *oxm, unsigned char *dest, int32_t *count);
tlv_result_t tlv_chain_deserialize(const unsigned char *src, tlv_chain_t *dest, int32_t length);
tlv_result_t tlv_chain_free(tlv_chain_t *oxm);
#endif
