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
/*****************************************************************************\
|          TLV module for the handling of OpenFlow Extended Match             |
\*****************************************************************************/
/* NB: Strongly inspired from https://codereview.stackexchange.com/questions/56203/type-length-value-tlv-encode-decode */


#include "tlv.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "openflow-1.3.h"

tlv_result_t tlv_chain_add_in_port(tlv_chain_t *oxm, uint32_t x, uint32_t* mask) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IN_PORT, 4, &x, NOMASK);
    } else {
        uint64_t val = ((uint64_t)x)<<32 | *mask;
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IN_PORT, 8, &val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_dl_src(tlv_chain_t *oxm, uint8_t x[static 6], uint8_t  mask[static 6]) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_SRC, 6, x, NOMASK);
    } else {
        uint32_t val[12];
        int i;
        for(i=0; i<6; i++) {
            val[i] = x[i];
            val[6+i] = mask[i];
        }
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_SRC, 12, val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_dl_dst(tlv_chain_t *oxm, uint8_t x[static 6], uint8_t  mask[static 6]) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_DST, 6, x, NOMASK);
    } else {
        uint32_t val[12];
        int i;
        for(i=0; i<6; i++) {
            val[i] = x[i];
            val[6+i] = mask[i];
        }
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_DST, 12, val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_dl_vlan(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask) {
	uint16_t tmp = htons(0x1000 | x);
	if (mask == NULL) {
		return tlv_chain_add_raw(oxm, OFPXMT_OFB_VLAN_VID, 2, &tmp, NOMASK);
	} else {
		uint32_t val = tmp<<16 | *mask;
		return tlv_chain_add_raw(oxm, OFPXMT_OFB_VLAN_VID, 4, &val, HASMASK);
	}
}

tlv_result_t tlv_chain_add_dl_type(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_TYPE, 2, &x, NOMASK);
    } else {
        uint32_t val = x<<16 | *mask;
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_ETH_TYPE, 4, &val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_nw_src(tlv_chain_t *oxm, uint32_t x, uint32_t*  mask) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IPV4_SRC, 4, &x, NOMASK);
    } else {
        uint64_t val =  ((uint64_t)*mask<<32) | (x);
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IPV4_SRC, 8, &val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_nw_dst(tlv_chain_t *oxm, uint32_t x, uint32_t*  mask) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IPV4_DST, 4, &x, NOMASK);
    } else {
        uint64_t val = ((uint64_t)*mask << 32) | x;
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IPV4_DST, 8, &val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_nw_proto(tlv_chain_t *oxm, uint8_t x, uint8_t*  mask) {
    if (mask == NULL) {
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IP_PROTO, 1, &x, NOMASK);
    } else {
        uint16_t val = x<<8 | *mask;
        return tlv_chain_add_raw(oxm, OFPXMT_OFB_IP_PROTO, 2, &val, HASMASK);
    }
}

tlv_result_t tlv_chain_add_tp_src(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask) {
    if (mask == NULL) {
        return (tlv_chain_add_raw(oxm, OFPXMT_OFB_UDP_SRC, 2, &x, NOMASK));
    } else {
        uint32_t val = x<<16 | *mask;
        return (tlv_chain_add_raw(oxm, OFPXMT_OFB_UDP_SRC, 4, &val, HASMASK));
    }
}

tlv_result_t tlv_chain_add_tp_dst(tlv_chain_t *oxm, uint16_t x, uint16_t*  mask) {
    if (mask == NULL) {
        return (tlv_chain_add_raw(oxm, OFPXMT_OFB_UDP_DST, 2, &x, NOMASK));
    } else {
        uint32_t val = x<<16 | *mask;
        return (tlv_chain_add_raw(oxm, OFPXMT_OFB_UDP_DST, 4, &val, HASMASK));
    }
}


tlv_result_t tlv_chain_add_raw(tlv_chain_t *oxm,
                          unsigned char field, int16_t size,
                          const void *bytes,
                          uint8_t hasmask) {
    if( oxm == NULL || bytes == NULL) {
        fprintf(stderr, "[ERROR] No data]");
        return TLV_ERROR_NO_DATA;
    }

    // all elements used in chain?
    if( oxm->used == MAX_OXM) {
        fprintf(stderr, "[ERROR] Out of memory");
        return TLV_ERROR_OOM;
    }

    int index = oxm->used;
    oxm->object[index].oxm_class = htons(OFPXMC_OPENFLOW_BASIC);
    oxm->object[index].field = field << 1;
    oxm->object[index].size = size;
    oxm->object[index].hasmask = hasmask;
    oxm->object[index].data = malloc(size);
    memcpy(oxm->object[index].data, bytes, size);

    // increase number of tlv objects used in this chain
    oxm->used++;

    // success
    return TLV_SUCCESS;
}

tlv_result_t tlv_chain_free(tlv_chain_t *oxm)
{
    int i;
    if(oxm == NULL) {
        return TLV_ERROR_NO_DATA;
    }

    for(i =0; i < oxm->used; i++) {
        free(oxm->object[i].data);
        oxm->object[i].data = NULL;
    }

    return TLV_SUCCESS;
}

// serialize the tlv chain into byte array
tlv_result_t tlv_chain_serialize(tlv_chain_t *a,
        unsigned char *dest, /* out */ int32_t* count)
{
    int i;
    if(a == NULL || dest == NULL) {
        return TLV_ERROR_NO_DATA;
    }

    // Number of bytes serialized
    int32_t counter = 0;

    for(i = 0; i < a->used; i++)
    {
        tlv_t current = a->object[i];
        memcpy(&dest[counter], &current.oxm_class, 2);
        counter += 2;

        dest[counter] =  current.field | current.hasmask;
        counter++;

        dest[counter] = current.size;
        counter++;

        memcpy(&dest[counter], current.data, current.size);
        counter += current.size;
    }

    // Return number of bytes serialized
    *count = counter;
    return TLV_SUCCESS;
}

tlv_result_t tlv_chain_deserialize(const unsigned char *src, struct tlv_chain *dest, int32_t length)
{
    if(dest == NULL || src == NULL)
        return TLV_ERROR_NO_DATA;

    // we want an empty chain
    if(dest->used != 0)
        return TLV_ERROR_NOT_EMPTY;

    int32_t counter = 0;
    while(counter < length) {
        if(dest->used == MAX_OXM) {
            return TLV_ERROR_OOM;
        }

        // deserialize oxm_class
        memcpy(&dest->object[dest->used].oxm_class, &src[counter], 2);
        counter+=2;

        dest->object[dest->used].field = src[counter] && 0xfe;
        dest->object[dest->used].hasmask= src[counter] && 0x01;
        counter++;

        // deserialize size
        dest->object[dest->used].size = src[counter];
        counter++;

        // deserialize data itself, only if data is not NULL
        if(dest->object[dest->used].size > 0) {
            dest->object[dest->used].data = malloc(dest->object[dest->used].size);
            memcpy(dest->object[dest->used].data, &src[counter], dest->object[dest->used].size);
            counter += dest->object[dest->used].size;
        } else {
            dest->object[dest->used].data = NULL;
        }
        // increase number of tlv objects reconstructed
        dest->used++;
    }
    // success
    return TLV_SUCCESS;
}


