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
#include "test_module.h"

/**
 * \defgroup openflow_dummy dummy 
 * @ingroup modules
 * This module provide an empty implementation for all the functions of an oflops module.
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 * 
 */

/**
 * get the name of the module. 
 * \ingroup openflow_dummy
 * @return name of module 
 */
char * name() {
  return "openflow_dummy";
}

/** Some constants to help me with conversions
 */



/** Send sequence
 */
uint32_t sendno;

/**
* \ingroup openflow_dummy
 * Initialization code of the module
 * @param ctx data context of the module
 */
int init(struct oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  //init counters
  sendno = 0;
  TAILQ_INIT(&my_tailq_head);
  finished = 0;
  //open file for storing measurement
  measure_output = fopen("measure.log", "w");

  while(*config_str == ' ') {
    config_str++;
  }
  param = config_str;
  while(1) {
    pos = index(param, ' ');

    if((pos == NULL)) {
      if (*param != '\0') {
        pos = param + strlen(param) + 1;
      } else
        break;
    }
    *pos='\0';
    pos++;
    value = index(param,'=');
    *value = '\0';
    value++;
    //fprintf(stderr, "param = %s, value = %s\n", param, value);
    if(value != NULL) {
      printf("value : %s \n", value);
    }
  } 

  return 0;
}

/** 
 * \ingroup openflow_dummy
 * Initializatize controll channel and schedule events 
 * @param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
  return 0;
}

/**
 * \ingroup openflow_dummy
 * Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(struct oflops_context * ctx, struct timer_event *te) {
  return 0;
}

/** \ingroup openflow_dummy
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter struct for pcap
 */
int get_pcap_filter(struct oflops_context *ctx, oflops_channel_name ofc, cap_filter** filter) {
    *filter = malloc(sizeof(cap_filter));
    return 0;
}


/**
 * \ingroup openflow_dummy
 * Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(struct oflops_context *ctx, struct pcap_event * pe, oflops_channel_name ch) {
  return 0;
}
/**
 * \ingroup openflow_dummy
 * Handle pkt_in of messages.
 * @param ctx pointer to opaque context
 * @param ofph a pointer to the data of the pkt_in packet
 */

int of_event_packet_in(struct oflops_context *ctx, const struct ofp_packet_in * ofph) {
  return 0;
}
/**
 * \ingroup openflow_dummy
 * Handle of echo requests.
 * @param ctx pointer to opaque context
 * @param ofph a pointer to the data of the echo request
 */

int of_event_echo_request(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}
/**
 * \ingroup openflow_dummy
 * Handle of port status replies
 * \param ctx pointer to opaque context
 * \param ofph a pointer to the data of the packet
 */

int of_event_port_status(struct oflops_context *ctx, const struct ofp_port_status * ofph) {
  return 0;
}

/**
* \ingroup openflow_dummy
* handle any of message received, not captured by the other event methods
* \param ctx data of the context of the module
*/
int of_event_other(struct oflops_context *ctx, const struct ofp_header * ofph) {
  return 0;
}

/**
 * \ingroup openflow_dummy
 * handle asyncronous snmp replies
 * \param ctx pointer to opaque context
 * \param se snmp reply
 */
int handle_snmp_event(struct oflops_context * ctx, struct snmp_event * se) {
  return 0;
}

