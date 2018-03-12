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

#include <string.h>
#include <dlfcn.h>

#include <openflow-1.3.h>

#include "context.h"
#include "utils.h"
#include "log.h"
#include "test_module.h"


/**
 * an oflops context generation and initialization method
 * \return a pointer to the new oflops context details
 */
oflops_context * oflops_default_context(void) {

  //initialize oflops nf packet generator (enable packet padding)
  nf_init(1, 0, 0);

  oflops_context * ctx = malloc_and_check(sizeof(oflops_context));
  bzero(ctx, sizeof(*ctx));
  ctx->max_tests = 10 ;
  ctx->tests = malloc_and_check(ctx->max_tests * sizeof(test_module *));

  ctx->listen_port = OFP_TCP_PORT;	// listen on default port

  ctx->listen_fd   = -1;
  ctx->print = 0;
  ctx->snaplen = 112;

  ctx->n_channels=1;
  ctx->max_channels=10;
  ctx->channels = malloc_and_check(sizeof(struct channel_info)* ctx->max_channels);

  ctx->control_outgoing = msgbuf_new(4096);       // dynamically sized

  //ctx->snmp_channel_info = malloc_and_check(sizeof(struct snmp_channel));
  //ctx->snmp_channel_info->hostname = NULL;
  //ctx->snmp_channel_info->community_string = NULL;
  ctx->channels[OFLOPS_CONTROL].raw_sock = -1;

  // initalize other channels later
  ctx->log = malloc(sizeof(DEFAULT_LOG_FILE));
  strcpy(ctx->log, DEFAULT_LOG_FILE);

  ctx->trafficGen = PKTGEN;

  ctx->dump_controller = 0;
  ctx->cpuOID_count = 0;

  ctx->io_loop = ev_loop_new(EVFLAG_AUTO);
  ctx->timer_loop = ev_loop_new(EVFLAG_AUTO);
  ctx->data_loop = ev_loop_new(EVFLAG_AUTO);
  ctx->cpuOID_len = NULL;
  ctx->cpuOID = NULL;

  return ctx;
}

/**
  * a method to reinit an oflops context structure.
  * to be run me between tests.
  * \param ctx a pointer to the context object
  */
int reset_context(oflops_context * ctx) {
  // close the open lirary object
  if(ctx->curr_test)
    dlclose(ctx->curr_test->symbol_handle);
  return 0;
}
