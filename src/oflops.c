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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
#include <pthread.h>

#include <nf_pktgen.h>

#include "oflops.h"
#include "msgbuf.h"
#include "module_run.h"
#include "usage.h"
#include "control.h"
#include "log.h"
#include "signal.h"
#include "traffic_generator.h"
#include "msg.h"
#include "channel_info.h"

#include "wc_event.h"

struct cap_event_data {
    oflops_context *ctx;
    enum oflops_channel_name ch;
};

void *run_module(void *param)
{
    struct run_module_param* tmp = (struct run_module_param *)param;
    return (void *)run_test_module(tmp->ctx, tmp->ix_mod);
}

void *start_traffic_thread(void *param)
{
    struct run_module_param* tmp = (struct run_module_param *)param;
    return (void *)run_traffic_generation(tmp->ctx, tmp->ix_mod);
}

static void process_pcap_event(struct ev_loop *loop, struct ev_io *w, int revents)
{
    struct cap_event_data *cap = (struct cap_event_data *)w->data;
    oflops_context *ctx = cap->ctx;
    enum oflops_channel_name ch = cap->ch;
    test_module * mod = ctx->curr_test;
    struct pcap_event_wrapper wrap;
    int count, i;
    static pcap_event pe;

    // read the next packet from the appropriate pcap socket
    if(revents | EV_READ) {
        if(ctx->channels[ch].cap_type == PCAP) {
            assert(ctx->channels[ch].pcap_handle);
            count = pcap_dispatch(ctx->channels[ch].pcap_handle, 1, oflops_pcap_handler, (u_char *) & wrap);

            //dump packet if required
            if((ch == OFLOPS_CONTROL) && (ctx->channels[ch].pcap_handle)
                    && (ctx->dump_controller))
                pcap_dump((u_char *)ctx->channels[ch].dump, &wrap.pe->pcaphdr, wrap.pe->data);

            if(count == 0)
                return;

            if(count < 0) {
                fprintf(stderr, "process_pcap_event:pcap_dispatch returned %d :: %s \n", count,
                        pcap_geterr(ctx->channels[ch].pcap_handle));
                return;
            }

            // dispatch it to the test module
            mod->handle_pcap_event(ctx, wrap.pe, ch);
            // clean up our mess
            pcap_event_free(wrap.pe);
        } else  if(ctx->channels[ch].cap_type == NF2) {

			for (i=0; i < 1000;i++) { 
				pe.data = (unsigned char *)nf_cap_next(ctx->channels[ch].nf_cap, &pe.pcaphdr);
                if((const u_char*) pe.data == (const u_char*)-1) {
                    return;
                }
				if(pe.data != NULL) {
                    ctx->channels[ch].rcv_packets++;
					mod->handle_pcap_event(ctx, &pe, ch);
				}
			}
        }
    }

    return;
}

void *start_capture_thread(void *param)
{
    int ch;
    struct run_module_param* tmp = (struct run_module_param *)param;
    ev_io *io_ch;
    struct cap_event_data *cap;

    for(ch = 0; ch < tmp->ctx->n_channels; ch++) {
        if((tmp->ctx->channels[ch].pcap_handle) || (tmp->ctx->channels[ch].nf_cap))  {
            io_ch = (ev_io*)xmalloc(sizeof(ev_io));
            ev_io_init(io_ch, process_pcap_event, tmp->ctx->channels[ch].pcap_fd, EV_READ);
            ev_io_start(tmp->ctx->data_loop, io_ch);
            cap = (struct cap_event_data*)xmalloc(sizeof(struct cap_event_data));
            cap->ctx = tmp->ctx;
            cap->ch = ch;
            io_ch->data = (void *)cap;
        }
    }
	ev_run(tmp->ctx->data_loop, 0);
    return NULL;
}


void *run_event_loop(void *param)
{
    struct run_module_param* state = (struct run_module_param *)param;
    return event_loop(state->ctx);
}

int main(int argc, char * argv[])
{
    int i, j;
    struct pcap_stat ps;
    pthread_t thread, event_thread, traffic_gen, traffic_cap;
    struct run_module_param *param =  
		(struct run_module_param *)malloc_and_check(sizeof(struct run_module_param));
    char msg[1024];
    struct timeval now;
    struct nf_cap_stats stat;
    struct nf_gen_stats gen_stat;
    // create the default context
    oflops_context * ctx = oflops_default_context();
    param->ctx = ctx;
    parse_args(ctx, argc, argv);

    if(ctx->n_tests == 0)
        usage("Need to specify at least one module to run\n", NULL);

    oflops_log_init(ctx->log);
    setup_control_channel(ctx);
    fprintf(stderr, "Running %d Test%s\n", ctx->n_tests, ctx->n_tests > 1 ? "s" : "");

    for(i = 0; i < ctx->n_tests; i++) {
        // init contaxt and setup module
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "------------ TEST %s ----------\n", (*(ctx->tests[i]->name))());
        fprintf(stderr, "-----------------------------------------------\n");
        // reset_context(ctx);
        ctx->curr_test = ctx->tests[i];
        param->ix_mod = i;
        setup_test_module(ctx, i);
        //start all the required threads of the program
        // the data receiving thread
        pthread_create(&thread, NULL, run_module, (void *)param);
        // the data generating thread
        pthread_create(&traffic_gen, NULL, start_traffic_thread, (void *)param);
        // the traffic capture thread
        pthread_create(&traffic_cap, NULL, start_capture_thread, (void *)param);
        // the timer thread.
        pthread_create(&event_thread, NULL, run_event_loop, (void *)param);
        pthread_join(event_thread, NULL);
        pthread_join(thread, NULL);

        // for the case of pktgen traffic generation the thread remain unresponsive to other
        // termination method, and for that reason we use explicit signal termination.
        if(ctx->trafficGen == PKTGEN)
            pthread_cancel(traffic_gen);
        else
            pthread_join(traffic_gen, NULL);

        //reading details for the data generation and capture process and output them to the log file.
        gettimeofday(&now, NULL);

        for(j = 0 ; j < ctx->n_channels; j++) {
            if((ctx->channels[j].cap_type == PCAP) &&
                    (ctx->channels[j].pcap_handle != NULL)) {
                pcap_stats(ctx->channels[j].pcap_handle, &ps);
                snprintf(msg, 1024, "%s:%u:%u", ctx->channels[j].dev, ps.ps_recv, ps.ps_drop);
                oflops_log(now, PCAP_MSG, msg);
                printf("%s\n", msg);
                // FIXME: this requires a parsing code to extract only required information and not the whole string.
                char *ret = report_traffic_generator(ctx);

                if(ret) {
                    oflops_log(now, PKTGEN_MSG, report_traffic_generator(ctx));
                    printf("%s\n", ret);
                }
            } else if((ctx->channels[j].cap_type == NF2) &&
                      (ctx->channels[j].nf_cap != NULL)) {
                nf_cap_stat(j - 1, &stat);
                snprintf(msg, 1024, "%s:rcv:%u:%u", ctx->channels[j].dev,  stat.pkt_cnt,
                         (stat.pkt_cnt - ctx->channels[j].rcv_packets));
                oflops_log(now, PCAP_MSG, msg);
                printf("device %s: %d packets transmitted, %u packets captured, %u packets dropped\n",
                        ctx->channels[j].dev, gen_stat.pkt_snd_cnt,
                        stat.pkt_cnt, (stat.pkt_cnt - ctx->channels[j].rcv_packets));
                snprintf(msg, 1024, "%s:snd:%u", ctx->channels[j].dev, gen_stat.pkt_snd_cnt);
                oflops_log(now, PCAP_MSG, msg);
            }
        }
    }
  
    for(i=0; i < ctx-> n_channels; i++) {
        free(ctx->channels[i].outgoing->buf);
        free(ctx->channels[i].pcap_handle);
        if (ctx->channels[i].nf_cap == NULL) {
            free(ctx->channels[i].nf_cap);
        }
    }
    free(param);
    free(ctx->tests);
    free(ctx->channels);
    free(ctx->snmp_channel_info);
    free(ctx->log);
    free(ctx->control_outgoing->buf);
    free(ctx->control_outgoing);
    free(ctx);

    oflops_log_close();
    fprintf(stderr, "-----------------------------------------------\n");
    fprintf(stderr, "---------------    Finished   -----------------\n");
    fprintf(stderr, "-----------------------------------------------\n");
    return 0;
}
