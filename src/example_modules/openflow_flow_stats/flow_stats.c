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
#include <poll.h>

#include "test_module.h"

#ifndef BUFLEN
#define BUFLEN 4096
#endif


#define TEST_DURATION 45

#define MIN_QUERY_DELAY 1000

#define LOG_FILE "of_flow_stat.log"

/*
 * Number of flow rules we send to the switch
 */
int flows = 128;
int flows_exponent, query_exponent;
int query = 64;
int query_delay = 1000000; //1 sec
char *network = "192.168.3.1";

/** The rate at which data will be send between the data ports (In Mbits per sec.).
*/
uint64_t datarate = 100;


time_t time_start = 0;
/** pkt sizes.
*/
uint64_t pkt_size = 1500;

// variable to store the state of the process
int finished = 0;
int poll_started = 0;

/*
 * calculated sending time interval (measured in usec).
 */
uint64_t data_snd_interval;

struct timeval stats_start;
int trans_id=0;

char *logfile = LOG_FILE;

struct entry {
    struct timeval snd,rcv;
    int ch, id;
    uint32_t nw_dst;
    TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};
TAILQ_HEAD(tailhead, entry) head;


uint64_t max_entry = (TEST_DURATION * SEC_TO_NSEC)/MIN_QUERY_DELAY;
struct stats_entry {
    struct timeval rcv,snd;
    int pkt_count;
} stats_counter[(TEST_DURATION * SEC_TO_NSEC)/MIN_QUERY_DELAY];

int stats_count = 0;

// control whether detailed packet information is printed
int print = 0;
int table = 0;
int pkt_in_count = 0; // counting how many packets where received over a
// specific channel
//the local mac address of the probe
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/**
 * \defgroup openflow_flow_stats openflow flow stats
 * \ingroup modules
 * The module benchmark the performance of the implementation of the openflow flow
 * statistics mechanism
 *
 * Parameters:
 *
 *  - flows}: The total number of unique flow that the module will
 * initialize the flow table of the switch. (default 128)
 *  - query}: The number of unique flows that the module will query the
 *   switch in each flow request. Because the matching method of the module is based
 * on the netmask field of the matching field. (default 64)
 *  - pkt\_size}:  This parameter can be used to control the length of the
 *   packets of the measurement probe. It allows indirectly to adjust the packet
 *   throughput of the experiment.
 *  - data\_rate}: The rate, in Mbps, of the variable probe. (default
 *       100Mbps)
 *  - print}: A parameter that defines whether the module will output full
 *   per packet details of the measurement probes. If this value is set to 1, then
 *   the module will print on a file called "of_flow_stat.log" for each capture packet a
 *   comma separated record with the timestamps of the generation and capture times of the
 *   packet, the packet id, the port at which the packet was captured and the flow id
 * of the flow that was used in order to switch the packet. (default 0)
 *  - table}: This parameter controls whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0). (default 0)
 *
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_flow_stats
 * get module name
 * @return name of module
 */
char * name()
{
    return "openflow_flow_stats_test";
}

/**
 * \ingroup openflow_flow_stats
 * configure module parameters
 * \param ctx data context of the module
 * \param config_str a space separated initilization string
 */
int init(struct oflops_context *ctx, char * config_str) {
    char *pos = NULL;
    char *param = config_str;
    char *value = NULL;
    double exponent;

    if (strcmp(ctx->log, DEFAULT_LOG_FILE) == 0) {
        strcpy(ctx->log, logfile);
    }
    fprintf(stderr, "Log file is %s.\n", ctx->log);

    // Set print mode.
    print = ctx->print;

    //init measurement queue
    TAILQ_INIT(&head);

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
        if(value != NULL) {
            if(strcmp(param, "flows") == 0) {
                flows = atoi(value);
                if(flows <= 0)
                    perror_and_exit("Invalid flow number",1);
            } else if(strcmp(param, "query") == 0) {
                //define the number of flows queried in each turn
                query = strtol(value, NULL, 0);
                if(query <= 0)
                    perror_and_exit("Invalid flow number",1);
                exponent = log2(query);
                if(exponent - floor(exponent) != 0) {
                    query = (int)pow(2, ceil(exponent));
                    printf("query size must be a power of 2. converting to %d\n", query);
                }
            } else if(strcmp(param, "pkt_size") == 0) {
                //packet size for the probes
                pkt_size = strtol(value, NULL, 0);
                if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))  {
                    perror_and_exit("Invalid packet size value", 1);
                }
            } else if(strcmp(param, "data_rate") == 0) {
                //multituple data rate
                datarate = strtol(value, NULL, 0);
                if((datarate <= 0) || (datarate > 10000))  {
                    perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
                }
                //time gap between querries in usec
            } else if(strcmp(param, "query_delay") == 0) {
                query_delay = strtol(value, NULL, 0);
                if(query_delay <= MIN_QUERY_DELAY) {
                    perror_and_exit("Invalid probe rate param", 1);
                }
                printf("query delay %d\n", query_delay);
                //should packet timestamp be printed
            } else if(strcmp(param, "print") == 0) {
                //parse int to get pkt size
                print = strtol(value, NULL, 0);
            }else if(strcmp(param, "table") == 0) {
                //parse int to get pkt size
                table = strtol(value, NULL, 0);
            } else {
                fprintf(stderr, "Invalid parameter:%s\n", param);
            }
            param = pos;
        }
    }

    //calculating interpacket gap
    data_snd_interval = (pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (datarate * MBITS_TO_BITS);
    fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
            (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
    fprintf(stderr, "sending %d flows, quering %d flows every %u nsec\n",
            flows, query, query_delay);


    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * calculate the statistics of the measurement probe and the statistic reply
 * \param ctx data context of the module
 */
int destroy(struct oflops_context *ctx) {
    char msg[1024];
    struct timeval now;
    struct entry *np;
    uint32_t mean, median, std;
    int min_id = INT_MAX;
    int max_id = INT_MIN;
    int ix = 0;
    int ch, i;
    float loss;
    double *data = NULL;
    double *stats_data = NULL;

    gettimeofday(&now, NULL);
    fprintf(stderr, "This is the destroy code of the module\n");
    del_traffic_generator(ctx, OFLOPS_DATA1);

    data = xmalloc(pkt_in_count * sizeof(double));
    for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
        if((np->ch > OFLOPS_DATA3) || ((np->ch < OFLOPS_DATA1))){
            printf("Invalid channel %d. skipping packet\n", np->ch);
            continue;
        }
        ch = np->ch - 1;
        if(print) {
            if(snprintf(msg, 1024, "%d:%lu:%ld.%06ld:%ld.%06ld:%d",
                        np->ch,
                        (long unsigned int)np->id,
                        (long unsigned int)np->snd.tv_sec,
                        (long unsigned int)np->snd.tv_usec,
                        (long unsigned int)np->rcv.tv_sec,
                        (long unsigned int)np->rcv.tv_usec,
                        time_diff(&np->snd, &np->rcv)
                        ) < 0)
                perror_and_exit("fprintf failed", 1);
            oflops_log(now, GENERIC_MSG, msg);
        }
        if( time_cmp(&np->snd, &np->rcv)> 0) {
            min_id = (np->id < min_id)?np->id:min_id;
            max_id = (np->id > max_id)?np->id:max_id;
            data[ix++] = time_diff(&np->snd, &np->rcv);
        }
        free(np);
    }

    if(ix > 0) {

        gsl_sort (data, 1, ix);
        mean = (uint32_t)gsl_stats_mean(data, 1, ix);
        std = (uint32_t)sqrt(gsl_stats_variance(data, 1, ix));
        median = (uint32_t)gsl_stats_median_from_sorted_data (data, 1, ix);
        loss = (float)ix/(float)(max_id - min_id);
        snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:count:%d",
                ch, mean, median, std, loss, ix);
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);
        }

    ix = 0;
    if(data!= NULL) {
        free(data);
        data = NULL;
    }
    free(data);
    stats_data = malloc(sizeof(double)*(stats_count));

    for (i = 0; i < trans_id; i++) {
        if(((stats_counter[i].rcv.tv_sec == 0) &&
                    (stats_counter[i].rcv.tv_usec == 0)) ||
                (ix >=  stats_count)) continue;
        stats_data[ix++]  = (double) time_diff(&stats_counter[i].snd, &stats_counter[i].rcv);
        snprintf(msg, 1024, "stats:%u:%d:%u.%06u:%u.%06u:%u",i,
                stats_counter[i].pkt_count,
                (uint32_t)stats_counter[i].snd.tv_sec,
                (uint32_t)stats_counter[i].snd.tv_usec,
                (uint32_t)stats_counter[i].rcv.tv_sec,
                (uint32_t)stats_counter[i].rcv.tv_usec,
                (uint32_t)time_diff(&stats_counter[i].snd, &stats_counter[i].rcv));
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);
    }

    if(ix > 0) {
        gsl_sort (stats_data, 1, ix);
        mean = (uint32_t)gsl_stats_mean(stats_data, 1, ix);
        std = (uint32_t)sqrt(gsl_stats_variance(stats_data, 1, ix));
        median = (uint32_t)gsl_stats_median_from_sorted_data(stats_data, 1, ix);
        loss = (float)ix/(float)(max_id - min_id);
        snprintf(msg, 1024, "statistics:stats:%u:%u:%u:%.04f:%d",
                mean, median, std, loss, ix);
        printf("%s\n", msg);
        oflops_log(now, GENERIC_MSG, msg);
    } else {
        oflops_log(now, GENERIC_MSG, "stats_stats:fail");
    }
    free(stats_data);
    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * the module initiliazes internal state of the module, inserts appropriate flows in flows
 * table and schedules appropriate events.
 * @param ctx pointer to opaque context
 */
int start(oflops_context * ctx)
{
    int i;
    struct timeval now;
    struct flow *fl = (struct flow*)xmalloc(sizeof(struct flow));
    char msg[1024];

    // a genric structure with which
    // we can create and send messages.
    void *b;

    //make filedescriptor blocking
    int saved_flags = fcntl(ctx->control_fd, F_GETFL);
    fcntl(ctx->control_fd, F_SETFL, saved_flags & ~O_NONBLOCK);

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);

    gettimeofday(&now, NULL);

    snprintf(msg, 1024, "Initializing module %s", name());
    oflops_log(now,GENERIC_MSG , msg);

    make_ofp_hello(&b);
    oflops_send_of_mesg(ctx, b);
    free(b);

    // send a features request, to stave off timeout (ignore response)
    make_ofp_feat_req(&b);
    oflops_send_of_mesg(ctx, b);
    free(b);

    // send a delete all message to clean up all flow tables.
    printf("cleaning up flow table...\n");
    make_ofp_flow_del(&b);
    oflops_send_of_mesg(ctx, b);
    free(b);

    //Send a singe rule to route the traffic we will generate
    bzero(fl, sizeof(struct flow));
    if (table)
        fl->mask =  OFPFW_IN_PORT | OFPFW_DL_DST | OFPFW_DL_SRC |
            (0 << OFPFW_NW_SRC_SHIFT) | (0 << OFPFW_NW_DST_SHIFT) |
            OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
            OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;
    else
        fl->mask = 0;
    fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
    fl->dl_type = htons(ETHERTYPE_IP);
    memcpy(fl->dl_src, data_mac, ETH_ALEN);
    memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
    fl->dl_vlan = 0xffff;
    fl->nw_proto = IPPROTO_UDP;
    fl->nw_src =  inet_addr("192.168.42.42");
    fl->nw_dst =  inet_addr(network);
    fl->tp_src = htons(8080);
    fl->tp_dst = htons(8080);

    printf("Sending new flow rules...\n");
    for(i=0; i< flows; i++) {
        make_ofp_flow_add(&b, fl, ctx->channels[OFLOPS_DATA2].of_port, 1, 1200);
        oflops_send_of_mesg(ctx, b);
        free(b);

        //calculate next ip
        fl->nw_dst =  htonl(ntohl(fl->nw_dst) + 1);
    }

    time_start = time(NULL);

    //Schedule end
    oflops_schedule_timer_event(ctx, TEST_DURATION, 0, BYESTR);

    //the event to request the flow statistics.
    oflops_schedule_timer_event(ctx, 2, 0, GETSTAT);

    flows_exponent = (int)floor(log2(flows));
    query_exponent = (int)log2(query);

    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Handle timer event:
 * - GETSTAT: send sta request
 * - BYESTR: terminate module
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te)
{
    void *b = NULL;
    char *str = te->arg;
    char msg[100];
    uint32_t flow_netmask;
    struct ofp_flow_stats_request *reqp;
    //send flow statistics request.
    if((strcmp(str, GETSTAT) == 0) && (finished != 1)) {
        sprintf(msg, "%d", trans_id);

        //log start of measurement
        if(trans_id == 0) {
            printf("flow stats request send with xid %s\n", msg);
            memcpy(&stats_start, &te->sched_time, sizeof(struct timeval));
            poll_started = 1;
        }
        if (trans_id < max_entry){
            memcpy(&stats_counter[trans_id].snd, &te->sched_time, sizeof(struct timeval));
            bzero(&stats_counter[trans_id].rcv, sizeof(struct timeval));
            //create generic statrequest message
            make_ofp_flow_get_stat(&b, trans_id++);
            reqp = (struct ofp_flow_stats_request *)(b + sizeof(struct ofp_stats_request));

            //set the query mask
            reqp->match.wildcards = htonl(OFPFW_IN_PORT |  OFPFW_DL_VLAN |  OFPFW_DL_SRC |
                    OFPFW_DL_DST |  OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC |
                    OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS | OFPFW_TP_DST |
                    (32 << OFPFW_NW_SRC_SHIFT) | ((query_exponent) << OFPFW_NW_DST_SHIFT));

            //calculate netowrk mask for the query
            flow_netmask = (ntohl(inet_addr(network)) & ((0xFFFFFFFF)<<flows_exponent));
            if(query_exponent < flows_exponent)
                flow_netmask += (stats_count%(0x1 <<(flows_exponent-query_exponent))
                        << query_exponent);

            reqp->match.nw_dst = htonl(flow_netmask);

            //send stats request
            oflops_send_of_mesg(ctx, b);
            free(b);

            if (TEST_DURATION - ((time(NULL) - time_start)) > 2) {
                //schedule next query
                oflops_schedule_timer_event(ctx, query_delay/SEC_TO_NSEC,
                                            query_delay%SEC_TO_NSEC, GETSTAT);
            }
        }
    } else if (strcmp(str, BYESTR) == 0) {
        //terminate programm execution
        finished = 1;
        printf("terminating test....\n");
        oflops_end_test(ctx,1);
    }
    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc channel ID
 * @param filter return buffer for the filter
 * @param buflen length of buffer
 */
int get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, cap_filter **filter)
{
    if(ofc == OFLOPS_CONTROL) {
        *filter = malloc(sizeof(cap_filter));
        memset(*filter, 0, sizeof(cap_filter));
        return 1;
    } else if (ofc == OFLOPS_DATA2) {
        *filter = malloc(sizeof(cap_filter));
        memset(*filter, 0, sizeof(cap_filter));
        (*filter)->proto = "udp";
		(*filter)->dst = inet_network("192.168.3.2");
		(*filter)->dst_mask = 0xffffffff;
        return 1;
    }
    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * Handle pcap event on data channels only
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(oflops_context *ctx, struct pcap_event *pe,
        enum oflops_channel_name ch) {
    struct pktgen_hdr *pktgen;
    struct flow fl;

    if ((ch == OFLOPS_DATA2) && (finished == 0)) {
        if(poll_started == 0) {
            return 0;
        }
        pktgen = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, pe->pcaphdr.caplen, &fl);
        if(pktgen == NULL) {
            printf("Failed to parse packet header\n");
            return 0;
        }
        struct entry *n1 = xmalloc(sizeof(struct entry));
        n1->snd.tv_sec = pktgen->tv_sec;
        n1->snd.tv_usec = pktgen->tv_usec;
        n1->rcv.tv_sec = pktgen->tv_rcv_sec;
        n1->rcv.tv_usec = pktgen->tv_rcv_usec;
        n1->id = htons(pktgen->seq_num);
        n1->ch = ch;
        n1->nw_dst = fl.nw_dst;
        pkt_in_count ++;
        TAILQ_INSERT_TAIL(&head, n1, entries);
    }
    return 0;
}

/**
 * \ingroup openflow_flow_stats
 * generate traffic on data plane
 * \param ctx data context of the module.
 */
int
handle_traffic_generation (oflops_context *ctx) {
    struct traf_gen_det det;
    char *str_ip;
    struct in_addr ip;
    init_traf_gen(ctx);

    //background data
    strcpy(det.src_ip,"192.168.42.42");
    strcpy(det.dst_ip_min, network);

    ip.s_addr = ntohl(inet_addr(network));
    ip.s_addr += (flows -1);
    ip.s_addr = htonl(ip.s_addr);
    str_ip = inet_ntoa(ip);
    strcpy(det.dst_ip_max, str_ip);
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);
    strcpy(det.mac_dst_base, "00:15:17:7b:92:0a");

    det.mac_dst_count = 1;
    det.vlan = 0x0;
    det.vlan_p = 0;
    det.vlan_cfi = 0;
    det.udp_src_port = 8080;
    det.udp_dst_port = 8080;
    det.pkt_size = pkt_size;
    det.delay = data_snd_interval;
    strcpy(det.flags, "");
    add_traffic_generator(ctx, OFLOPS_DATA1, &det);
    start_traffic_generator(ctx);
    return 1;
}

/**
 * \ingroup openflow_flow_stats
 * handle openflow stats reply and openflow errors
 * \param ctx data context of the module
 * \param ofph pointer to the data of the packet
 */
int
of_event_other(oflops_context *ctx, const struct ofp_header * ofph) {
    struct timeval now;
    char msg[100];
    struct ofp_error_msg *err_p;

    if((ofph->type == OFPT_STATS_REPLY) && (finished == 0)) {
        struct ofp_stats_reply *ofpr = (struct ofp_stats_reply *)ofph;
        stats_counter[ntohl(ofph->xid)].pkt_count++;
        if(ntohs(ofpr->type) == OFPST_FLOW) {
            if(!(ntohs(ofpr->flags) & OFPSF_REPLY_MORE)) {
                gettimeofday(&now, NULL);
                memcpy(&stats_counter[ntohl(ofph->xid)].rcv, &now, sizeof(struct timeval));
                stats_count++;
            }
        }
    } else if (ofph->type == OFPT_ERROR) {
        err_p = (struct ofp_error_msg *)ofph;
        sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
        perror_and_exit(msg, 1);
    }
    return 0;
}
