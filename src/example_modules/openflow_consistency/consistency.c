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
#include <arpa/inet.h>

#include "test_module.h"

/** \defgroup openflow_consistency openflow consistency
 *   \ingroup modules
 * \brief Openflow flow insertion test module.
 *
 * A module to measure the consistency between information known by the
 * controller, and the flows.  When a switch announces that flows are
 * installed, are they effectively installed ? How many packets can still go
 * through ?
 *
 * Parameters:
 *
 * - pkt_size: This parameter can be used to control the length of the
 * packets of the measurement probe. It allows indirectly to adjust the packet
 * throughput of the experiment. The parameter uses bytes as measurement unit.
 * The parameter applies for both measurement probes.
 * - data_rate: The rate of the sequential data, measured in Mbps.
 * - flows:  The number of unique flows that the module will
 * update/insert.
 * - table:  This parameter controls whether the inserted flow will be
 *  a wildcard(value of 1) or exact match(value of 0). For the wildcard flows, the
 *  module wildcards all of the fields except the destination IP address.
 * - print: This parameter enables the measurement module to print
 *  extended per packet measurement information. The information is printed in a
 *  separate CSV file, named "of\_add\_flow.log".
 *
 *
 * @author Rémi Oudin
 * @date 2018
 *
 */

/**
 * \ingroup openflow_consistency
 * get the name of the module
 * \return name of module
 */
char * name() {
    return "openflow_consistency";
}

#define RULE_DURATION 120

//logging filename
#define LOG_FILE "of_consistency.log"
char *logfile = LOG_FILE;


/**
 * Some constants to help me with conversions
 */



// packet generation loca variables
uint64_t linkrate = 10000;
uint64_t datarate = 100;
uint32_t pkt_size = 1500;
uint64_t data_snd_interval;
uint32_t insert_delay = 0;
int table = 0;
char *network = "192.168.2.0";
int flows = 100;
struct flow *fl_probe;
/**
 * A variable to inform when the module is over.
 */
int finished, first_pkt = 0;
//control if a per packet measurement log is created on destroy
int print = 0;
struct timeval flow_mod_timestamp, pkt_timestamp;
int send_flow_mod = 0, stored_flow_mod_time = 0;
int count[] = {0,0,0};

char *cli_param;

char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
    struct timeval snd,rcv;
    int id;
    TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};
TAILQ_HEAD(tailhead, entry) head;


int *ip_received;
int ip_received_count;

/**
 * \ingroup openflow_consistency
 * Initialize mac address of the measurement probe, setup connection
 * channel, insert initial flow set and schedule events.
 * @param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
    fl_probe = (struct flow*)xmalloc(sizeof(struct flow));
    flow_t *mask =  xmalloc(sizeof(flow_t));
    struct timeval now;
    int i, inc = 1;
    char msg[1024];
    struct in_addr ip_addr;
    void *b;

    //init module packet queue
    TAILQ_INIT(&head);


    //Initialize pap-based  tcp flow reassembler for the communication
    //channel
    msg_init();
    bzero(&flow_mod_timestamp, sizeof(struct timeval));
    snprintf(msg, 1024,  "Intializing module %s", name());

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, local_mac);
    get_mac_address(ctx->channels[OFLOPS_DATA2].dev, data_mac);

    //log when I start module
    oflops_gettimeofday(ctx, &now);
    oflops_log(now, GENERIC_MSG, msg);
    oflops_log(now,GENERIC_MSG , cli_param);

    //start openflow session with switch
    make_ofp_hello(&b);
    oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);

    //start openflow session with switch
    make_ofp_hello(&b);
	((struct ofp_header *)b)->type = OFPT_FEATURES_REQUEST;
    oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);

    //send a message to clean up flow tables.
    printf("cleaning up flow table...\n");
    make_ofp_flow_del(&b);
    oflops_send_of_mesg(ctx, b);
    free(b);

    make_ofp_table_miss(&b);
    oflops_send_of_mesg(ctx, b);
    free(b);

    /**
     * Send flow records to start switching packets.
     */

    printf("XXXXXXXXXXXXX starting table = %d XXXXXXXXXX\n", table);
    memset(fl_probe, 0, sizeof(flow_t));
    memset(mask, 1, sizeof(flow_t));
    if (table != 0) {
        mask->in_port = 0;
        mask->dl_type = 0;
        memset(&mask->dl_dst, 0, sizeof(uint8_t[6]));
        memset(&mask->dl_src, 0, sizeof(uint8_t[6]));
    }
    fl_probe->in_port = htonl(ctx->channels[OFLOPS_DATA1].of_port);
    fl_probe->dl_type = htons(ETHERTYPE_IP);
    memcpy(fl_probe->dl_src, data_mac, 6);
    memcpy(fl_probe->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
    fl_probe->dl_vlan = 22;
    fl_probe->nw_proto = IPPROTO_UDP;
    fl_probe->nw_src =  inet_addr("192.168.42.42");
    ip_addr.s_addr = inet_addr(network);
    ip_addr.s_addr =  ntohl(ip_addr.s_addr);
    fl_probe->tp_src = htons(8080);
    fl_probe->tp_dst = htons(8080);

    for(i=0; i< flows; i++) {
        fl_probe->nw_dst =  htonl(ip_addr.s_addr);
        make_ofp_flow_add(&b, fl_probe, mask, ctx->channels[OFLOPS_DATA2].of_port, -1, 0, 1200);
        ((struct ofp_flow_mod *)b)->priority = htons(11);
        ((struct ofp_flow_mod *)b)->flags = 0;
        oflops_send_of_mesg(ctx, b);
        free(b);
        ip_addr.s_addr += inc;
    }
    /**
     * Scheduling events
     */
    //send the flow modyfication command in 30 seconds.
    oflops_schedule_timer_event(ctx, 10, 0, SND_ACT);

    //end process
    oflops_schedule_timer_event(ctx, 40, 0, BYESTR);

    return 0;
}

/**
 * \ingroup openflow_consistency
 * Calculate measurement probe stats and output them.
 * \param ctx module context
 */
int destroy(oflops_context *ctx) {
    struct entry *np;
    struct timeval now;
    char msg[1024];
    int true_number = 0;

    //get what time we start printing output
    oflops_gettimeofday(ctx, &now);

    for(np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
        if (time_diff(&flow_mod_timestamp, &np->rcv) >= 0) {
            true_number++;
            if(print) {
                if(snprintf(msg, 1024, "%lu %ld.%06ld %ld.%06ld",
                            (long unsigned int)np->id,
                            (long unsigned int)np->snd.tv_sec,
                            (long unsigned int)np->snd.tv_usec,
                            (long unsigned int)np->rcv.tv_sec,
                            (long unsigned int)np->rcv.tv_usec) < 0)
                    perror_and_exit("fprintf fail", 1);
                else {
                    oflops_log(now, GENERIC_MSG, msg);
                    memset(msg, 0, sizeof(msg));
                    free(np);
                }
            }
        }
    }


    snprintf(msg, 1024, "statistics:rate:%lu:count:%d", datarate, true_number);
    oflops_log(now, GENERIC_MSG, msg);
    printf("statistics:rate:%lu:count:%d\n", datarate, true_number);


    return 0;
}

/**
 * \ingroup openflow_consistency
 * Handle timer event.
 * - BYESTR: terminate module execution
 * - SND_ACT: send new flows to switch
 * @param ctx context of module
 * @param te event data
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
    char *str = te->arg;
    int i, inc=1;
    void *b;
    struct in_addr ip_addr;
    flow_t *mask = malloc(sizeof(flow_t));
    flow_t *fl = malloc(sizeof(flow_t));

    //terminate process
    if (strcmp(str, BYESTR) == 0) {
        printf("cleaning up flow table...\n");
        make_ofp_flow_del(&b);
        oflops_send_of_mesg(ctx, b);
        free(b);
        finished = 1;

        printf("terminating test....\n");
        oflops_end_test(ctx,1);
        return 0;
    } else if (strcmp(str, SND_ACT) == 0) {
        //first create new rules
        send_flow_mod = 1;
        memset(fl, 0, sizeof(flow_t));
        memset(mask, 1, sizeof(flow_t));
        oflops_gettimeofday(ctx, &flow_mod_timestamp);
        if (table != 0) {
            mask->in_port = 0;
            mask->dl_type = 0;
            memset(&mask->dl_dst, 0, sizeof(uint8_t[6]));
            memset(&mask->dl_src, 0, sizeof(uint8_t[6]));
        }
        printf("START FLOW MOD\n");
        oflops_log(flow_mod_timestamp, GENERIC_MSG, "START_FLOW_MOD");
        fl->in_port = htonl(ctx->channels[OFLOPS_DATA1].of_port);
        fl->dl_type = htons(ETHERTYPE_IP);
        memcpy(fl->dl_src, data_mac, 6);
        memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);
        fl->dl_vlan = 22;
        fl->nw_proto = IPPROTO_UDP;
        fl->nw_src =  inet_addr("192.168.42.42");
        ip_addr.s_addr = inet_addr(network);
        ip_addr.s_addr =  ntohl(ip_addr.s_addr);
        fl->tp_src = htons(8080);
        fl->tp_dst = htons(8080);

        printf("sending flow modifications ....\n");
        oflops_gettimeofday(ctx, &pkt_timestamp);
        for(i=0; i< flows; i++) {
            fl->nw_dst =  htonl(ip_addr.s_addr);
            make_ofp_flow_modify_output_port(&b, fl, mask,
                    ctx->channels[OFLOPS_DATA1].of_port, -1, 1200);
            ((struct ofp_flow_mod *)b)->priority = htons(17);
            ((struct ofp_flow_mod *)b)->flags = 0;
            oflops_send_of_mesg(ctx, b);
            free(b);
            ip_addr.s_addr += inc;
        }

        memset(&flow_mod_timestamp, 0, sizeof(struct timeval));
        make_ofp_hello(&b);
        ((struct ofp_header *)b)->type = OFPT_BARRIER_REQUEST;
        oflops_send_of_mesg(ctx, b);
        free(b);

    }
    return 0;
}

/**
 * \ingroup openflow_consistency
 * Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap * @param buflen length of buffer
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, cap_filter **filter) {
    if ((ofc == OFLOPS_DATA2)) {
		*filter = (cap_filter *)malloc(sizeof(cap_filter));
		bzero(*filter, sizeof(cap_filter));
		return 1;
    }
    return 0;
}

/**
 * \ingroup openflow_consistency
 * Handle event on data plane
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
    struct pktgen_hdr *pktgen;
    struct entry *n1;
    struct flow fl;

    if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2)) {
        if((pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl)) == NULL) {
            printf("%s, %d:  Failed to parse packet\n", ctx->channels[ch].dev, ch);
            return 0;
        }

        if ((stored_flow_mod_time == 1) &&  (ch == OFLOPS_DATA2)) {
            ip_received_count++;
            n1 = malloc(sizeof(struct entry));

            n1->snd.tv_sec = pktgen->tv_sec;
            n1->snd.tv_usec = pktgen->tv_usec;
            n1->rcv.tv_sec = pktgen->tv_rcv_sec;
            n1->rcv.tv_usec = pktgen->tv_rcv_usec;
            n1->id = pktgen->seq_num;
            TAILQ_INSERT_TAIL(&head, n1, entries);
            printf("Received errorous packet\n");
        } else if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2)) {
            if(pktgen->seq_num % 1000000 == 0)
                printf("data packet received %d port %d\n", ntohl(pktgen->seq_num), ch);
        }
    }
    return 0;
}

/**
 * \ingroup openflow_consistency
 * Record barrier reply message timestamp and openflow message.
 * \param ctx context of the module
 * \param ofph data of the openflow message
 */
int
of_event_other(oflops_context *ctx, struct ofp_header *ofph) {
    struct ofp_error_msg *err_p = NULL;
    struct timeval now;
    char msg[1024];
    gettimeofday(&now, NULL);
    switch(ofph->type) {
        case OFPT_ERROR:
            err_p = (struct ofp_error_msg *)ofph;
            snprintf(msg, 1024, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
            oflops_log(now, OFPT_ERROR_MSG, msg);
            fprintf(stderr, "%s\n", msg);
            break;
        case OFPT_BARRIER_REPLY:
            oflops_gettimeofday(ctx, &flow_mod_timestamp);
            stored_flow_mod_time = 1;
            oflops_log(now, GENERIC_MSG, "BARRIER_REPLY");
            oflops_log(now, GENERIC_MSG, msg);
            break;
	}
    return 0;
}

/**
 * \ingroup openflow_consistency
 * printf packet in events.
 * \param ctx context of the module
 * \param pkt_in data of the pkt_in message
 */
int
of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pkt_in) {
    switch(pkt_in->reason) {
        case  OFPR_NO_MATCH:
               // printf("OFPR_NO_MATCH: %d bytes\n", ntohs(pkt_in->total_len));
            break;
        case OFPR_ACTION:
            printf("OFPR_ACTION: %d bytes\n", ntohs(pkt_in->total_len));
            break;
        default:
            printf("Unknown reason: %d bytes\n", ntohs(pkt_in->total_len));
    }
    return 0;
}

/**
 * \ingroup openflow_consistency
 * reply to openflow requests so that the control channel will not close.
 * \param ctx context data of the module.
 * \param ofph data of the openflow echo request message.
 */
int
of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph) {
    void *b;

    make_ofp_hello(&b);
    ((struct ofp_header *)b)->type = OFPT_ECHO_REPLY;
    ((struct ofp_header *)b)->xid = ofph->xid;
    oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);
    return 0;
}

/**
 * \ingroup openflow_consistency
 * start generation of 2 measrument probe(constant and variable)
 * \param ctx data of the context of the module.
 */
int
handle_traffic_generation (oflops_context *ctx) {
    struct traf_gen_det det;
    struct in_addr ip_addr;

    init_traf_gen(ctx);

    //background data
    strcpy(det.src_ip,"192.168.42.42");
    strcpy(det.dst_ip_min,network);
    ip_addr.s_addr = ntohl(inet_addr(network));
    ip_addr.s_addr += (flows -1);
    ip_addr.s_addr = htonl(ip_addr.s_addr);
    strcpy(det.dst_ip_max,  inet_ntoa(ip_addr));
    if(ctx->trafficGen == PKTGEN)
        strcpy(det.mac_src,"00:00:00:00:00:00");
    else
        snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)data_mac[0], (unsigned char)data_mac[1],
                (unsigned char)data_mac[2], (unsigned char)data_mac[3],
                (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

    strcpy(det.mac_dst_base,"00:15:17:7b:92:0a");
	det.mac_dst_count = 1;
    det.vlan = 22;
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
 * \ingroup openflow_consistency
 * Initialization code of the module parameter.
 * \param ctx data of the context of the module.
 * \param config_str the initiliazation string of the module.
 */
int init(struct oflops_context *ctx, char * config_str) {

    char ***params;
    struct timeval now;
    int ix = 0;

    if (strcmp(ctx->log, DEFAULT_LOG_FILE) == 0) {
        strcpy(ctx->log, logfile);
    }
    fprintf(stderr, "Log file is %s.\n", ctx->log);

    // Set print mode.
    print = ctx->print;

    gettimeofday(&now, NULL);

    cli_param = strdup(config_str);
	params = run_tokenizer(config_str, ' ', '=');

	while(params[ix] != NULL) {
		if((params[ix][0] != NULL) && (strcmp(params[ix][0], "pkt_size") == 0)) {
			//parse int to get pkt size
			pkt_size = strtol(params[ix][1], NULL, 0);
			if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
				perror_and_exit("Invalid packet size value", 1);
		}  else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "data_rate") == 0)) {
			//parse int to get measurement data rate
			datarate = strtol(params[ix][1], NULL, 0);
			if((datarate <= 0) || (datarate >= 10010))
				perror_and_exit("Invalid data rate param(Value between 1 and 10010)", 1);
		}  else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "link_rate") == 0)) {
			//parse int to get measurement probe rate
			linkrate = strtol(params[ix][1], NULL, 0);
			if((linkrate <= 0) || (linkrate >= 10010))
				perror_and_exit("Invalid link rate param(Value between 1 and 10010)", 1);
		} else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "table") == 0)) {
			//parse int to get pkt size
			table = strtol(params[ix][1], NULL, 0);
			if((table < 0) || (table > 2))
				perror_and_exit("Invalid table number", 1);
		} else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "flows") == 0)) {
			//parse int to get pkt size
			flows = strtol(params[ix][1], NULL, 0);
			if(flows <= 0)
				perror_and_exit("Invalid flow number", 1);
		} else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "print") == 0)) {
			//parse int to get pkt size
			print = strtol(params[ix][1], NULL, 0);
		} else
			fprintf(stderr, "Invalid parameter:%s\n", params[ix][0]);
		ix++;
	}

	destroy_tokenizer(params);

    //calculate sendind interval
    data_snd_interval = ((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (datarate * MBITS_TO_BITS)) -
        ((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (linkrate * MBITS_TO_BITS));
    data_snd_interval = (data_snd_interval < 9)?0:data_snd_interval;
    fprintf(stderr, "Sending data interval : %u nsec (pkt_size: %u bytes, rate: %u Mbits/sec %u Mbits/sec)\n",
            (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate, (uint32_t) linkrate);
    return 0;
}
