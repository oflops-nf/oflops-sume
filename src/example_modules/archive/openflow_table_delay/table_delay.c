#include <arpa/inet.h>

#include "test_module.h"

/** \defgroup openflow_table_delay table delay module
 * \ingroup modules
 * Packet in module.
 * This module benchmarks the implementation of table lookups in the various
 * switch tables.
 *
 * Parameters:
 *
 * - pkt_size: This parameter can be used to control the length of
 * packets of the measurement probe, measured in bytes. Thus, together with the
 *   rate parameter, it allows indirectly to adjust the packet throughput of the
 * experiment. (default 1500 bytes)
 * - data_rate: The rate of the measurement probe measured in Mbps.
 * (default 10Mbps)
 * - link_rate : The rate of the underlying link
 * - table: The parameter define whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0).  (default 1)
 * - action:  A comma separate string of entries of the format
 *   action_id/action_value. E.g. a value of `b/1010,0/2` defines that the action
 *   will modify the tcp/udp port of the matching packet to a value of 1010 and the
 * packet will be output on port 2. (default no action)
 *
 * Copyright (C) Computer Laboratory, University of Cambridge, 2014
 * @author crotsos
 * @date December, 2014
 *
 */

/**
 * \ingroup openflow_table_delay
 * @return name of module
 */
const char * name() {
	return "openflow_table_delay";
}


//logging filename
#define LOG_FILE "of_table_delay.log"




int64_t datarate = 100;
int64_t linkrate = 100;
int64_t data_snd_interval;

/**
 * Probe packet size
 */
uint32_t pkt_size = 180;

int count[] = {0,0,0}; // counting how many packets where received over a
					   // specific channel

uint32_t flows = 30;
char *cli_param;

/**
 * storing the argument list passed to the module
 */
char* logfile = LOG_FILE;
int print = 0;

//the local mac address of the probe
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

TAILQ_HEAD(tailhead, entry) head;

int append_action(int action, const char *action_param);

/**
 * \ingroup openflow_table_delay
 * Initializate flow table and schedule events
 * \param ctx pointer to opaque context
 */
int
start(oflops_context * ctx) {
	struct flow fl; 
	void *b; //somewhere to store message data
	int res;
	struct timeval now;  //init measurement queue
	TAILQ_INIT(&head);
	uint32_t counter = 0;
    flow_t *mask;
    memset(mask, 1, sizeof(flow_t));

	//init logging service
	msg_init();

	//log when I start module
	oflops_gettimeofday(ctx, &now);
	oflops_log(now, GENERIC_MSG, "Intializing module openflow_action_measurement");

	get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);

	make_ofp_hello(&b);
	res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
	free(b);

	//send a message to clean up flow tables.
	printf("cleaning up flow table...\n");
	res = make_ofp_flow_del(&b);
	res = oflops_send_of_mesgs(ctx, b, res);
	free(b);

	/**
	 * prepare mac address
	 * */
	memcpy(fl.dl_dst, "\xfe\xff\x00\x00\x00\x00", ETH_ALEN);

	/**
	 * Send flow records to start routing packets.
	 */
	printf("Sending new flows...\n");
	bzero(&fl, sizeof(struct flow));
    mask->in_port = 0;
    memset(&mask->dl_src, 0, ETH_ALEN);
    mask->dl_type = 0;
    mask->nw_proto = 0;
    mask->nw_dst = 0;
    mask->nw_src = 0;
    mask->tp_src = 0;
    mask->tp_dst = 0;
	memcpy(fl.dl_dst, "\xfe\xff\xff\xff\xff\xff", ETH_ALEN);
	fl.dl_vlan = htons(0x1);
	for (counter = 0; counter < flows; counter++) {	
	   memcpy((fl.dl_dst + 2), (void *)&counter, sizeof(uint32_t));
	   // make_ofp_flow_add_actions(&b, &fl, actions, action_len, -1, 60);
	   make_ofp_flow_add(&b, &fl, mask, ctx->channels[OFLOPS_DATA2].of_port, -1, 0, 60);
	   res = oflops_send_of_mesg(ctx, b);
	   free(b);
   }

	/**
	 * Shceduling events
	 */
	//get port and cpu status from switch
	oflops_schedule_timer_event(ctx, 1, 0, SNMPGET);

	//end process
	oflops_schedule_timer_event(ctx, 10, 0, BYESTR);
	return 0;
}

/**
 * \ingroup openflow_table_delay
 * calculate the stats of the measurement probes.
 * \param ctx data context of the module.
 */
int
destroy(oflops_context *ctx) {
	char msg[1024];
	struct timeval now;
	FILE *out = fopen(logfile, "w");
	struct entry *np;
	int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
	int ix[] = {0,0,0};
	int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch;
	uint32_t mean, std, median;
	float loss;
	double *data[3];

	gettimeofday(&now, NULL);
	printf("destroying code\n");

	//insert delay
	for(ch = 0; ch < 3; ch++)
		data[ch] = xmalloc(count[ch]*sizeof(double));

	for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
		ch = np->ch - 1;
		min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
		max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
//		if (time_diff(&np->snd, &np->rcv) > 1) 
//			continue;
		data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
		if(print)
			if(fprintf(out, "%ld %ld.%09ld %ld.%09ld %d\n",
						(long unsigned int)np->id,
						(long unsigned int)np->snd.tv_sec,
						(long unsigned int)np->snd.tv_usec,
						(long unsigned int)np->rcv.tv_sec,
						(long unsigned int)np->rcv.tv_usec,  np->ch) < 0)
				perror_and_exit("fprintf fail", 1);
		//release memory
		free(np);
	}

	for(ch = 0; ch < 3; ch++) {
		if(ix[ch] == 0) continue;
		gsl_sort (data[ch], 1, ix[ch]);
		mean = (uint32_t)gsl_stats_mean(data[ch], 1, ix[ch]);
		std = (uint32_t)sqrt(gsl_stats_variance(data[ch], 1, ix[ch]));
		median = (uint32_t)gsl_stats_median_from_sorted_data (data[ch], 1, ix[ch]);
		loss = (float)ix[ch]/(float)(max_id[ch] - min_id[ch]);

		//print summarization data
		snprintf(msg, 1024, "statistics:port:%d:%u:%u:%u:%.4f:%d",
				ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
		printf("statistics:port:%d:%u:%u:%u:%.4f:%d\n",
				ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
		oflops_log(now, GENERIC_MSG, msg);
	}

	return 0;
}

/**
 * \ingroup openflow_table_delay
 * Handle timer event
 * - BYESTR: terminate module
 * - SND_ACT: send measured action
 * - SNMPGET: query snmp stats
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
	char *str = te->arg;
	int i;
	
	//terminate process
	if (strcmp(str, BYESTR) == 0) {
		printf("terminating test....\n");
		oflops_end_test(ctx,1);
		return 0;
	} else if(strcmp(str, SNMPGET) == 0) {
		for(i=0;i<ctx->cpuOID_count;i++) {
			oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);
		}
		for(i=0;i<ctx->n_channels;i++) {
			oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
			oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
		}
		oflops_schedule_timer_event(ctx, 5, 0, SNMPGET);
	}
	return 0;
}

/**
 * \ingroup openflow_action_dela
 * setup a filter on data channels only
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int 
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc, cap_filter **filter)
{
	// Just define a single rule
    if (ofc == OFLOPS_DATA2) {
		*filter = (cap_filter *)malloc(sizeof(cap_filter));
		bzero(*filter, sizeof(cap_filter));
		filter[0]->dst = 0x0a010102;
		filter[0]->dst_mask = 0xffffffff;
     return 1;
    }
    return 0;
}

/**
 * \ingroup openflow_action_dela
 * Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int
handle_pcap_event(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch) {
	struct pktgen_hdr *pktgen;
	struct flow fl;

	if ((ch == OFLOPS_DATA1) || (ch == OFLOPS_DATA2) || (ch == OFLOPS_DATA3)) {
		if (count[ch - 1] % 1000000 == 0)
			printf("got %d packet on port %d\n", count[ch-1], ch);
		pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl);
		if(pktgen == NULL) {
			printf("Failed to parse measurement packet\n");
			return 0;
		}

		struct entry *n1 = malloc(sizeof(struct entry));
		n1->snd.tv_sec = pktgen->tv_sec;
		n1->snd.tv_usec = pktgen->tv_usec;
		memcpy(&n1->rcv, &pe->pcaphdr.ts, sizeof(struct timeval));
		n1->id = pktgen->seq_num;
		n1->ch = ch;
		count[ch - 1]++;
		TAILQ_INSERT_TAIL(&head, n1, entries);
	}
	return 0;
}

/**
 * \ingroup openflow_table_delay
 * reply to echo requests
 * \param ctx data context of the module
 * \param ofph pointer to data of the echo packet
 */
int
of_event_echo_request(oflops_context *ctx, const struct ofp_header * ofph) {
	struct ofp_header * ofp_reply = xmalloc(sizeof(struct ofp_header));
	memcpy(ofp_reply, ofph, sizeof(struct ofp_header));
	ofp_reply->type = OFPT_ECHO_REPLY;
	oflops_send_of_mesgs(ctx, (void *)ofp_reply, sizeof(struct ofp_header));
	return 0;
}

/**
 * \ingroup openflow_table_delay
 * handle asynch. snmp replies
 * \param ctx data context of module
 * \param se snmp data
 */
int
handle_snmp_event(oflops_context * ctx, struct snmp_event * se) {
	netsnmp_variable_list *vars;
	int len = 1024;
	char msg[1024], out_buf[1024];
	struct timeval now;
	int i;
	gettimeofday(&now, NULL);

	for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
		snprint_value(msg, len, vars->name, vars->name_length, vars);
		for (i = 0; i < ctx->cpuOID_count; i++) {
			if((vars->name_length == ctx->cpuOID_len[i]) &&
					(memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
				snprintf(out_buf, len, "cpu:%s", msg);
				oflops_log(now, SNMP_MSG, out_buf);
			}
		}

		for(i=0;i<ctx->n_channels;i++) {
			if((vars->name_length == ctx->channels[i].inOID_len) &&
					(memcmp(vars->name, ctx->channels[i].inOID,
							ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
				snprintf(out_buf, len, "port %d : rx %s pkts",
						(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
				oflops_log(now, SNMP_MSG, out_buf);
				break;
			}

			if((vars->name_length == ctx->channels[i].outOID_len) &&
					(memcmp(vars->name, ctx->channels[i].outOID,
							ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
				snprintf(out_buf, len, "port %d : tx %s pkts",
						(int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
				oflops_log(now, SNMP_MSG, out_buf);
				break;
			}
		} //for
	}// if cpu
	return 0;
}

/**
 * \ingroup openflow_table_delay
 * Traffic generation methods
 * \param ctx data context of module
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;

  init_traf_gen(ctx);
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"10.1.1.2");
  strcpy(det.dst_ip_max,"10.1.1.2");
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
  else
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)data_mac[0], (unsigned char)data_mac[1],
        (unsigned char)data_mac[2], (unsigned char)data_mac[3],
        (unsigned char)data_mac[4], (unsigned char)data_mac[5]);
  printf("src mac %s\n", det.mac_src );
  strcpy(det.mac_dst_base, "fe:ff:00:00:00:00");
  det.mac_dst_count = flows;
  det.vlan = 1;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.pkt_count = 0;
  det.udp_src_port = 1;
  det.udp_dst_port = 100;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);

//  strcpy(det.dst_ip_min,"10.1.1.3");
//  strcpy(det.dst_ip_max,"10.1.1.3");
//  add_traffic_generator(ctx, OFLOPS_DATA2, &det);
//
//  strcpy(det.dst_ip_min,"10.1.1.4");
//  strcpy(det.dst_ip_max,"10.1.1.4");
//  add_traffic_generator(ctx, OFLOPS_DATA3, &det);

  start_traffic_generator(ctx);
  return 1;
}

/**
 * \ingroup openflow_table_delay
 * Initialization code with parameters
 * @param ctx
 */
int 
init(oflops_context *ctx, char * config_str) {
	char ***params;
	char *param = config_str;
	int ix = 0;

    if (strcmp(ctx->log, DEFAULT_LOG_FILE) == 0) {
        strcpy(ctx->log, logfile);
    }
    fprintf(stderr, "Log file is %s.\n", ctx->log);

    // Set print mode.
    print = ctx->print;
    

	cli_param = strdup(config_str);
	params = run_tokenizer(config_str, ' ', '=');

	while (params[ix] != NULL) {
		if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "pkt_size") == 0) ) {
			//parse int to get pkt size
			pkt_size = strtol(params[ix][1], NULL, 0);
			if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
				perror_and_exit("Invalid packet size value", 1);
		} else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "flows") == 0)) {
			//parse int to get rate of background data
			flows = strtol(params[ix][1], NULL, 0);
		}  else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "data_rate") == 0)) {
			//parse int to get rate of background data
			datarate = strtol(params[ix][1], NULL, 0);
			if((datarate > 10010))
				perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
		} else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "link_rate") == 0)) {
			//parse int to get rate of background data
			linkrate = strtol(params[ix][1], NULL, 0);
			if((linkrate > 10010))
				perror_and_exit("Invalid link rate param(Values between 1 and 1010)", 1);
		} else if ((params[ix][0] != NULL) && (strcmp(params[ix][0],  "print") == 0)) {
			printf("printing data\n");
			//parse int to check whether per packet statistics should be stored
			print = strtol(params[ix][1], NULL, 0);
		} else
			fprintf(stderr, "Invalid parameter:%s\n", param);

		ix++;
	}
	destroy_tokenizer(params);


	//calculate sendind interval
	data_snd_interval = ((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (datarate * MBITS_TO_BITS)) - 
		((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (linkrate * MBITS_TO_BITS));
	data_snd_interval = (data_snd_interval < 0)?0:data_snd_interval;
	fprintf(stderr, "Sending data interval : %u nsec (pkt_size: %u bytes, rate: %u Mbits/sec %u Mbits/sec)\n",
			(uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate, (uint32_t) linkrate);

	return 0;
}
