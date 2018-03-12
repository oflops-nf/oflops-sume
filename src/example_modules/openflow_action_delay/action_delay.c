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

/** \defgroup openflow_action_delay flow action module
 * \ingroup modules
 * Packet in module.
 * This module benchmarks the implementation of specific sequence of action
 * in the action section of the flow.
 *
 * Parameters:
 *
 * - pkt_size: This parameter can be used to control the length of
 * packets of the measurement probe, measured in bytes. Thus, together with the
 *   rate parameter, it allows indirectly to adjust the packet throughput of the
 * experiment. (default 1500 bytes)
 * - data_rate: The rate of the measurement probe measured in Mbps.
 * (default 10Mbps)
 * - table: The parameter define whether the inserted flow will be
 * a wildcard(value of 1) or exact match(value of 0).  (default 1)
 * - action:  A comma separate string of entries of the format
 *   action_id/action_value. E.g. a value of `b/1010,0/2` defines that the action
 *   will modify the tcp/udp port of the matching packet to a value of 1010 and the
 * packet will be output on port 2. (default no action)
 *
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 */

/**
 * \ingroup openflow_action_delay
 * @return name of module
 */
char * name() {
  return "openflow_action_delay_measurement";
}

//logging filename
#define LOG_FILE "of_action_delay.log"

struct oxm_tlv {
    uint16_t oxm_class;
    uint8_t oxm_field;
    uint8_t oxm_length;
    uint8_t oxm_data[0];
};



uint32_t flows = 10;
int64_t datarate = 100;
int64_t linkrate = 10000;
int64_t data_snd_interval;

int table = 0;
const char *network = "192.168.3.1";
struct flow* fl_probe;

int finished = 0;
/**
 * Probe packet size
 */
uint32_t pkt_size = 1500;

/**
 * Buffer to store the content of the action of the flow mod message.
 */
void *actions = NULL;
int action_len = 0;

/**
 * calculated sending time interval (measured in usec).
 */
int count[] = {0,0,0}; // counting how many packets where received over a
					   // specific channel

/**
 * storing the argument list passed to the module
 */
char *cli_param;
const char *logfile = LOG_FILE;
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
 * \ingroup openflow_action_delay
 * Initializate flow table and schedule events
 * \param ctx pointer to opaque context
 */
int start(struct oflops_context * ctx) {
    struct flow *fl = (struct flow*)xmalloc(sizeof(flow_t));
    fl_probe = (struct flow*)xmalloc(sizeof(flow_t));
    flow_t * mask = malloc(sizeof(flow_t));
    void *b; //somewhere to store message data
    int res, i, len;
    struct timeval now;  //init measurement queue
    TAILQ_INIT(&head);
    char msg[1024];

    //init logging service
    msg_init();

    //log when I start module
    gettimeofday(&now, NULL);

    snprintf(msg, 1024, "Intializing module %s", name());
    oflops_log(now,GENERIC_MSG, msg);
    oflops_log(now,GENERIC_MSG , cli_param);

    get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);

    make_ofp_hello(&b);
    res = oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
    free(b);

    //send a message to clean up flow tables.
    printf("cleaning up flow table...\n");
    res = make_ofp_flow_del(&b);
    res = oflops_send_of_mesgs(ctx, b, res);
    free(b);


    make_ofp_table_miss(&b);
    oflops_send_of_mesg(ctx, b);

    /**
     * Send flow records to start routing packets.
     */
    printf("Sending new flow ...\n");
    memset(fl, 0, sizeof(flow_t));
    memset(mask, 1, sizeof(flow_t));
    if(table == 0) {
    } else {
        mask->in_port = 0;
        mask->tp_dst = 0;
    }
    fl->in_port = htonl(ctx->channels[OFLOPS_DATA1].of_port);
    fl->dl_type = htons(ETHERTYPE_IP);
    memcpy(fl->dl_src, data_mac, ETH_ALEN);
    memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
    fl->dl_vlan = 22;
    fl->nw_proto = IPPROTO_UDP;
    fl->nw_src =  inet_addr("192.168.42.42");
    fl->nw_dst =  inet_addr(network);
    fl->tp_src = htons(8080);
    fl->tp_dst = htons(8080);
    make_ofp_flow_add_actions(&b, fl, mask, actions, action_len, -1, 1200);
    res = oflops_send_of_mesg(ctx, b);
    free(b);

    for(i=0; i< flows; i++) {
        //calculate next ip
        fl->nw_dst =  htonl(ntohl(fl->nw_dst) + 1);
        len = make_ofp_flow_add(&b, fl, mask, 3, -1, 0, 1200);
        if(len == -1) {
            fprintf(stderr, "Coudn't make flow modification message.\nExiting...\n");
            exit(1);
        }
        ((struct ofp_flow_mod *)b)->flags = 0;
        oflops_send_of_mesg(ctx, b);

    }
    free(b);

    /**
     * Scheduling events
     */

    //end process
    oflops_schedule_timer_event(ctx, 20, 0, BYESTR);
    return 0;
}

/**
 * \ingroup openflow_action_delay
 * calculate the stats of the measurement probes.
 * \param ctx data context of the module.
 */
int
destroy(struct oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  struct entry *np;
  int  min_id[] = {INT_MAX, INT_MAX, INT_MAX};
  int ix[] = {0,0,0};
  int max_id[] = {INT_MIN, INT_MIN, INT_MIN}, ch;
  uint32_t mean, std, median;
  float loss;
  double **data;

  gettimeofday(&now, NULL);
  printf("This is the destroying code of the module.\n");

  //insert delay
  data = xmalloc(3*sizeof(double *));
  for(ch = 0; ch < 3; ch++)
    data[ch] = xmalloc(count[ch]*sizeof(double));

  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    ch = np->ch - 1;
    min_id[ch] = (np->id < min_id[ch])?np->id:min_id[ch];
    max_id[ch] = (np->id > max_id[ch])?np->id:max_id[ch];
    data[ch][ix[ch]++] = time_diff(&np->snd, &np->rcv);
    if(print) {
      if(snprintf(msg, 1024, "%lu %ld.%06ld %ld.%06ld %d",
            (long unsigned int)np->id,
            (long unsigned int)np->snd.tv_sec,
            (long unsigned int)np->snd.tv_usec,
            (long unsigned int)np->rcv.tv_sec,
            (long unsigned int)np->rcv.tv_usec,  np->ch) < 0)
        perror_and_exit("Fprintf failed", 1);
      oflops_log(now, GENERIC_MSG, msg);
    }
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
    printf("statistics:port:%d:%u:%u:%u:%.4f:count:%d\n",
        ctx->channels[ch + 1].of_port, mean, median, std, loss, count[ch]);
    oflops_log(now, GENERIC_MSG, msg);
  }

  return 0;
}

/**
 * \ingroup openflow_action_delay
 * Handle timer event
 * - BYESTR: terminate module
 * - SND_ACT: send measured action
 * - SNMPGET: query snmp stats
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te) {
	char *str = te->arg;
	//terminate process
	if (strcmp(str, BYESTR) == 0) {
         finished = 1;
		printf("terminating test....\n");
		oflops_end_test(ctx,1);
		return 0;
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
        memset(*filter, 0, sizeof(cap_filter));
        //(*filter)->proto = "udp";
        //(*filter)->dst = inet_network("192.168.3.2");
        //(*filter)->dst_mask = 0xffffffff;
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

	if ((ch == OFLOPS_DATA2)) {

		if (count[ch - 1] % 1000000 == 0)
			printf("got %d packet on port %d\n", count[ch-1], ch);
		pktgen = extract_pktgen_pkt(ctx, ch, pe->data, pe->pcaphdr.caplen, &fl);
		if(pktgen == NULL) {
			printf("Failed to parse measurement packet\n");
			return 0;
		}

        if (finished == 0) {

            struct entry *n1 = malloc(sizeof(struct entry));
            n1->snd.tv_sec = pktgen->tv_sec;
            n1->snd.tv_usec = pktgen->tv_usec;
            n1->rcv.tv_sec = pktgen->tv_rcv_sec;
            n1->rcv.tv_usec = pktgen->tv_rcv_usec;
            n1->id = htonl(pktgen->seq_num);
            n1->ch = ch;
            count[ch - 1]++;
            TAILQ_INSERT_TAIL(&head, n1, entries);
        }
    }

	return 0;
}

/**
 * \ingroup openflow_action_delay
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
 * \ingroup openflow_action_delay
 * Traffic generation methods
 * \param ctx data context of module
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip;
  char* str_ip;

  init_traf_gen(ctx);
  strcpy(det.src_ip,"192.168.42.42");
  strcpy(det.dst_ip_min, network);
  ip.s_addr = ntohl(inet_addr(network));
  ip.s_addr += (flows - 1);
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
  strcpy(det.mac_dst_base,"00:15:17:7b:92:0a");
  det.mac_dst_count = 1;
  det.vlan = 22;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  //det.pkt_count = 2000;
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
 * \ingroup openflow_action_delay
 * Initialization code with parameters
 * @param ctx
 */
int init(struct oflops_context *ctx, char * config_str) {
  char ***params, ***acts;
  char *param = config_str;
  int ix = 0, actions_ix = 0;
  struct timeval now;

  gettimeofday(&now, NULL);

  cli_param = strdup(config_str);
  params = run_tokenizer(config_str, ' ', '=');

  if ((strcmp(ctx->log, DEFAULT_LOG_FILE)) == 0) {
      strcpy(ctx->log, logfile);
  }
  fprintf(stderr, "Log file is %s.\n", ctx->log);

  // Set print mode.
  print = ctx->print;

  while (params[ix] != NULL) {
      if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "pkt_size") == 0) ) {
          //parse int to get pkt size
          pkt_size = strtol(params[ix][1], NULL, 0);
          if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
              perror_and_exit("Invalid packet size value", 1);
      } else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "data_rate") == 0)) {
          //parse int to get rate of background data
          datarate = strtol(params[ix][1], NULL, 0);
          if((datarate > 10010))
              perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
      } else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "link_rate") == 0)) {
          //parse int to get rate of background data
          linkrate = strtol(params[ix][1], NULL, 0);
          if((linkrate > 10010))
              perror_and_exit("Invalid link rate param(Values between 1 and 1010)", 1);
      } else if ((params[ix][0] != NULL) && (strcmp(params[ix][0], "action") == 0)) {
          acts = run_tokenizer(params[ix][1], ',', '/');
          actions_ix = 0;

          while (acts[actions_ix] != NULL) {

              int action_type = strtol(acts[actions_ix][0], NULL, 10);
              if (((action_type < 0) ||  (action_type > 27)) ||
                  ((action_type > 0) && (action_type < 11))) {
                  printf("Invalid action type %x\n", action_type);
                  actions_ix++;
                  continue;
              }
              append_action(action_type, acts[actions_ix][1]);
              actions_ix++;
          }
          destroy_tokenizer(acts);

      } else if((params[ix][0] != NULL) && (strcmp(params[ix][0], "table") == 0)) {
          //parse int to get pkt size
          table = strtol(params[ix][1], NULL, 0);
          if((table < 0) || (table > 2))
              perror_and_exit("Invalid table number", 1);
      } else if ((params[ix][0] != NULL) && (strcmp(params[ix][0],  "print") == 0)) {
          printf("printing data\n");
          //parse int to check whether per packet statistics should be stored
          print = strtol(params[ix][1], NULL, 0);
      } else {
          fprintf(stderr, "Invalid parameter:%s\n", param);
      }

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

/*
 * Help function
 */
/*
 * Given the global variables buffer and buffer_len, append at their end
 * the commands that with type action and action param action_param.
 * @param action the id of the action.
 * @param action_param the parameter of the action
 * @todo code is very dirty. Needs to be refactored.
 * FIXME Code is ugly, I have to fix it.
 */
int
append_action(int action, const char *action_param) {
	char *p = NULL;
    char **fields;
    size_t counter;
    uint16_t len;
    switch(action) {
        case OFPAT_OUTPUT:
            len = sizeof(struct ofp_action_output);
            fprintf(stderr, "output packet to port %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_output *act_out =
                (struct ofp_action_output *)(actions + action_len);
            action_len += len;
            memset(act_out, 0, len);
            act_out->type = htons(OFPAT_OUTPUT);
            act_out->len = htons(len);
            act_out->max_len = htons(2000);
            act_out->port = htonl((uint32_t)strtol(action_param, &p, 10));
            break;
        case OFPAT_PUSH_VLAN: case OFPAT_PUSH_MPLS: case OFPAT_PUSH_PBB:
            len = sizeof(struct ofp_action_push);
            fprintf(stderr, "Add vlan/mpls/pbb tag %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_push *act_push =
                (struct ofp_action_push *)(actions + action_len);
            action_len += len;
            act_push->type = htons(action);
            act_push->len = htons(len);
            act_push->ethertype = ntohs((uint16_t)strtol(action_param, &p, 10));
            break;
        case OFPAT_SET_QUEUE:
            len = sizeof(struct ofp_action_set_queue);
            fprintf(stderr, "Send packets to the queue %s on port\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_set_queue *act_queue =
                (struct ofp_action_set_queue *)(actions + action_len);
            action_len += len;
            memset(act_queue, 0, len);
            act_queue->type = htons(action);
            act_queue->len = htons(len);
            act_queue->queue_id = htonl((uint32_t)strtol(action_param, &p, 10));
            break;
        case OFPAT_SET_MPLS_TTL:
            len = sizeof(struct ofp_action_mpls_ttl);
            fprintf(stderr, "Set MPLS TTL to %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_mpls_ttl *act_mpls =
                (struct ofp_action_mpls_ttl *)(actions + action_len);
            action_len += len;
            memset(act_mpls, 0, len);
            act_mpls->type = htons(OFPAT_SET_MPLS_TTL);
            act_mpls->len = htons(len);
            act_mpls->mpls_ttl = (uint8_t)strtol(action_param, &p, 10);
        case OFPAT_SET_NW_TTL:
            len = sizeof(struct ofp_action_nw_ttl);
            fprintf(stderr, "Set IPv4 TTL to %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_nw_ttl *act_nw =
                (struct ofp_action_nw_ttl *)(actions + action_len);
            action_len += len;
            memset(act_nw, 0, len);
            act_nw->type = htons(OFPAT_SET_NW_TTL);
            act_nw->len = htons(len);
            act_nw->nw_ttl = (uint8_t)strtol(action_param, &p, 10);
        case OFPAT_DEC_MPLS_TTL: case OFPAT_DEC_NW_TTL: case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN: case OFPAT_POP_VLAN: case OFPAT_POP_PBB:
            len = sizeof(struct ofp_action_header);
            actions = realloc(actions, action_len + len);
            struct ofp_action_header *act_basic =
                (struct ofp_action_header *)(actions + action_len);
            action_len += len;
            memset(act_basic, 0, len);
            act_basic->type = htons(action);
            act_basic->len = htons(len);
        case OFPAT_POP_MPLS:
            len = sizeof(struct ofp_action_pop_mpls);
            fprintf(stderr, "Pop MPLS for %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_pop_mpls *act_pop_mpls =
                (struct ofp_action_pop_mpls *)(actions + action_len);
            action_len += len;
            memset(act_pop_mpls, 0, len);
            act_pop_mpls->type = htons(OFPAT_POP_MPLS);
            act_pop_mpls->len = htons(len);
            act_pop_mpls->ethertype = (uint8_t)strtol(action_param, &p, 10);
        case OFPAT_GROUP:
            len = sizeof(struct ofp_action_group);
            fprintf(stderr, "Use group %s\n", action_param);
            actions = realloc(actions, action_len + len);
            struct ofp_action_group *act_group =
                (struct ofp_action_group *)(actions + action_len);
            action_len += len;
            memset(act_group, 0, len);
            act_group->type = htons(OFPAT_GROUP);
            act_group->len = htons(len);
            act_group->group_id = htonl((uint32_t)strtol(action_param, &p, 10));
	case OFPAT_SET_FIELD:
            fields = str_split((char*)action_param, '-', &counter);
            if (counter != 2) {
                fprintf(stderr, "SET Field: invalid number of parameters\n");
            } else {
                fprintf(stderr, "Set field action\n");
                struct oxm_tlv *tlv = NULL;
                uint8_t field = (uint8_t)strtol(*fields, &p, 10);
                uint16_t tmp_16;
                uint32_t tmp_32;
                switch (field) {
                    case OFPXMT_OFB_VLAN_VID: case OFPXMT_OFB_ETH_TYPE: case OFPXMT_OFB_UDP_SRC:
                    case OFPXMT_OFB_UDP_DST: case OFPXMT_OFB_TCP_SRC: case OFPXMT_OFB_TCP_DST:
                        tlv = malloc(sizeof(struct oxm_tlv) + 2);
                        tlv->oxm_class = htons(OFPXMC_OPENFLOW_BASIC);
                        tlv->oxm_field = field << 1;
                        tlv->oxm_length = 2;
                        tmp_16 = htons((uint16_t)strtol(*(fields+1), &p, 10));
                        memcpy(tlv->oxm_data, &tmp_16, 2);
                        break;
                    case OFPXMT_OFB_IP_PROTO:
                        tlv = malloc(sizeof(struct oxm_tlv) + 1);
                        tlv->oxm_class = htons(OFPXMC_OPENFLOW_BASIC);
                        tlv->oxm_field = field << 1;
                        tlv->oxm_length = 1;
                        tlv->oxm_data[0] = (uint8_t)strtol(*(fields+1), &p, 10);
                        break;
                    case OFPXMT_OFB_IPV4_SRC: case OFPXMT_OFB_IPV4_DST:
                        tlv = malloc(sizeof(struct oxm_tlv) + 4);
                        tlv->oxm_class = htons(OFPXMC_OPENFLOW_BASIC);
                        tlv->oxm_field = field << 1;
                        tlv->oxm_length = 4;
                        tmp_32 = inet_addr(*(fields+1));
                        printf("IP is %x\n", tmp_32);
                        memcpy(tlv->oxm_data, &tmp_32, 4);
                        break;
                    case OFPXMT_OFB_ETH_DST: case OFPXMT_OFB_ETH_SRC:
                        tlv = malloc(sizeof(struct oxm_tlv) + 6);
                        tlv->oxm_class = htons(OFPXMC_OPENFLOW_BASIC);
                        tlv->oxm_field = field << 1;
                        tlv->oxm_length = 6;
                        uint8_t bytes[6];
                        char* devnull = NULL;
                        int values[6], i;
                        if (6 == sscanf(*(fields +1), "%x:%x:%x:%x:%x:%x%c",
                                        &values[0], &values[1], &values[2],
                                        &values[3], &values[4], &values[5],
                                        devnull)) {
                            for (i = 0; i<6; i++) {
                                bytes[i] = (uint8_t)values[i];
                            }
                        } else {
                            fprintf(stderr, "Invalid mac adress given %s\n", *(fields +1));
                        }
                        memcpy(tlv->oxm_data, bytes, 6);
                        break;
                     default: fprintf(stderr, "Unsupported header field.");
                }
                int pad_len = (8-(tlv->oxm_length + 4)) % 8;
                pad_len = pad_len < 0 ? pad_len + 8: pad_len;
                int struct_len = sizeof(struct ofp_action_set_field) +
                                 4 + tlv->oxm_length + pad_len;
                printf("Struct len is %d\n", struct_len);
                actions = realloc(actions, action_len + struct_len);
                struct ofp_action_set_field *act_field= (struct ofp_action_set_field *)
                    (actions + action_len);
                action_len += struct_len;
                memset(act_field, 0, struct_len);
                act_field->type = htons(OFPAT_SET_FIELD);
                act_field->len = htons(struct_len);
                memcpy(act_field->field, tlv, 4 + tlv->oxm_length);
                free(tlv);
            }
			break;
        default:
            printf("Ignoring action %d %s\n", action, action_param);
            break;
	}
	return 0;
}
