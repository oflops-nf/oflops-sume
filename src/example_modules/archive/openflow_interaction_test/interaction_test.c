#include <poll.h>

#include "test_module.h"

#ifndef BUFLEN
#define BUFLEN 4096
#endif


#define TEST_DURATION 120

#define MIN_QUERY_DELAY 1000

#define LOG_FILE "of_interaction_test.log"

/*
 * Number of flow rules we send to the switch
 */
int flows = 128;
int total_flows = 1024;

int flows_exponent, query_exponent;
int query = 2;
int query_delay = 1000000; //1 sec
/** The iniitial ip from which we start
 */
char *network = "192.168.40.0";

/** Some constants to help me with conversions
 */


/** The rate at which data will be send between the data ports (In Mbits per sec.).
 */
uint64_t datarate = 100;
uint64_t proberate = 100;

/** pkt sizes.
 */
uint64_t pkt_size = 1500;

//internat state of the module
int finished;
int poll_started = 0;
int send_flow_mod = 0, stored_flow_mod_time = 0;
int first_pkt = 0;

/*
 * calculated sending time interval (measured in usec).
 */
uint64_t data_snd_interval;
uint64_t probe_snd_interval;

//stoer when events happened
struct timeval stats_start;
struct timeval flow_mod_timestamp;
int trans_id=0;

char *logfile = LOG_FILE;

//a struct to store stats details
struct stats_entry {
  struct timeval rcv,snd;
  int pkt_count;
} stats_counter[(TEST_DURATION * SEC_TO_USEC)/MIN_QUERY_DELAY];

int stats_count = 0;

// control whether detailed packet information is printed and
// whether the flow are exact match
int print = 0, table = 0;

//the local mac address of the probe
char data_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

int *ip_received;
int ip_received_count;

/** \defgroup openflow_interaction_test
 * \ingroup modules
*
* Parameters:
*
*   - pkt_size: This parameter can be used to control the length of the
*  packets of the measurement probe. It allows indirectly to adjust the packet
*  throughput of the experiment. The parameter uses bytes as measurement unit.
*  The parameter applies for both measurement probes.
*   - probe_rate: The rate of the sequential probe, measured in
*  Mbps.
*   - data_rate: The rate of the constant probe, measured in Mbps.
*   - flows:  The number of unique flows that the module will
*  update/insert.
*   - table:  This parameter controls whether the inserted flow will
*  be  a wildcard(value of 1) or exact match(value of 0). For the wildcard
*  flows, the module wildcards all of the fields except the destination IP address.
*
*
 * Copyright (C) t-labs, 2010
 * @author crotsos
 * @date June, 2010
 *
 * @return name of module
 */
char * name()
{
  return "openflow_interaction_test";
}

/**
* \ingroup openflow_interaction_test
* parse initialisation string and init parameters
* \param ctx data context of module
* \param config_str a space separated initialization sting string
*/
int init(oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;

  if(strcmp(ctx->log, DEFAULT_LOG_FILE) == 0) {
      strcpy(ctx->log, logfile);
  }
  fprintf(stderr, "Log file is %s.\n", ctx->log);

  // Set print mode.
  print = ctx->print;

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
      if(strcmp(param, "network") == 0) {
	//network range to send data for the data probe
        network = (char *)xmalloc(strlen(value) + 1);
        strcpy(network, value);
      } else if(strcmp(param, "pkt_size") == 0) {
        //packet size for the probes
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))  {
          perror_and_exit("Invalid packet size value", 1);
        }
      } else if(strcmp(param, "data_rate") == 0) {
        //multituple data rate
        datarate = strtol(value, NULL, 0);
        if((datarate <= 0) || (datarate > 1010))  {
          perror_and_exit("Invalid data rate param(Values between 1 and 1010)", 1);
        }

      } else if(strcmp(param, "probe_rate") == 0) {
        //single tuple data rate
        proberate = strtol(value, NULL, 0);
        if((proberate <= 0) || (proberate >= 1010)) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }

	//time gap between querries in usec
      } else if(strcmp(param, "query_delay") == 0) {
        query_delay = strtol(value, NULL, 0);
        if(query_delay <= MIN_QUERY_DELAY) {
          perror_and_exit("Invalid probe rate param(Value between 1 and 1010)", 1);
        }
	printf("query delay %d\n", query_delay);
	//should packet timestamp be printed
      } else if(strcmp(param, "print") == 0) {
        //parse int to get pkt size
        print = strtol(value, NULL, 0);
      } else if(strcmp(param, "flows") == 0) {
	//parse int to get pkt size
        flows = strtol(value, NULL, 0);
        if(flows <= 0)
          perror_and_exit("Invalid flow number", 1);
      } else if(strcmp(param, "table") == 0) {
        //parse int to get pkt size
        table = strtol(value, NULL, 0);
      } else {
        fprintf(stderr, "Invalid parameter:%s\n", param);
      }
      param = pos;
    }
  }

  //calculating interpacket gap
  data_snd_interval = (pkt_size * BYTE_TO_BITS * SEC_TO_USEC) / (datarate * MBITS_TO_BITS);
  fprintf(stderr, "Sending data interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
	  (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate);
  probe_snd_interval = (pkt_size * BYTE_TO_BITS * SEC_TO_USEC) / (proberate * MBITS_TO_BITS);
  fprintf(stderr, "Sending probe interval : %u usec (pkt_size: %u bytes, rate: %u Mbits/sec )\n",
	  (uint32_t)probe_snd_interval, (uint32_t)pkt_size, (uint32_t)proberate);
  fprintf(stderr, "sending %d flows, quering %d flows every %u usec\n",
	  flows, query, query_delay);


  return 0;
}


int destroy(oflops_context *ctx) {
  char msg[1024];
  struct timeval now;
  uint32_t mean, median, std;
  int min_id[] = {INT_MAX, INT_MAX, INT_MAX};
  int max_id[] = {INT_MIN, INT_MIN, INT_MIN};
  int ix[] = {0, 0, 0};
  int i;
  float loss;
  double **data;

  gettimeofday(&now, NULL);
  fprintf(stderr, "This is the destroy code of the module\n");

  data = (double **)malloc(3*sizeof(double*));
  bzero(data, 3*sizeof(double*));

  ix[0] = 0;
  if(data[0] != NULL)
    free(data[0]);
  data[0] = (double *)malloc(sizeof(double)*(stats_count));

  for (i = 0; i < trans_id; i++) {
    if(((stats_counter[i].rcv.tv_sec == 0) &&
	(stats_counter[i].rcv.tv_usec == 0)) ||
       (ix[0] >=  stats_count)) continue;
    data[0][ix[0] - 1]  = (double) time_diff(&stats_counter[i].snd, &stats_counter[i].rcv);
    ix[0]++;
    snprintf(msg, 1024, "stats:%u:%d:%d.%06d:%d.%06d:%d",i,
     	   stats_counter[i].pkt_count,
     	    (uint32_t)stats_counter[i].snd.tv_sec,
     	    (uint32_t)stats_counter[i].snd.tv_usec,
     	    (uint32_t)stats_counter[i].rcv.tv_sec,
     	    (uint32_t)stats_counter[i].rcv.tv_usec,
	     (uint32_t)time_diff(&stats_counter[i].snd,
     		     &stats_counter[i].rcv));
    oflops_log(now, GENERIC_MSG, msg);
  }

  if(ix[0] > 0) {
    gsl_sort (data[0], 1, ix[0]);
    mean = (uint32_t)gsl_stats_mean(data[0], 1, ix[0]);
    std = (uint32_t)sqrt(gsl_stats_variance(data[0], 1, ix[0]));
    median = (uint32_t)gsl_stats_median_from_sorted_data (data[0], 1, ix[0]);
    loss = (float)ix[0]/(float)(max_id[0] - min_id[0]);
    snprintf(msg, 1024, "statistics:stats:%u:%u:%u:%.04f:%d",
	     mean, median, std, loss, ix[0]);
    printf("%s\n", msg);
    oflops_log(now, GENERIC_MSG, msg);
  } else {
    oflops_log(now, GENERIC_MSG, "stats_stats:fail");
  }
  return 0;
}

/**
* \ingroup openflow_interaction_test
* init flow table and schedule oflops events
 * @param ctx pointer to opaque context
 */
int start(oflops_context * ctx)
{
  int res = -1, i, len = 0;
  struct timeval now;
  struct pollfd * poll_set = malloc(sizeof(struct pollfd));
  flow_t *fl = xmalloc(sizeof(flow_t));
  flow_t *mask = xmalloc(sizeof(flow_t));
  int ret = 0;
  char msg[1024];

  // a genric structure with which
  // we can create and send messages.
  void *b;

  msg_init();
  bzero(&flow_mod_timestamp, sizeof(struct timeval));

  ip_received = xmalloc(flows*sizeof(int));
  memset(ip_received, 0, flows*sizeof(int));

  //make filedescriptor blocking
  int saved_flags = fcntl(ctx->control_fd, F_GETFL);
  fcntl(ctx->control_fd, F_SETFL, saved_flags & ~O_NONBLOCK);

  get_mac_address(ctx->channels[OFLOPS_DATA1].dev, data_mac);
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ctx->channels[OFLOPS_DATA1].dev,
	 (unsigned char)data_mac[0], (unsigned char)data_mac[1],
	 (unsigned char)data_mac[2], (unsigned char)data_mac[3],
	 (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

  gettimeofday(&now, NULL);
  snprintf(msg, 1024,  "Intializing module %s", name());
  oflops_log(now, GENERIC_MSG, msg);

  make_ofp_hello(&b);
  ret = write(ctx->control_fd, b, sizeof(struct ofp_hello));
  free(b);

  // send a features request, to stave off timeout (ignore response)
  printf("cleaning up flow table...\n");
  res = make_ofp_flow_del(&b);
  ret = write(ctx->control_fd, b, res);
  free(b);

  sleep(10);

  //Send a singe ruke to route the traffic we will generate
  printf("Sending new flow rules...%d\n", table);
  bzero(fl, sizeof(struct flow));
  if(table == 0)
      mask = NULL;
  else {
      memset(mask, 1, sizeof(flow_t));
      memset(&mask->dl_src, 0, 6);
      memset(&mask->dl_dst, 0, 6);
      mask->tp_dst = 0;
      mask->tp_src = 0;
      mask->dl_vlan = 0;
      mask->nw_proto = 0;
  }
    //fl->mask = OFPFW_DL_DST | OFPFW_DL_SRC | (32 << OFPFW_NW_SRC_SHIFT) |
    //  (0 << OFPFW_NW_DST_SHIFT) | OFPFW_DL_VLAN | OFPFW_TP_DST | OFPFW_NW_PROTO |
    //  OFPFW_TP_SRC | OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS;

  fl->dl_type = htons(ETHERTYPE_IP);
  memcpy(fl->dl_src, data_mac, ETH_ALEN);
  memcpy(fl->dl_dst, "\x00\x15\x17\x7b\x92\x0a", ETH_ALEN);
  fl->dl_vlan = 0xffff;
  fl->nw_proto = IPPROTO_UDP;
  fl->nw_src =  inet_addr("10.1.1.1");
  fl->nw_dst = inet_addr(network);
  fl->tp_src = htons(8080);
  fl->tp_dst = htons(8080);
  fl->in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
  for(i=0; i< flows; i++) {
    do {
      bzero(poll_set, sizeof(struct pollfd));
      poll_set[0].fd = ctx->control_fd;
      poll_set[0].events = POLLOUT;
      ret = poll(poll_set, 1, -1);
    } while ((ret == 0) || ((ret > 0) && !(poll_set[0].revents & POLLOUT)) );

    if(( ret == -1 ) && ( errno != EINTR))
      perror_and_exit("poll",1);

    len = make_ofp_flow_add(&b, fl, mask, ctx->channels[OFLOPS_DATA3].of_port, 1, 0, 1200);
    ((struct ofp_flow_mod *)b)->flags = 0;
    ret = write(ctx->control_fd, b, len);
    free(b);

    //calculate next ip
    fl->nw_dst =  htonl(ntohl(fl->nw_dst) + 1);
  }

  fl->in_port = htons(ctx->channels[OFLOPS_DATA2].of_port);
  for(; i< total_flows; i++) {
    do {
      bzero(poll_set, sizeof(struct pollfd));
      poll_set[0].fd = ctx->control_fd;
      poll_set[0].events = POLLOUT;
      ret = poll(poll_set, 1, -1);
    } while ((ret == 0) || ((ret > 0) && !(poll_set[0].revents & POLLOUT)) );

    if(( ret == -1 ) && ( errno != EINTR))
      perror_and_exit("poll",1);

    len = make_ofp_flow_add(&b, fl,mask, ctx->channels[OFLOPS_DATA3].of_port, 1, 0, 1200);
    ((struct ofp_flow_mod *)b)->flags = 0;
    ret = write(ctx->control_fd, b, len);
    free(b);

    //calculate next ip
    fl->nw_dst =  htonl(ntohl(fl->nw_dst) + 1);
  }

  make_ofp_hello(&b);
  ((struct ofp_header *)b)->type = OFPT_ECHO_REQUEST;
  free(b);

  //Schedule end
  oflops_schedule_timer_event(ctx, TEST_DURATION, 0, BYESTR);

  //the event to request the flow statistics.
  oflops_schedule_timer_event(ctx, query_delay/SEC_TO_USEC, 
		  query_delay%SEC_TO_USEC, GETSTAT);

  //send the flow modyfication command in 30 seconds.
  oflops_schedule_timer_event(ctx, 20, 0, SND_ACT);

  //get port and cpu status from switch
  oflops_schedule_timer_event(ctx, 1, 0, SNMPGET);

  flows_exponent = (int)floor(log2(flows));
  query_exponent = (int)log2(query);

  return 0;
}

/**
* \ingroup openflow_interaction_test
* Handle timer event
 * @param ctx pointer to opaque context
 * @param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te)
{
  int len, i, ret;
  void *b = NULL;
  char *str = te->arg;
  char msg[100];
  struct flow fl, *mask;
  struct pollfd * poll_set = malloc(sizeof(struct pollfd));

  //send flow statistics request.
  if(strcmp(str, GETSTAT) == 0) {
    //log start of measurement
    if(trans_id == 0) {
      printf("flow stats request send with xid %s\n", msg);
      memcpy(&stats_start, &te->sched_time, sizeof(struct timeval));
      poll_started = 1;
    }
    memcpy(&stats_counter[trans_id].snd, &te->sched_time, sizeof(struct timeval));
    bzero(&stats_counter[trans_id].rcv, sizeof(struct timeval));
    //create generic statrequest message
    len = make_ofp_aggr_flow_stats(&b, trans_id++);

    //send stats request
    ret = write(ctx->control_fd, b, len);
    free(b);

    //schedule next query
    oflops_schedule_timer_event(ctx, query_delay/SEC_TO_USEC, 
		query_delay%SEC_TO_USEC, GETSTAT);
  } else if (strcmp(str, BYESTR) == 0) {
    //terminate programm execution
    printf("terminating test....\n");
    oflops_end_test(ctx,1);
  } else if (strcmp(str, SND_ACT) == 0) {
    //first create new rules
    send_flow_mod = 1;

    if(table == 0) {
        mask = NULL;
    } else {
        memset(mask, 1, sizeof(flow_t));
        memset(&mask->dl_dst, 0, 6);
        memset(&mask->dl_src, 0, 6);
        mask->dl_vlan = 0;
        mask->nw_proto = 0;
        mask->tp_dst = 0;
        mask->tp_src = 0;
        mask->nw_src =  0;
    }

    fl.in_port = htons(ctx->channels[OFLOPS_DATA1].of_port);
    fl.dl_type = htons(ETHERTYPE_IP);
    memcpy(fl.dl_src, data_mac, 6);
    memcpy(fl.dl_dst, "\x00\x15\x17\x7b\x92\x0a", 6);

    fl.dl_vlan = 0xffff;
    fl.nw_proto = IPPROTO_UDP;
    fl.nw_src =  inet_addr("10.1.1.1");
    fl.tp_src = htons(8080);
    fl.tp_dst = htons(8080);

    for(i=0; i< flows; i++) {
      fl.nw_dst =   htonl(ntohl(inet_addr(network)) + i);
      do {
        bzero(poll_set, sizeof(struct pollfd));
        poll_set[0].fd = ctx->control_fd;
        poll_set[0].events = POLLOUT;
        ret = poll(poll_set, 1, -1);
      } while ((ret == 0) || ((ret > 0) && !(poll_set[0].revents & POLLOUT)) );

      if(( ret == -1 ) && ( errno != EINTR))
        perror_and_exit("poll",1);

      len = make_ofp_flow_modify_output_port(&b, &fl, mask, ctx->channels[OFLOPS_DATA2].of_port, 1, 120);
      ((struct ofp_flow_mod *)b)->flags = 0;
      ret = write(ctx->control_fd, b, len);
      //oflops_send_of_mesgs(ctx, b, len);
      free(b);
    }
    oflops_gettimeofday(ctx, &flow_mod_timestamp);
    make_ofp_hello(&b);
    ((struct ofp_header *)b)->type = OFPT_BARRIER_REQUEST;
    ret = write(ctx->control_fd, b, sizeof(struct ofp_header));
    free(b);
    stored_flow_mod_time = 1;
    printf("pcap flow modification send %lu.%06lu %d\n",  flow_mod_timestamp.tv_sec, flow_mod_timestamp.tv_usec, table);
  } else if(strcmp(str, SNMPGET) == 0) {
    return 0;
    for(i=0;i<ctx->cpuOID_count;i++)
      oflops_snmp_get(ctx, ctx->cpuOID[i], ctx->cpuOID_len[i]);

    for(i=0;i<ctx->n_channels;i++) {
      oflops_snmp_get(ctx, ctx->channels[i].inOID, ctx->channels[i].inOID_len);
      oflops_snmp_get(ctx, ctx->channels[i].outOID, ctx->channels[i].outOID_len);
    }
    oflops_schedule_timer_event(ctx, 10, 0, SNMPGET);
  }
  return 0;
}

/**
* \ingroup openflow_interaction_test
* log information from asynchronous snmp queries
* \param ctx data context of the module
* \param se the snmp message
*/
int
handle_snmp_event(oflops_context * ctx, struct snmp_event * se) {
  netsnmp_variable_list *vars;
  int i, len = 1024;
  char msg[1024], count[1024];
  struct timeval now;

  for(vars = se->pdu->variables; vars; vars = vars->next_variable)  {
    snprint_value(msg, len, vars->name, vars->name_length, vars);

    for (i = 0; i < ctx->cpuOID_count; i++) {
      if((vars->name_length == ctx->cpuOID_len[i]) &&
	 (memcmp(vars->name, ctx->cpuOID[i],  ctx->cpuOID_len[i] * sizeof(oid)) == 0) ) {
	snprintf(count, len, "cpu : %s %%", msg);
	oflops_log(now, SNMP_MSG, count);
      }
    }

    for(i=0;i<ctx->n_channels;i++) {
      if((vars->name_length == ctx->channels[i].inOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].inOID,
		 ctx->channels[i].inOID_len * sizeof(oid)) == 0) ) {
	snprintf(count, len, "port %d : rx %s pkts",
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1],
		 msg);
	oflops_log(now, SNMP_MSG, count);
	break;
      }

      if((vars->name_length == ctx->channels[i].outOID_len) &&
	 (memcmp(vars->name, ctx->channels[i].outOID,
		 ctx->channels[i].outOID_len * sizeof(oid))==0) ) {
	snprintf(count, len, "port %d : tx %s pkts",
		 (int)ctx->channels[i].outOID[ctx->channels[i].outOID_len-1], msg);
	oflops_log(now, SNMP_MSG, count);
	break;
      }
    } //for
  }// if cpu
  return 0;
}

/** Register pcap filter.
 * @param ctx pointer to opaque context
 * @param ofc enumeration of channel that filter is being asked for
 * @param filter filter string for pcap
 * @param buflen length of buffer
 */
int get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
        cap_filter **filter)
{
  if (ofc == OFLOPS_DATA2) {
      *filter = malloc(sizeof(cap_filter));
      memset(*filter, 0, sizeof(cap_filter));
      (*filter)->proto = "udp";
      return 1;
  }
  return 0;
}

/**
* \ingroup openflow_interaction_test
* Handle pcap event.
 * @param ctx pointer to opaque context
 * @param pe pcap event
 * @param ch enumeration of channel that pcap event is triggered
 */
int handle_pcap_event(oflops_context *ctx, struct pcap_event *pe,
		      enum oflops_channel_name ch) {
  struct pktgen_hdr *pktgen;
  struct flow fl;
  struct in_addr addr;
  char msg[1024];

  pktgen = extract_pktgen_pkt(ctx, ch, (unsigned char *)pe->data, pe->pcaphdr.caplen, &fl);
  if ((pktgen != NULL) && (ch == OFLOPS_DATA2) ) {
    addr.s_addr = fl.nw_dst;
    if(!first_pkt) {
      printf("INSERT_DELAY:%d:%s\n", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts), inet_ntoa(addr));
      snprintf(msg, 1024, "INSERT_DELAY:%d:%s", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts), inet_ntoa(addr));
      oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
      first_pkt = 1;
    }

    int id = ntohl(fl.nw_dst) - ntohl(inet_addr(network));
    if ((id >= 0) && (id < flows) && (!ip_received[id])) {
      ip_received_count++;
      ip_received[id] = 1;
      if (ip_received_count >= flows) {
	if(ip_received_count % 100) {
	  printf("id %d %s\n", ip_received_count, inet_ntoa(addr));
	}
	oflops_schedule_timer_event(ctx, 1, 0, BYESTR);
	printf("Received all packets to channel 2\n");
	printf("COMPLETE_INSERT_DELAY:%u\n", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
	snprintf(msg, 1024, "COMPLETE_INSERT_DELAY:%u", time_diff(&flow_mod_timestamp, &pe->pcaphdr.ts));
	oflops_log(pe->pcaphdr.ts, GENERIC_MSG, msg);
      }
    }
  }
  return 0;
}

/**
* \ingroup openflow_interaction_test
* setup 2 measurement probes
* \param ctx data context of the module
*/
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip;
  init_traf_gen(ctx);

  //measurement probe
  ip.s_addr = ntohl(inet_addr("192.168.2.0")) + (flows);
  strcpy(det.dst_ip_min,  inet_ntoa(ip));
  ip.s_addr = htonl(ntohl(inet_addr("192.168.2.0")) + total_flows - 1);
  strcpy(det.dst_ip_max,  inet_ntoa(ip));
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
    else
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
   	     (unsigned char)data_mac[0], (unsigned char)data_mac[1],
   	     (unsigned char)data_mac[2], (unsigned char)data_mac[3],
   	     (unsigned char)data_mac[4], (unsigned char)data_mac[5]);
  strcpy(det.mac_dst_base, "00:15:17:7b:92:0a");
  det.mac_dst_count = 1;
  det.vlan = 0xffff;
  det.delay = probe_snd_interval*1000;
  strcpy(det.flags, "IPDST_RND");
  add_traffic_generator(ctx, OFLOPS_DATA2, &det);

  //background data
  strcpy(det.src_ip,"10.1.1.1");
  strcpy(det.dst_ip_min,"192.168.2.0");

  ip.s_addr = ntohl(inet_addr("192.168.2.0")) + (flows - 1);
  ip.s_addr = htonl(ip.s_addr);
  strcpy(det.dst_ip_max, inet_ntoa(ip));
  if(ctx->trafficGen == PKTGEN)
    strcpy(det.mac_src,"00:00:00:00:00:00");
  else
    snprintf(det.mac_src, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
	     (unsigned char)data_mac[0], (unsigned char)data_mac[1],
	     (unsigned char)data_mac[2], (unsigned char)data_mac[3],
	     (unsigned char)data_mac[4], (unsigned char)data_mac[5]);

  strcpy(det.mac_dst_base, "00:15:17:7b:92:0a");
  det.mac_dst_count = 1;
  det.vlan = 0xffff;
  det.vlan_p = 1;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval*1000;
  strcpy(det.flags, "");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);

  start_traffic_generator(ctx);
  return 1;
}

/**
* \ingroup openflow_interaction_test
* log information for barrier reply and openflow stats replies
* \param ctx data context of the module
* \param ofph the data of the openflow packet
*/
int
of_event_other(oflops_context *ctx, const struct ofp_header * ofph) {
  struct timeval now;
  char msg[1024];
  struct ofp_error_msg *err_p;

  if(ofph->type == OFPT_MULTIPART_REPLY) {
    struct ofp_multipart_reply *ofpr = (struct ofp_multipart_reply *)ofph;
    stats_counter[ntohl(ofph->xid)].pkt_count++;
    if(ntohs(ofpr->type) == OFPMP_FLOW) {
      if(!(ntohs(ofpr->flags) & OFPMPF_REPLY_MORE)) {
	oflops_gettimeofday(ctx, &now);
	memcpy(&stats_counter[ntohl(ofph->xid)].rcv, &now, sizeof(struct timeval));
	stats_count++;
      }
    }
  } else if (ofph->type == OFPT_ERROR) {
    oflops_gettimeofday(ctx, &now);
    err_p = (struct ofp_error_msg *)ofph;
    sprintf(msg, "OFPT_ERROR(type: %d, code: %d)", ntohs(err_p->type), ntohs(err_p->code));
    oflops_log(now, OFPT_ERROR_MSG, msg);
    fprintf(stderr, "%s\n", msg);
  } else if (ofph->type == OFPT_BARRIER_REPLY) {
    oflops_gettimeofday(ctx, &now);
    snprintf(msg, 1024, "BARRIER_DELAY:%d.\n", time_diff(&flow_mod_timestamp, &now));
    oflops_log(now, GENERIC_MSG, msg);
    printf("BARRIER_DELAY:%d\n",  time_diff(&flow_mod_timestamp, &now));
  }
  return 0;
}
