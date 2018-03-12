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
#include <net/ethernet.h>

#include <test_module.h>


#define LOG_FILE "of_pktin.log"

char* logfile = LOG_FILE;

uint64_t datarate = 100;
uint64_t data_snd_interval;
uint64_t linkrate = 10000;


// Number of flows to send.
int flows = 100;
char *cli_param;
char *network = "192.168.20.0";
int pkt_size = MAX_PKT_SIZE;
int finished = 0;
uint32_t pkt_in_count = 0;
int print = 0;


//local mac
char local_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

struct entry {
  struct timeval snd,rcv;
  int ch, id;
  TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};
TAILQ_HEAD(tailhead, entry) head;

/**
 * \defgroup openflow_packet_in openflow packet in
 * \ingroup modules
 * A module to benchmark the packet_in functionality of an openflow implementation.
 * the module generates traffic at user specified rates and measures the delay to receive
 * packets on the control channel.
 *
 * Parameters:
 *
 *    - pkt_size:  This parameter can be used to control the length of the
 *   packets of the packet_out message in bytes. It allows indirectly to adjust the packet
 * throughput of the experiment. (default 1500 bytes)
 *    - data_rate: This parameter controls the data rate of the
 * measurement probe, in Mbps. (default 10Mbps)
 *    - print: This parameter enables the measurement module to print
 *   extended per packet measurement information. The information is printed in log
 * file. (default 0)
 *
 * Copyright (C) University of Cambridge, Computer Lab, 2011
 * \author crotsos
 * \date March, 2011
 *
 */

/**
 * \ingroup openflow_packet_in
 * get the name of the module
 * \return name of module
 */
char * name()
{
  return "Pkt_in_module";
}

/**
 * \ingroup openflow_packet_in
 * empty flow tables and shcedule events.
 * \param ctx pointer to opaque context
 */
int start(oflops_context * ctx) {
  struct timeval now;
  gettimeofday(&now, NULL);
  void *b;
  char msg[1024];

  //init measurement queue
  TAILQ_INIT(&head);

  snprintf(msg, 1024,  "Intializing module %s", name());

  //log when I start module
  gettimeofday(&now, NULL);
  oflops_log(now, GENERIC_MSG, msg);
  oflops_log(now, GENERIC_MSG, cli_param);

  //start openflow session with switch
  make_ofp_hello(&b);
  oflops_send_of_mesgs(ctx, b, sizeof(struct ofp_hello));
  free(b);

  //send a message to clean up flow tables.
  printf("cleaning up flow table...\n");
  make_ofp_flow_del(&b);
  oflops_send_of_mesg(ctx, b);
  free(b);

  //Schedule end
  oflops_schedule_timer_event(ctx, 30, 0, BYESTR);

  return 0;
}

/**
 * \ingroup openflow_packet_in
 * Handle timer events
 * - BYESTR: terminate module execution
 * \param ctx pointer to opaque context
 * \param te pointer to timer event
 */
int handle_timer_event(oflops_context * ctx, struct timer_event *te)
{
  struct timeval now;
  char * str;

  gettimeofday(&now,NULL);
  str = (char *) te->arg;

  if(!strcmp(str,BYESTR)) {
    oflops_end_test(ctx,1);
  } else
    fprintf(stderr, "Unknown timer event: %s", str);
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * Calcute and log stats of packet_in packets
 * \param ctx data context of the module
 */
int
destroy(oflops_context *ctx) {
  struct entry *np;
  uint32_t mean, median, variance;
  int min_id =  INT_MAX, max_id =  INT_MIN, i;
  float loss;
  char msg[1024];
  double *data;
  struct timeval now;

  gettimeofday(&now, NULL);

  del_traffic_generator(ctx, OFLOPS_DATA1);

  data = xmalloc(pkt_in_count*sizeof(double));
  i=0;
  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
    if(((int)time_diff(&np->snd, &np->rcv) < 0) ||
        (time_diff(&np->snd, &np->rcv) > 1000000000))
        {
            fprintf(stderr, "Invalid timestamp !");
            fprintf(stderr, "Received : %ld.%09ld\n", np->rcv.tv_sec, np->rcv.tv_usec);
            fprintf(stderr, "Sent : %ld.%09ld\n", np->snd.tv_sec, np->snd.tv_usec);
            continue;
        }
    min_id = (np->id < min_id)?np->id:min_id;
    max_id = (np->id > max_id)?np->id:max_id;

    data[i++] = (double)time_diff(&np->snd, &np->rcv);
    if(print) {
      snprintf(msg, 1024, "%ld.%06ld:%ld.%06ld:%d:%d",
          np->snd.tv_sec, np->snd.tv_usec,
          np->rcv.tv_sec, np->rcv.tv_usec,
          np->id, time_diff(&np->snd, &np->rcv));
      oflops_log(now, OFPT_PACKET_IN_MSG, msg);
    }
    free(np);
  }

  if(i > 0) {
    gsl_sort (data, 1, i);

    //calculating statistical measures
    mean = (uint32_t)gsl_stats_mean(data, 1, i);
    variance = (uint32_t)gsl_stats_variance(data, 1, i);
    median = (uint32_t)gsl_stats_median_from_sorted_data (data, 1, i);
    loss = (float)i/(float)(max_id - min_id);

    snprintf(msg, 1024, "statistics:%lu:%lu:%lu:%f:%d", (long unsigned)mean, (long unsigned)median,
        (long unsigned)sqrt(variance), loss, i);
    printf("statistics:%lu:%lu:%lu:%f:%d\n", (long unsigned)mean, (long unsigned)median,
        (long unsigned)sqrt(variance), loss, i);
    oflops_log(now, GENERIC_MSG, msg);
  }
  free(data);
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * define pcap filters for each channel
 * \param ctx pointer to opaque context
 * \param ofc channel id
 * \param filter buffer to store filter
 * \param buflen max length of buffer
 */
int
get_pcap_filter(oflops_context *ctx, enum oflops_channel_name ofc,
    cap_filter **filter) {
  // Aminor hack to make the extraction code work
  if (ofc == OFLOPS_CONTROL) {
      return 0;
  }
  if (ofc == OFLOPS_DATA1) {
    *filter = malloc(sizeof(cap_filter));
    memset(*filter, 0, sizeof(cap_filter));
    (*filter)->proto = "udp";
    return 1;
    }
  return 0;
}

/**
 * \ingroup openflow_packet_in
 * handle packet_in packets received on the control channel
 * \param ctx data context of module
 * \pram pktin data of the openflow packet received
 */
int
of_event_packet_in(oflops_context *ctx, const struct ofp_packet_in * pktin) {
  struct flow fl;
  struct timeval now;
  struct pktgen_hdr *pktgen;

  oflops_gettimeofday(ctx, &now);

  pktgen = extract_pktgen_pkt(ctx, ntohs(pktin->in_port), (u_char*)pktin->data,
      ntohs(pktin->total_len), &fl);

  if(fl.tp_src != 8080) {
    fprintf(stderr, "Invalid port number; %d.\n", fl.tp_src);
    return 0;
  }

  if(pktgen == NULL) {
    fprintf(stderr, "Invalid packet received\n");
    return 0;
  }

  struct entry *n1 = xmalloc(sizeof(struct entry));
  n1->snd.tv_sec = pktgen->tv_sec;
  n1->snd.tv_usec = pktgen->tv_usec;
  memcpy(&n1->rcv, &now, sizeof(struct timeval));
  n1->id = pktgen->seq_num;
  TAILQ_INSERT_TAIL(&head, n1, entries);
  pkt_in_count++;
  return 0;
}


/**
 * \ingroup openflow_packet_in
 * Configure packet generator and start packet generation
 * \param ctx data context of the module
 */
int
handle_traffic_generation (oflops_context *ctx) {
  struct traf_gen_det det;
  struct in_addr ip;
  char *str_ip;
  init_traf_gen(ctx);
  strcpy(det.src_ip,"192.168.20.0");
  strcpy(det.dst_ip_min,"192.168.20.1");
  ip.s_addr = ntohl(inet_addr("192.168.20.0"));
  ip.s_addr += flows;
  ip.s_addr = htonl(ip.s_addr);
  str_ip = inet_ntoa(ip);
  strcpy(det.dst_ip_max, str_ip);
  strcpy(det.mac_src,"00:1e:68:9a:c5:75");
  strcpy(det.mac_dst_base,"00:15:17:7b:92:0a");
  det.mac_dst_count = 1;
  det.vlan = 0xffff;
  det.vlan_p = 0;
  det.vlan_cfi = 0;
  det.udp_src_port = 8080;
  det.udp_dst_port = 8080;
  det.pkt_size = pkt_size;
  det.delay = data_snd_interval;
  strcpy(det.flags, "IPDST_RND");
  add_traffic_generator(ctx, OFLOPS_DATA1, &det);

  start_traffic_generator(ctx);
  return 1;
}

/**
 * \ingroup openflow_packet_in
 * Initialization module with space separated string
 * \param ctx data context of the module
 * \param config_str initiliazation string
 */
int init(oflops_context *ctx, char * config_str) {
  char *pos = NULL;
  char *param = config_str;
  char *value = NULL;
  struct timeval now;

  if (strcmp(ctx->log, DEFAULT_LOG_FILE) == 0) {
      strcpy(ctx->log, logfile);
  }
  fprintf(stderr, "Log file is %s.\n", ctx->log);

  // Set print mode.
  print = ctx->print;

  //init counters
  finished = 0;
  gettimeofday(&now, NULL);
  cli_param = strdup(config_str);

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
      if(strcmp(param, "pkt_size") == 0) {
        //parse int to get pkt size
        pkt_size = strtol(value, NULL, 0);
        if((pkt_size < MIN_PKT_SIZE) && (pkt_size > MAX_PKT_SIZE))
          perror_and_exit("Invalid packet size value", 1);
      }  else if(strcmp(param, "data_rate") == 0) {
          datarate = strtol(value, NULL, 0);
          if(( datarate <= 0))
            perror_and_exit("Invalid probe rate param(Value larger than 0)", 1);
        } else

          if(strcmp(param, "flows") == 0) {
            //parse int to get pkt size
            flows = strtol(value, NULL, 0);
            if(flows <= 0)
              perror_and_exit("Invalid flow number", 1);
          } else if(strcmp(param, "print") == 0) {
            //parse int to get pkt size
            print = strtol(value, NULL, 0);
          } else
            fprintf(stderr, "Invalid parameter:%s\n", param);
          param = pos;
    }
  }

  //calculate sendind interval
  data_snd_interval = ((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (datarate * MBITS_TO_BITS)) -
      ((pkt_size * BYTE_TO_BITS * SEC_TO_NSEC) / (linkrate * MBITS_TO_BITS));
  data_snd_interval = (data_snd_interval < 0)?0:data_snd_interval;
  fprintf(stderr, "Sending data interval : %u nsec (pkt_size: %u bytes, rate: %u Mbits/sec %u Mbits/sec)\n",
          (uint32_t)data_snd_interval, (uint32_t)pkt_size, (uint32_t)datarate, (uint32_t) linkrate);
  return 0;
}
