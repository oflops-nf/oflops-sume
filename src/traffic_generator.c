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
#include "traffic_generator.h"

#include <sys/queue.h>
#include <sys/stat.h>
#include <string.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
#include <pthread.h>

/*
 * Used to iniitialize any code required by the
 * traffic generation system.
 * \param ctx the oflops context.
 */
struct pkt_details {
	int traffic_gen;
	uint32_t seq_num;
	struct timeval timestamp;
	struct ether_header *eth;
	struct ether_vlan_header *eth_vlan;
	struct iphdr *ip;
	struct udphdr *udp;
	struct tcphdr *tcp;
	void *data;
	uint32_t data_len;
	struct pktgen_hdr *pktgen;
};

/*
 * Since traffic gen will have to keep only a few traffic probes, it makes sense to
 * use a linear time search approach and reduce complexity.
 */
struct pkt_details **generator_state = NULL;


int start_user_traffic_generator(oflops_context *ctx);
int start_pktgen_traffic_generator(oflops_context *ctx);
int start_nf_traffic_generator(oflops_context *ctx);

int init_traf_gen(oflops_context *ctx) {
	if(ctx->trafficGen == PKTGEN) {
		if (setuid(0) < 0) {
			perror("setuid failed");
			exit(1);
		}
		if(system("/sbin/modprobe pktgen") != 0)
			perror_and_exit("/sbin/modprobe pktgen failed", 1);
	}
	return 1;
}


int
add_traffic_generator(oflops_context *ctx, int channel, struct traf_gen_det *det) {
	if(ctx->n_channels < channel) {
		perror_and_exit("the channel chose to generate traffic is incorrect", 1);
	}

	ctx->channels[channel].det = (struct traf_gen_det *)malloc(sizeof(struct traf_gen_det));
	memcpy(ctx->channels[channel].det , det, sizeof(struct traf_gen_det));
	return 1;
};

int del_traffic_generator(struct oflops_context *ctx, int channel) {
    if (ctx->n_channels < channel) {
        perror_and_exit("The channel to be deleted is incorrect", 1);
    }

    free(ctx->channels[channel].det);
    return 1;
}

int
printf_and_check(char *filename, char *msg) {
	FILE *ctrl = fopen(filename, "w");

	if(ctrl == NULL)
		perror_and_exit("failed to open file", 1);

	if (fprintf(ctrl, "%s\n", msg) < 0)
		perror_and_exit("failed to write command", 1);

	//printf("echo %s > %s\n", msg, filename);

	fclose(ctrl);
	return 1;
}

int
start_traffic_generator(oflops_context *ctx) {
	if(ctx->trafficGen == PKTGEN) {
		return start_pktgen_traffic_generator(ctx);
	} else if(ctx->trafficGen == USER_SPACE) {
		return start_user_traffic_generator(ctx);
	} else if(ctx->trafficGen == NF_PKTGEN) {
		return start_nf_traffic_generator(ctx);
	}else {
		return 0;
	}
}

char *
report_pktgen_traffic_generator(oflops_context *ctx) {
	int ix, len = 2048, i, size=0;
	char line[2048];
	char intf_file[1024];
	char *ret = NULL;
	for(ix = 0; ix < ctx->n_channels; ix++) {
		if(ctx->channels[ix].det != NULL) {
			//assume pktgen file have fixed format
			//skip first 18 lines
			snprintf(intf_file, 1024, "/proc/net/pktgen/%s", ctx->channels[ix].dev);
			FILE *status_file = fopen(intf_file, "r");
			for (i = 0 ; i < 18; i++) {
				if (fgets(line, len, status_file) == NULL) {
                    fprintf(stderr, "Error, couldn't copy line");
                }
			}

			ret = realloc(ret, size + sizeof("dev XXXXXXXXXXX "));
			size += snprintf(&ret[size], sizeof("dev XXXXXXXXXXX "), "dev %s ", ctx->channels[ix].dev);

			//	snprintf("dev %s:\n", ctx->channels[ix].dev);
            
		    if (fgets(line, len, status_file) == NULL) {
                fprintf(stderr, "Error, couldn't copy line");
            }
			//this is a new line
			line[strlen(line)-1] = '\0';

			ret = realloc(ret, size + strlen(line) + 1);
			memcpy(ret + size, line, strlen(line) + 1);
			size += strlen(line) + 1;
            if (fgets(line, len, status_file) == NULL) {
                fprintf(stderr, "Error, couldn't copy line");
            }
			line[strlen(line)-1] = ',';
			ret = realloc(ret, size + strlen(line) + 1);
			memcpy(ret + size - 1, line, strlen(line)  + 1);
			size += strlen(line)  - 1;
			//printf("4: %s\n", ret);
		}
	}
	return ret;
}

char *
report_traffic_generator(oflops_context *ctx) {
	if(ctx->trafficGen == PKTGEN) {
		return report_pktgen_traffic_generator(ctx);
	} else {
		return "";
	}
}

/*
 * returns the time until the next packet send.
 * @param generator the generator mumber for which we
 * have to send next packet
 * @return number of milliseconds until next packet.
 */
int
get_next_pkt(int num_generator) {
	int i, tm, min_tm = 1000, min_generator = -1;
	struct timeval now;
	gettimeofday(&now, NULL);
	for (i = 0; i < num_generator; i++) {
		if(( (tm = time_diff(&now, &generator_state[i]->timestamp)) <=0) && (tm < min_tm)) {
			min_tm = tm;
			min_generator = i;
		}
	}
	return min_generator;
}

int
send_pkt(oflops_context *ctx, int ix) {
	struct timeval now;
	struct pkt_details *state = generator_state[ix];

	gettimeofday(&now, NULL);
	state->pktgen->seq_num = htonl(state->seq_num++);
	state->pktgen->tv_sec = htonl(now.tv_sec);
	state->pktgen->tv_usec = htonl(now.tv_usec);
	oflops_send_raw_mesg(ctx, state->traffic_gen, state->data, state->data_len);
	//printf("%d: %ld.%06ld\n", state->traffic_gen, now.tv_sec, now.tv_usec);
	add_time(&state->timestamp, 0, ctx->channels[state->traffic_gen].det->delay);
	return 1;
}

int
read_mac_addr(uint8_t *addr, char *str) {
	char *p = str, *tmp;
	int i = 0;
	do {
		tmp = index(p, ':');
		if(tmp != NULL) {
			*tmp = '\0';
			tmp++;
		}
		addr[i] = (uint8_t)strtol(p, NULL, 16);
		i++;
		p = tmp;
	} while (p!= NULL);
	//fprintf(stderr, "mac %x:%x:%x:%x:%x:%x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return 0;
}

int
innitialize_generator_packet(struct pkt_details *state, struct traf_gen_det *det) {
	int l3_size;
	state->data = (void *)xmalloc(det->pkt_size);
	state->data_len = det->pkt_size;

	bzero((void *)state->data, state->data_len);
	if(state->data_len < sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
		printf("packet size is too small\n");
		return 0;
	}
	//ethernet header with default values
	state->eth_vlan = (struct ether_vlan_header *) state->data;
	state->eth = (struct ether_header *) state->data;
	read_mac_addr(state->eth->ether_dhost, det->mac_dst_base);
	read_mac_addr(state->eth->ether_shost, det->mac_src);
	if(det->vlan != 0 && det->vlan != 0xffff) {
		state->eth_vlan->tpid = htons(0x8100);
		state->eth_vlan->vid = htons(det->vlan) >>4;
		state->eth_vlan->ether_type = htons(ETHERTYPE_IP);
		state->ip = (struct iphdr *)(state->data + sizeof(struct ether_vlan_header));
		state->ip->tot_len=htons(state->data_len - sizeof(struct ether_vlan_header));
		state->udp = (struct udphdr *)
			(state->data + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
		state->tcp = (struct tcphdr *)
			(state->data + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
		l3_size = htons(state->data_len - sizeof(struct ether_vlan_header) - sizeof(struct iphdr));
		state->pktgen = (struct pktgen_hdr *)
			(state->data + sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
	} else {
		state->eth->ether_type = htons(ETHERTYPE_IP);
		state->ip = (struct iphdr *)(state->data + sizeof(struct ether_header));
		state->ip->tot_len=htons(state->data_len - sizeof(struct ether_header));
		state->udp = (struct udphdr *)
			(state->data + sizeof(struct ether_header) + sizeof(struct iphdr));
		state->tcp = (struct tcphdr *)
			(state->data + sizeof(struct ether_header) + sizeof(struct iphdr));
		l3_size = htons(state->data_len - sizeof(struct ether_header) - sizeof(struct iphdr));
		state->pktgen = (struct pktgen_hdr *)
			(state->data + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
	}
	//ip header with default values
	state->ip->protocol=1;
	state->ip->ihl=5;
	state->ip->version=4;
	//state->ip->check = htons(0x9a97);
	//total packet size without ethernet header
	state->ip->ttl = 100;
	state->ip->protocol = IPPROTO_UDP; //udp protocol
	state->ip->saddr = inet_addr(det->src_ip);
	state->ip->daddr = inet_addr(det->dst_ip_min); //test.nw_dst;

	state->ip->check=ip_sum_calc(20, (void *)state->ip);

	state->udp->source = htons(det->udp_src_port);
	state->udp->dest = htons(det->udp_dst_port);
	state->udp->len = l3_size;

	state->pktgen->magic = 0xbe9be955;

	return 1;
}

int
init_traffic_gen(oflops_context *ctx) {
	int num_generator = 0;
	int ix;

	srand(getpid());

	for(ix = 0; ix < ctx->n_channels; ix++) {
		if(ctx->channels[ix].det != NULL) {
			num_generator++;
			generator_state = (struct pkt_details **)realloc(generator_state, num_generator);
			generator_state[num_generator - 1] = (struct pkt_details *)xmalloc(sizeof(struct pkt_details));
			generator_state[num_generator - 1]->traffic_gen = ix;
			gettimeofday(&(generator_state[num_generator - 1]->timestamp), NULL);
			add_time(&(generator_state[num_generator - 1]->timestamp), 0,  (rand()%1000000));
			innitialize_generator_packet(generator_state[num_generator - 1], ctx->channels[ix].det);
		}
	}
	return num_generator;
}

int
start_user_traffic_generator(oflops_context *ctx) {
	int num_generator = init_traffic_gen(ctx), generator;
	while(ctx->should_end == 0) {
		generator = get_next_pkt(num_generator);
		if(generator >= 0 ) {
			send_pkt(ctx, generator);
		}
	};
	return 1;
}

int
start_nf_traffic_generator(oflops_context *ctx) {
    printf("Starting traffic generation\n");
    int flow_num, ix, i;
	uint32_t j;
	uint32_t seed;
    struct traf_gen_det *det;
    struct pkt_details pkt_state;
    struct pcap_pkthdr h;
    int pkt_count = 0;
    uint32_t max_packets = MAX_PACKETS;
    uint32_t iteration[] = {0,0,0,0};
    int data_to_send = 0; // in case we only want to capture data, we enable the capturing module,
    // but never load any data.

    //  for (ix = 0; ix < 4; ix++)
    //      nf_gen_reset_queue(ix);
    //nf_init(1, 0, 1);
    //for (ix = 0; ix < 4; ix++)
          //nf_gen_rate_limiter_disable(ix, 0);


    for(ix = 1; ix < ctx->n_channels; ix++) {
        if(ctx->channels[ix].det != NULL) {
            data_to_send = 1;
            det = ctx->channels[ix].det;

            if(det->pkt_count) {
                max_packets = det->pkt_count;
            } else {
                max_packets = MAX_PACKETS;
            }

            flow_num = ntohl(inet_addr(det->dst_ip_max))-ntohl(inet_addr(det->dst_ip_min))+1L;
            pkt_count = flow_num;
            if(strstr(det->flags, "IPDST_RND") != NULL)
                pkt_count = 1.2*flow_num;
            if(pkt_count) iteration[ix-1] = max_packets/pkt_count;
            else iteration[ix-1] = max_packets;
            printf("queue %d: flow_mum %d iterations %u (%s - %s)\n",
                    ix-1, pkt_count, iteration[ix-1], det->dst_ip_max, det->dst_ip_min);
        }
    }

    printf("Running nf packet gen\n");
    for(ix = 0; ix < ctx->n_channels; ix++) {
        if(ctx->channels[ix].det != NULL) {
            det = ctx->channels[ix].det;
            h.len = det->pkt_size;
            h.caplen = det->pkt_size;
            h.ts.tv_sec = 0;
            h.ts.tv_usec = 0;
            flow_num = ntohl(inet_addr(det->dst_ip_max)) - ntohl(inet_addr(det->dst_ip_min)) + 1;
            printf("Found %d flows %d pkt size iteration %d\n", flow_num, h.caplen,
                    iteration[ix - 1] );

            innitialize_generator_packet(&pkt_state, ctx->channels[ix].det);
            nf_gen_set_number_iterations (iteration[ix - 1], 1, ix-1);

            pkt_count = flow_num;
            if(strstr(det->flags, "IPDST_RND") != NULL)
                pkt_count += 0.2*flow_num;
			memcpy(&seed, (pkt_state.eth->ether_dhost + 2), sizeof(uint32_t));
			for (j = seed; j < seed + det->mac_dst_count; j++) {
				memcpy(pkt_state.eth->ether_dhost + 2, &j, sizeof(uint32_t));
				for(i = 0; i < pkt_count; i++) {
					if(strstr(det->flags, "IPDST_RND") != NULL)
						pkt_state.ip->daddr = htonl(ntohl(inet_addr(det->dst_ip_min)) + rand()%(flow_num));
					else
						pkt_state.ip->daddr = htonl(ntohl(inet_addr(det->dst_ip_min)) + i);
					pkt_state.ip->check=0x0;
					pkt_state.ip->check=htons(ip_sum_calc(20, (uint16_t *)pkt_state.ip));
					nf_gen_load_packet(&h, pkt_state.data, ix - 1, det->delay);
				}
            }
        }
    }

    nf_start(0);
    while(!ctx->should_end) {
        pthread_yield();
        if(nf_gen_finished() && (data_to_send)) {
            nf_finish();
            if(det->pkt_count) break;
            printf("Packet generation finished. Restarting...\n");
            nf_start(0);
        }
    }

    free(pkt_state.data);

    nf_finish();

    printf("Finished NetFPGA generation\n");
    usleep(10);
    return 1;
}

int
start_pktgen_traffic_generator(oflops_context *ctx) {
	int ix;
	char buf[5000];
	char intf_file[1024];
	char file[1024];
	int i = 0;
	struct stat st;

	for(ix = 0; ix < ctx->n_channels; ix++) {
		sprintf(file, "/proc/net/pktgen/kpktgend_%d", i);
		if(stat(file, &st) == 0) {
			i++;
			printf_and_check(file, "rem_device_all");
			printf_and_check(file, buf);
		}
	}
	i=0;
	//setup generic traffic generator details
	for(ix = 0; ix < ctx->n_channels; ix++) {
		if(ctx->channels[ix].det != NULL) {
			sprintf(file, "/proc/net/pktgen/kpktgend_%d", i);
			i++;
			//printf_and_check(file, "rem_device_all");
			snprintf(buf, 5000, "add_device %s", ctx->channels[ix].dev);
			printf_and_check(file, buf);
			//printf_and_check(file, "max_before_softirq 1000");
		}
	}

	//setup specific interface details
	for(ix = 0; ix < ctx->n_channels; ix++) {
		if(ctx->channels[ix].det != NULL) {
			snprintf(intf_file, 1024, "/proc/net/pktgen/%s", ctx->channels[ix].dev);

			printf_and_check(intf_file, "clone_skb 0");
			printf_and_check(intf_file, "count 0");

			snprintf(buf, 5000, "delay %d", ctx->channels[ix].det->delay);
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "pkt_size %d", ctx->channels[ix].det->pkt_size);
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "dst_min %s", ctx->channels[ix].det->dst_ip_min);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "dst_max %s", ctx->channels[ix].det->dst_ip_max);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "flag %s ", ctx->channels[ix].det->flags);//IPDST_RND");
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "vlan_id %d", ctx->channels[ix].det->vlan);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "vlan_p %d", ctx->channels[ix].det->vlan_p);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "vlan_cfi %d", ctx->channels[ix].det->vlan_cfi);
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "dst_mac %s", ctx->channels[ix].det->mac_dst_base);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "src_mac %s", ctx->channels[ix].det->mac_src);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "src_min %s", ctx->channels[ix].det->src_ip);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "src_max %s", ctx->channels[ix].det->src_ip);
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "tos 4");
			printf_and_check(intf_file, buf);


			snprintf(buf, 5000, "udp_src_max %d", ctx->channels[ix].det->udp_src_port);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "udp_src_min %d", ctx->channels[ix].det->udp_src_port);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "udp_dst_max %d", ctx->channels[ix].det->udp_dst_port);
			printf_and_check(intf_file, buf);
			snprintf(buf, 5000, "udp_dst_min %d", ctx->channels[ix].det->udp_dst_port);
			printf_and_check(intf_file, buf);

			snprintf(buf, 5000, "count %lu", ctx->channels[ix].det->pkt_count);
			printf_and_check(intf_file, buf);
		}
	}

	//start process
	printf_and_check("/proc/net/pktgen/pgctrl", "start");

	return 1;
};

int
stop_traffic_generator( oflops_context *ctx) {
	if(ctx->trafficGen == PKTGEN) {
		nf_finish();
	} else if(ctx->trafficGen == NF_PKTGEN) {
		//terminate process of packet generation
		FILE *ctrl = fopen("/proc/net/pktgen/pgctrl", "w");
		if(ctrl == NULL)
			perror_and_exit("failed to open file to terminate pktgen process", 1);

		if (fprintf(ctrl, "stop") < 0)
			perror_and_exit("failed to stop packet generation process", 1);

		fclose(ctrl);
	}

	return 1;
};

//check here whether the pktgen format is correct
struct pktgen_hdr * extract_pktgen_pkt( oflops_context *ctx, int port,
		   unsigned char *b, int len, struct flow *fl) {
  struct ether_header *ether = (struct ether_header *)b;
  struct ether_vlan_header *ether_vlan = (struct ether_vlan_header *)b;
  struct pktgen_hdr *pktgen;
  const uint8_t *data = b;
  int offset = len;
  


  if((port < 0) || (port > ctx->n_channels))
    return NULL;


  if( (ntohs(ether->ether_type) == 0x8100) && (ntohs(ether_vlan->ether_type) == 0x0800)) {
      b = b + sizeof(struct ether_vlan_header);
      offset -= sizeof(struct ether_vlan_header);
  } else if(ntohs(ether->ether_type) == 0x0800) {
      b = b + sizeof(struct ether_header);
      offset -= sizeof(struct ether_header);
  } else {
      printf("Invalid ether type found: %x\n", ntohs(ether->ether_type));
      return NULL;
  }

  struct iphdr *ip_p = (struct iphdr *) b;
  if (offset < 4*ip_p->ihl) {
      printf("capture too small for ip: %d\n", offset);
      return NULL;
  }
  b = b + 4*ip_p->ihl;
  offset -=  4*ip_p->ihl;

  if(fl!= NULL) {
      bzero(fl, sizeof(struct flow));
      //ethenet fields
      memcpy(fl->dl_src, ether->ether_shost, 6);
      memcpy(fl->dl_dst, ether->ether_dhost, 6);
      if(ntohs(ether->ether_type) == 0x8100) {
          fl->dl_type = ntohs(ether_vlan->ether_type);
          fl->dl_vlan = (0x0FFF&ntohs(ether_vlan->vid<<4));
      } else {
          fl->dl_type = ntohs(ether->ether_type);
          fl->dl_vlan = 0xFFFF;
      }

      //ip fields
      fl->nw_src = ip_p->saddr;
      fl->nw_dst = ip_p->daddr;

      fl->nw_proto = IPPROTO_UDP;
      //tcp/udp fields
      struct udphdr *udp_p = (struct udphdr *)b;
      fl->tp_src = ntohs(udp_p->source);
      fl->tp_dst = ntohs(udp_p->dest);

  }

  b += sizeof(struct udphdr);

  pktgen = (struct pktgen_hdr *)b;

  if(ctx->channels[port].cap_type == PCAP) {
      pktgen->tv_sec = ntohl(pktgen->tv_sec);
      pktgen->tv_usec = ntohl(pktgen->tv_usec);
      pktgen->seq_num = ntohl(pktgen->seq_num);
      return pktgen;
  } else if (ctx->channels[port].cap_type == NF2) {
    return nf_gen_extract_header(ctx->channels[port].nf_cap, (const u_char*)data, len);
  } else
    printf("Can't extract: Unkonwn port type %d\n",ctx->channels[port].cap_type);
      return NULL;
}

void
oflops_gettimeofday(oflops_context *ctx, struct timeval *ts) {
	if(ctx->trafficGen == NF_PKTGEN) {
		nf_cap_timeofday(ts);
	} else {
		gettimeofday(ts, NULL);
	}

}
