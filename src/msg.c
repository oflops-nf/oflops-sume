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
#include "msg.h"
#include "tlv.h"

/* @brief: Converts a match structure into the data of a packet.
 * @param match: the match structure to convert.
 * @param bufferp: pointer to a buffer to fill with the data.
 */
int match_to_payload(match_t *match, void** bufferp) {
    tlv_chain_t tlv_chain;
    memset(&tlv_chain, 0, sizeof(tlv_chain_t));
    if (match->wildcarded.in_port) {
        tlv_chain_add_in_port(&tlv_chain, match->flow.in_port, &match->wc.in_port);
    } else {
        tlv_chain_add_in_port(&tlv_chain, match->flow.in_port, NULL);
    }
    if (match->wildcarded.dl_type) {
        tlv_chain_add_dl_type(&tlv_chain, match->flow.dl_type, &match->wc.dl_type);
    } else {
        tlv_chain_add_dl_type(&tlv_chain, match->flow.dl_type, NULL);
    }
    if (match->wildcarded.dl_src) {
        tlv_chain_add_dl_src(&tlv_chain, match->flow.dl_src, match->wc.dl_src);
    } else {
        tlv_chain_add_dl_src(&tlv_chain, match->flow.dl_src, NULL);
    }
    if (match->wildcarded.dl_dst) {
        tlv_chain_add_dl_dst(&tlv_chain, match->flow.dl_dst, match->wc.dl_dst);
    } else {
        tlv_chain_add_dl_dst(&tlv_chain, match->flow.dl_dst, NULL);
    }
    if (match->wildcarded.dl_vlan) {
        // If vlan is missing, we can ingore.
        //tlv_chain_add_dl_vlan(&tlv_chain, match->flow.dl_vlan, NULL);
    } else {
        tlv_chain_add_dl_vlan(&tlv_chain, match->flow.dl_vlan, NULL);
    }
    if (match->wildcarded.nw_proto) {
        tlv_chain_add_nw_proto(&tlv_chain, match->flow.nw_proto, &match->wc.nw_proto);
    } else {
        tlv_chain_add_nw_proto(&tlv_chain, match->flow.nw_proto, NULL);
    }
    if (match->wildcarded.nw_src) {
        tlv_chain_add_nw_src(&tlv_chain, match->flow.nw_src, &match->wc.nw_src);
    } else {
        tlv_chain_add_nw_src(&tlv_chain, match->flow.nw_src, NULL);
    }
    if (match->wildcarded.nw_dst) {
        tlv_chain_add_nw_dst(&tlv_chain, match->flow.nw_dst, &match->wc.nw_dst);
    } else {
        tlv_chain_add_nw_dst(&tlv_chain, match->flow.nw_dst, NULL);
    }
    if (match->wildcarded.tp_src) {
        //tlv_chain_add_tp_src(&tlv_chain, match->flow.tp_src, &match->wc.tp_src);
    } else {
        tlv_chain_add_tp_src(&tlv_chain, match->flow.tp_src, NULL);
    }
    if (match->wildcarded.tp_dst) {
        //tlv_chain_add_tp_dst(&tlv_chain, match->flow.tp_dst, &match->wc.tp_dst);
    } else {
        tlv_chain_add_tp_dst(&tlv_chain, match->flow.tp_dst, NULL);
    }
    int32_t count = 0;
    tlv_result_t rc;
    if ((rc = tlv_chain_serialize(&tlv_chain, *bufferp, &count)) < 0) {
        fprintf(stderr, "Error during the serialisation.... Returned %d\n", rc);
        return -1;
    }
    tlv_chain_free(&tlv_chain);
    return count;
}

int payload_to_match(match_t * match, tlv_chain_t* tlv_chain) {
    int i;
    if (tlv_chain->used == 0) {
        fprintf(stderr, "[ERROR] No data in the OXM chain");
        return -1;
    }
    for(i=0; i< tlv_chain->used; i++) {
        switch (tlv_chain->object[i].field) {
            case OFPXMT_OFB_IN_PORT :
                (match->flow).in_port = *(tlv_chain->object[i].data);
                break;
            case OFPXMT_OFB_ETH_SRC : // To modify
                memcpy((match->flow).dl_src, tlv_chain->object[i].data, 6);
                break;
            case OFPXMT_OFB_ETH_DST : // To modify
                memcpy((match->flow).dl_dst, tlv_chain->object[i].data, 6);
                break;
            case OFPXMT_OFB_VLAN_VID :
                (match->flow).dl_vlan = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_ETH_TYPE :
                (match->flow).dl_type = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_IPV4_SRC :
                (match->flow).nw_src = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_IPV4_DST :
                (match->flow).nw_dst = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_IP_PROTO :
                (match->flow).nw_proto = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_TCP_SRC : case OFPXMT_OFB_UDP_SRC :
                (match->flow).tp_src = *tlv_chain->object[i].data;
                break;
            case OFPXMT_OFB_TCP_DST : case OFPXMT_OFB_UDP_DST :
                (match->flow).tp_dst = *tlv_chain->object[i].data;
                break;
            default :
                fprintf(stderr, "Flow match field %d not supported or corrupted. Ignoring.\n",
                        tlv_chain->object[i].field);
                break;
        }
    }
    return 0;
}


void
ofp_init(struct ofp_header *oh, int type, int len) {
  oh->version = OFP_VERSION;
  oh->type = type;
  oh->length = htons(len);
  oh->xid = 0;
}

int
make_ofp_hello(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_HELLO, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}


int
make_ofp_echo_req(void **buferp) {
  struct ofp_header *p;
  *buferp = xmalloc(sizeof(struct ofp_header));
  p = *(struct ofp_header **)buferp;
  ofp_init(p, OFPT_ECHO_REQUEST, sizeof(struct ofp_header));
  return sizeof(struct ofp_header);
}

int
make_ofp_feat_req(void **buferp) {
  struct ofp_hello *p;
  *buferp = xmalloc(sizeof(struct ofp_hello));
  p = *(struct ofp_hello **)buferp;
  ofp_init(&p->header, OFPT_FEATURES_REQUEST, sizeof(struct ofp_hello));
  return sizeof(struct ofp_hello);
}

/*
 * A function the creates a simple flow modification message
 * based on the content of the  flow structure and the mask details.
 * @param ofp The bufer where we create the packet.
 * @param command the type of message we want to create.
 * @param flow The flow structure from we create the match rule.
 * @param mask T
 */
void *
make_flow_mod(void *ofp, uint16_t command, uint32_t len,
	      flow_t *flow, flow_t *wildcards) {
  int length, pad_length;
  size_t real_len;

  // The match structure used for serialization.
  match_t match;
  memset(&match, 0, sizeof(match_t));


  unsigned char* payload;
  payload = malloc(2048*sizeof(unsigned char));
  match.flow = *flow;
  match.wc = *wildcards;
  match.wildcarded.in_port = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.dl_src = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.dl_dst = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.dl_vlan = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.dl_vlan = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.dl_type = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.nw_src = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.nw_dst = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.nw_proto = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.tp_src = (wildcards == NULL) ? 1 : 0;
  match.wildcarded.tp_dst = (wildcards == NULL) ? 1 : 0;
  length = match_to_payload(&match, (void**)&payload);
  pad_length = ((length + 7)/8*8 - length);
  if (length < 0) {
      fprintf(stderr, "Couldn't serialize message");
      return NULL;
  }

  real_len = htons(len + length + pad_length - 8);

  ofp = realloc(ofp, real_len);
  // The struct to fill.
  struct ofp_flow_mod *ofm = (struct ofp_flow_mod *)ofp;
  ofm->match.type = htons(OFPMT_OXM);
  ofm->match.length = htons(length + 4);
  memcpy(&ofm->match.oxm_fields[0], payload, length);
  memset(&ofm->match.oxm_fields + length, 0, pad_length);
  ofm->command = htons(command);
  ofm->out_port = 0;
  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = real_len;
  return ofp;
}

/**
 * This function can be used to create a flow modification maching @fl flow
 * match and forwarding  the packet to the @out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param fl the flow definition parameter
 * @param out_port the output port of the action.
 * @param buffer_id a buffer id for the OpenFlow header.
 * @param idle_timeout a value to timeout the respecitve flow in the flow table.
 */
int
make_ofp_flow_add(void **buferp, flow_t *fl, flow_t *wildcards, uint32_t out_port,
		  uint32_t buffer_id, uint8_t table_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  int pad_len, match_len;
  size_t len = sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action_output) +
      sizeof(struct ofp_instruction_actions);
  struct ofp_action_output action;
  struct ofp_instruction_actions* instruction = NULL;
  *buferp = xmalloc(len);
  if((*buferp = make_flow_mod(*buferp, OFPFC_ADD, len, fl, wildcards)) < 0 )
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;

  action.type = htons(OFPAT_OUTPUT);
  action.len = htons(16);
  action.port = htonl(out_port);
  action.max_len = htons(2000);

  match_len = ntohs(ofm->match.length);
  pad_len = (8 - match_len) % 8;
  pad_len = pad_len < 0 ? pad_len + 8: pad_len;

  instruction = malloc(action.len + sizeof(struct ofp_instruction_actions));
  instruction->type = htons(OFPIT_APPLY_ACTIONS);
  instruction->len = htons(sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
  memcpy(instruction->actions, &action, ntohs(action.len));

  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->priority = htons(17);
  ofm->buffer_id = htonl(-1);
  ofm->table_id = table_id;
  ofm->command = htons(OFPFC_ADD);
  ofm->cookie = 0;
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  memcpy(ofm->instructions + match_len + pad_len - sizeof(struct ofp_match) , instruction, ntohs(instruction->len));
  return len;
}

/*
 * This function can be used to create a flow modification message that creates
 * a match regarding the source and destination i pgiven as parameters. The packet
 * matched is forwarded to the out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param dst_ip a string of the destination ip to which the rule will reference.
 */
int
make_ofp_flow_add_wildcard(void **bufferp, uint32_t port) {
    struct ofp_flow_mod *p;
    struct ofp_match match;
    struct ofp_instruction_actions *instr = NULL;
    uint16_t length = sizeof(struct ofp_flow_mod) + sizeof(struct
            ofp_instruction_actions) + sizeof(struct ofp_action_output);
    *bufferp = xmalloc(length);
    p = *(struct ofp_flow_mod **)bufferp;
    ofp_init(&p->header, OFPT_FLOW_MOD, length);
    p->cookie = 0;
    p->cookie_mask = 0;
    p->table_id = 0;
    p->priority = htons(1);
    p->idle_timeout = OFP_FLOW_PERMANENT;
    p->hard_timeout = OFP_FLOW_PERMANENT;
    p->command = OFPFC_ADD;
    p->out_port = OFPP_ANY;
    p->out_group = OFPG_ANY;
    p->flags = htons(OFPFF_SEND_FLOW_REM);
    p->buffer_id = OFP_NO_BUFFER;

    instr = (struct ofp_instruction_actions *)p->instructions;
    instr->type = htons(OFPIT_APPLY_ACTIONS);
    instr->len = htons(24);

    struct ofp_action_output * action= NULL;
    action = (struct ofp_action_output *)instr->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(16);
    action->port = htonl(port);
    action->max_len = htons(2000);


    match.type = htons(OFPMT_OXM);
    match.length = htons(4);
    p->match = match;
    return length;
}


/**
 * @brief: Generate a OF 1.3 compatible table miss flow that sends packet in
 * messages to the controller
 * @param: a pointer to the location of the memory on which the packet can be found
 **/
int make_ofp_table_miss(void **bufferp) {
    struct ofp_flow_mod *p;
    struct ofp_match match;
    struct ofp_instruction_actions *instr = NULL;
    uint16_t length = sizeof(struct ofp_flow_mod) + sizeof(struct
            ofp_instruction_actions) + sizeof(struct ofp_action_output);
    *bufferp = xmalloc(length);
    p = *(struct ofp_flow_mod **)bufferp;
    ofp_init(&p->header, OFPT_FLOW_MOD, length);
    p->cookie = 0;
    p->cookie_mask = 0;
    p->table_id = 0;
    p->priority = 0;
    p->idle_timeout = OFP_FLOW_PERMANENT;
    p->hard_timeout = OFP_FLOW_PERMANENT;
    p->command = OFPFC_ADD;
    p->out_port = OFPP_ANY;
    p->flags = 0;
    p->buffer_id = OFP_NO_BUFFER;

    instr = (struct ofp_instruction_actions *)p->instructions;
    instr->type = htons(OFPIT_APPLY_ACTIONS);
    instr->len = htons(24);

    struct ofp_action_output * action= NULL;
    action = (struct ofp_action_output *)instr->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(16);
    action->port = htonl(OFPP_CONTROLLER);
    action->max_len = htons(2000);


    match.type = htons(OFPMT_OXM);
    match.length = htons(4);
    p->match = match;
    return length;
}


/*
 * This function can be used to create a flow modification maching @fl flow
 * match and forwarding  the packet to the @out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param fl the flow definition parameter
 * @param out_port the output port of the action.
 * @param buffer_id a buffer id for the OpenFlow header.
 * @param idle_timeout a value to timeout the respecitve flow in the flow table.
 */
int
make_ofp_flow_add_actions(void **buferp, flow_t *fl, flow_t * wildcards, uint8_t *actions, uint8_t action_len,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  int pad_len, match_len;
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + action_len + sizeof(struct ofp_instruction_actions);
  *buferp = xmalloc(len);
  if((*buferp = make_flow_mod(*buferp, OFPFC_ADD, len, fl, wildcards)) == NULL)
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(buffer_id);
  ofm->table_id = 0;
  ofm->out_port = OFPP_ANY;
  ofm->cookie = 0;
  ofm->command = htons(OFPFC_ADD);
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  ofm->priority = htons(17);
  match_len = ntohs(ofm->match.length);
  pad_len = (8 - match_len) % 8;
  pad_len = pad_len < 0 ? pad_len + 8: pad_len;
  struct ofp_instruction_actions *instructions = malloc(action_len + sizeof(struct ofp_instruction_actions));
  instructions->type = htons(OFPIT_APPLY_ACTIONS);
  instructions->len = htons(action_len + sizeof(struct ofp_instruction_actions));
  memcpy(instructions->actions, actions, action_len);
  memcpy(ofm->instructions + match_len + pad_len - sizeof(struct ofp_match) , instructions, instructions->len);
  return len;
}

int
make_ofp_flow_modify_output_port(void **buferp, flow_t *fl, flow_t *wildcards, uint32_t out_port,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  int pad_len, match_len;
  struct ofp_action_output action;
  struct ofp_instruction_actions* instruction = NULL;
  size_t len = sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action_output) +
      sizeof(struct ofp_instruction_actions);
  //struct ofp_action_output *p = NULL;
  *buferp = xmalloc(len);
  if((*buferp = make_flow_mod(*buferp, OFPFC_MODIFY, len, fl, wildcards)) == NULL )
    fail("Error: falied to create flow modification packet.");
  //struct ofp_flow_mod *ofm = *buferp;
  //p = (struct ofp_action_output *)ofm->instructions;
  //ofm->idle_timeout = htons(idle_timeout);
  //ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  //ofm->buffer_id = htonl(-1); //buffer_id);
  //ofm->command = htons(OFPFC_MODIFY);
  //ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  //p->type = htons(OFPAT_OUTPUT);
  //p->len = htons(8);
  //p->port = htons(out_port);
  //p->max_len = htons(2000);
  //return len;
  struct ofp_flow_mod *ofm = *buferp;

  action.type = htons(OFPAT_OUTPUT);
  action.len = htons(16);
  action.port = htonl(out_port);
  action.max_len = htons(2000);

  match_len = ntohs(ofm->match.length);
  pad_len = (8 - match_len) % 8;
  pad_len = pad_len < 0 ? pad_len + 8: pad_len;

  instruction = malloc(action.len + sizeof(struct ofp_instruction_actions));
  instruction->type = htons(OFPIT_APPLY_ACTIONS);
  instruction->len = htons(sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
  memcpy(instruction->actions, &action, ntohs(action.len));

  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->priority = htons(17);
  ofm->buffer_id = htonl(-1);
  ofm->table_id = 0;
  ofm->command = htons(OFPFC_ADD);
  ofm->cookie = 0;
  ofm->flags = htons(OFPFF_SEND_FLOW_REM);
  memcpy(ofm->instructions + match_len + pad_len - sizeof(struct ofp_match) , instruction, ntohs(instruction->len));
  return len;
}

int
make_ofp_flow_modify(void **buferp, flow_t *fl, flow_t *wildcards, char *actions,  uint16_t action_len,
		  uint32_t buffer_id, uint16_t idle_timeout) {
  //size of the packet we are sending .
  size_t len = sizeof(struct ofp_flow_mod) + action_len;
  *buferp = xmalloc(len);
  if(make_flow_mod(*buferp, OFPFC_MODIFY, len, fl, wildcards) < 0 )
    fail("Error: falied to create flow modification packet.");
  struct ofp_flow_mod *ofm = *buferp;
  memcpy(((void *)ofm)+sizeof(struct ofp_flow_mod), (void *)actions, action_len);
  ofm->idle_timeout = htons(idle_timeout);
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); //buffer_id);
  ofm->command = htons(OFPFC_ADD);
  return len;
}



/*
 * This function can be used to create a flow modification message that creates
 * a match regarding the source and destination i pgiven as parameters. The packet
 * matched is forwarded to the out_port.
 * @param buferp a pointer to the location of the memory on which the new packet can be found.
 * @param dst_ip a string of the destination ip to which the rule will reference.
 */
int
make_ofp_flow_del(void **buferp) {
  uint16_t len = sizeof(struct ofp_flow_mod);
  *buferp = xmalloc(len);
  struct ofp_flow_mod *ofm = *buferp;
  memset(ofm, 0, len);

  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(len);

  ofm->cookie = 0;
  ofm->cookie_mask = 0;
  ofm->table_id = htons(OFPTT_ALL);
  ofm->idle_timeout = 0;
  ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
  ofm->buffer_id = htonl(-1); // Ignored all in all...
  ofm->priority = htonl(-1);
  ofm->command = OFPFC_DELETE;
  ofm->out_port = htonl(OFPP_ANY); //htons(OFPP_ANY); //
  ofm->out_group = OFPG_ANY;
  ofm->match.type = htons(OFPMT_OXM);
  ofm->match.length = htons(4);

  return len;
}



int
make_ofp_flow_get_stat(void **buferp, int trans_id) {
  struct ofp_flow_stats_request *reqp = NULL;
  struct ofp_multipart_request *headp = NULL;

//  flow_t wildcards, mask;
//  wildcarded_t wildcarded;
//  match_t match;
//  memset(&wildcarded, 1, sizeof(wildcarded_t));
//  memset(&mask, 1, sizeof(flow_t));
//  memset(&wildcards, 1, sizeof(flow_t));
//  match.flow = mask;
//  match.wildcarded = wildcarded;
//  match.wc = wildcards;
//  match_to_payload(&match, (void**)&payload);

  int len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_flow_stats_request);

  //allocate memory
  *buferp = xmalloc(len);
  memset(*buferp, 0, len);
  headp =  (struct ofp_multipart_request *)*buferp;

  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_MULTIPART_REQUEST;
  headp->header.length = htons(len);
  headp->header.xid = htonl(trans_id);
  headp->type = htons(OFPMP_FLOW);
  headp->flags = htonl(OFPMPF_REQ_MORE);

  reqp = (struct ofp_flow_stats_request *)headp->body;
  //memcpy(&reqp->match, &payload, sizeof(payload));
  reqp->table_id = OFPTT_ALL;
  reqp->out_port = OFPP_ANY;
  reqp->out_group = OFPG_ANY;
  reqp->cookie = 0;
  reqp->cookie_mask = 0;
  reqp->match.type = htons(OFPMT_OXM);
  reqp->match.length = htons(4);
  return len;
}

int
make_ofp_aggr_flow_stats(void **buferp, int trans_id) {
  struct ofp_aggregate_stats_request *reqp = NULL;
  struct ofp_multipart_request *headp = NULL;

  int len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_aggregate_stats_request);

  //allocate memory
  *buferp = xmalloc(len);
  memset(*buferp, 0, len);
  headp =  (struct ofp_multipart_request *)*buferp;

  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_MULTIPART_REQUEST;
  headp->header.length = htons(len);
  headp->header.xid = htonl(trans_id);
  headp->type = htons(OFPMP_AGGREGATE);
  headp->flags = htonl(OFPMPF_REQ_MORE);

  reqp = (struct ofp_aggregate_stats_request *)headp->body;
  reqp->table_id = OFPTT_ALL;
  reqp->out_group = OFPG_ANY;
  reqp->out_port = OFPP_ANY;
  reqp->cookie = 0;
  reqp->cookie_mask = 0;
  reqp->match.type = htons(OFPMT_OXM);
  reqp->match.length = htons(4);

  return len;
}

int make_ofp_port_get_stat(void **buferp) {
//#if OFP_VERSION == 0x97
//  struct ofp_multipart_request *headp = NULL;
//  *buferp = xmalloc(sizeof(struct ofp_multipart_request));
//  headp =  (struct ofp_multipart_request *)*buferp;
//  headp->header.version = OFP_VERSION;
//  headp->header.type = OFPT_MULTIPART_REQUEST;
//  headp->header.length = htons(sizeof(struct ofp_multipart_request));
//  headp->type = htons(OFPMP_PORT_STATS);
//  return sizeof(struct ofp_multipart_request);
//#elif OFP_VERSION == 0x01
  struct ofp_multipart_request *headp = NULL;
  struct ofp_port_stats_request *port = NULL;
  int len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_port_stats_request);
  *buferp = xmalloc(len);
  headp =  (struct ofp_multipart_request *)*buferp;
  headp->header.version = OFP_VERSION;
  headp->header.type = OFPT_MULTIPART_REQUEST;
  headp->header.length = htons(len);
  headp->type = htons(OFPMP_PORT_STATS);
  port = (struct ofp_port_stats_request *)(*buferp+sizeof(struct ofp_multipart_request));
  port->port_no = htons(OFPP_ANY);
  return len;
//#endif
//  return -1;
}

char *
generate_packet(struct flow test, size_t len) {
  char *buf = (char *)xmalloc(len);
  printf("flow:%x\n", test.dl_dst[5]);
  bzero((void *)buf, len);
  if(len < sizeof(struct ether_vlan_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
    printf("packet size is too small\n");
    return NULL;
  }

  //ethernet header with default values
  struct ether_vlan_header * eth = (struct ether_vlan_header * ) buf;
  memcpy(eth->ether_dhost, test.dl_dst,  OFP_ETH_ALEN);
  memcpy(eth->ether_shost, test.dl_src,  OFP_ETH_ALEN);
  eth->tpid = htons(0x8100);
  eth->vid = test.dl_vlan>>4;
  eth->ether_type = test.dl_type;
  //ip header with default values
  struct iphdr * ip = (struct iphdr *) (buf + sizeof(struct ether_vlan_header));
  ip->protocol=1;
  ip->ihl=5;
  ip->version=4;
  ip->check = htons(0x9a97);
  //total packet size without ethernet header
  ip->tot_len=htons(len - sizeof(struct ether_vlan_header));
  ip->ttl = 10;
  ip->protocol = test.nw_proto; //udp protocol
  ip->saddr = test.nw_src;
  ip->daddr = test.nw_dst;

  if(test.nw_proto == IPPROTO_UDP) {
    //  case IPPROTO_UDP:
    //udp header with default values
    struct udphdr *udp = (struct udphdr *)
      (buf + sizeof(struct ether_vlan_header) + sizeof(struct iphdr));
    udp->source = test.tp_src;
    udp->dest = test.tp_dst;
    udp->len = htons(len - sizeof(struct ether_vlan_header) - sizeof(struct iphdr));
    //   break;
    //default:
  } else {
    printf("unimplemented protocol %x\n", test.nw_proto);
    return NULL;
  }
  return buf;

}

uint32_t
extract_pkt_id(const char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct ether_vlan_header *ether_vlan = (struct ether_vlan_header *)b;

  //  printf("%x %x\n",ntohl(ether->ether_type),ntohl(ether_vlan->ether_type));

  if( (ntohs(ether->ether_type) == 0x8100) && (ntohs(ether_vlan->ether_type) == 0x0800)) {
    b = b + sizeof(struct ether_vlan_header);
    len -= sizeof(struct ether_vlan_header);
  } else if(ntohs(ether->ether_type) == 0x0800) {
    b = b + sizeof(struct ether_header);
    len -= sizeof(struct ether_header);
  } else {
    return 0;
  }

  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl)
    return 0;
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;

  b += sizeof(struct udphdr);
  uint32_t ret = *((uint32_t *)b);
  return ret;
}
