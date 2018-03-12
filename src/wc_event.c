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
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <pthread.h>

#include "utils.h"
#include "traffic_generator.h"
#include "test_module.h"
#include "wc_event.h"


/***************************** local types
*/
typedef struct wc_event
{
    struct timeval eventtime;
    void (*fun)(void *);
    void * arg;
    oflops_context *ctx;
    int id;
} wc_event;

struct list {
    struct ev_timer *tm;
    struct list *next;
};

struct list* timer_list = NULL;

static int WC_EVENT_ID=0;

void insert_timer(struct ev_timer *tm) {
    struct list *tmp;

    tmp = malloc(sizeof(struct list));
    tmp->tm = tm;
    if (timer_list == NULL) {
        timer_list = tmp;
        timer_list->next = NULL;
    } else {
        tmp->next = timer_list;
        timer_list = tmp;
    }
};

void free_list() {
    while (timer_list != NULL) {
        struct list* prev = timer_list;
        //free(timer_list->tm->data);
        free(timer_list->tm);
        timer_list = timer_list->next;
        free(prev);
    }
};

static void event_callback(EV_P_ ev_timer *w, int revents) {
    wc_event * data = (wc_event *)w->data;
    timer_event te;

    te.timer_id = data->id;
    te.arg = data->arg;
    te.sched_time  = data->eventtime;
    // func is ignored by oflops
    data->ctx->curr_test->handle_timer_event(data->ctx, &te);
}

static  void event_idle_callback(EV_P_ ev_timer *w, int revents)
{
    return;
}


/*************************************************
*  The main event loop of the event subsystem.
*/
void *event_loop(oflops_context *ctx) {
	struct ev_timer *tm;

	tm = (struct ev_timer *)malloc(sizeof(struct ev_timer));
	bzero(tm, sizeof(struct ev_timer));
	ev_timer_init(tm, event_idle_callback, 1.0, 1.0);
	tm->data = ctx;
    insert_timer(tm);
	ev_timer_start(ctx->timer_loop, tm);

	ev_run(ctx->timer_loop, 0);

	return NULL;
}

int wc_event_ev_add(oflops_context *ctx, void (*fun)(void *), void *arg, struct timeval key, 
		uint32_t sec, uint32_t usec){
    wc_event * data;
    struct ev_timer *tm;
    double delay;

    data = malloc_and_check(sizeof(wc_event));
    assert(data != NULL);
    data->fun=fun;
    data->eventtime=key;
    data->arg=arg;
    data->id = WC_EVENT_ID++;
    data->ctx = ctx;
//    oflops_gettimeofday(ctx, &now);
//    delay = time_diff_d(&now, &key);
    tm = (struct ev_timer *)malloc(sizeof(struct ev_timer));
    bzero(tm, sizeof(struct ev_timer));

	delay = (double)sec + ((double)usec)/1e6;
    ev_timer_init(tm, event_callback, delay, 0.0);
    tm->data = data;
    insert_timer(tm);
    ev_timer_start(ctx->timer_loop, tm);
    return 0;
}
