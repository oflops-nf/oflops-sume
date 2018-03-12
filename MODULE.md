# How to write a new module

## Interface of a module

A module is used as a shared library by oflops.
The interface of a module is the following

```C
struct test_module {
    const char * (*name)(void);

    int (*init)(oflops_context *ctx, char * config_str);

    int (*destroy)(oflops_context *ctx);
    int (*get_pcap_filter)(oflops_context *ctx, enum oflops_channel_name ofc,
            cap_filter **filter);
    int (*start)(oflops_context * ctx);
    int (*handle_pcap_event)(oflops_context *ctx, struct pcap_event * pe, enum oflops_channel_name ch);
    int (*of_event_packet_in)(oflops_context *ctx, const struct ofp_packet_in * ofph);
    int (*of_event_flow_removed)(oflops_context *ctx, const struct ofp_flow_removed * ofph);
    int (*of_event_echo_request)(oflops_context *ctx, const struct ofp_header * ofph);
    int (*of_event_port_status)(oflops_context *ctx, const struct ofp_port_status * ofph);
    int (*of_event_other)(oflops_context *ctx, const struct ofp_header * ofph);
    int (*handle_timer_event)(oflops_context * ctx, struct timer_event * te);
    void * symbol_handle;
    int (*handle_snmp_event)(oflops_context * ctx, struct snmp_event * se);
    int (*handle_traffic_generation)(oflops_context * ctx);

} test_module;

```

The functions `name`, `init` and `destroy` must be defined.

The other functions have the default comportment of doing nothing, ignoring events...
To write a module, you may write a comportment for the functions you are interested in.

For exemple, the [openflow_packet_in](./src/example_modules/openflow_packet_in/pktin.c) module
defines 'handle_timer_event', 'get_pcap_filter', 'of_event_packet_in', 'handle_snmp_event' and
'handle_traffic_generation'.

More information can be found in [the test module header file](./src/test_module.h).
It also defines a lot of useful constants:

```C
 // String for scheduling events
 #define BYESTR "bye bye"
 #define SND_ACT "send action"
 #define SNMPGET "snmp get"
 #define ECHO "echo"
 #define GETSTAT "getstat"
 #define ECHO_REQUEST "echo request"
 #define SND_PKT "send packet"
 #define SND_FLOW "send flow"

 // Useful conversions constants
 #define SEC_TO_USEC (uint64_t)1000000
 #define SEC_TO_NSEC (int64_t)1e9
 #define BYTE_TO_BITS (uint64_t)8
 #define MBITS_TO_BITS (uint64_t)1024*1024

 // Packet size limits
 #define MIN_PKT_SIZE 64
 #define MAX_PKT_SIZE 1500
```

And includes many common C library like `gsl/gsl_statistics.h`, `gsl/gsl_sort.h`, `sys/queue.h`, `math.h`


## Additionnal information on a module writing.

### Arguments

A module can handle arguments. Indeed, if you look at the `init` function:

```
int (*init)(oflops_context *ctx, char * config_str);
```

It will be fed by oflops with the trailing arguments given in the command line.

If you use a configuration file, you can give the following line:

```
module: ({
    path="/root/oflops-turbo-devel/oflops-turbo/example_modules/openflow_packet_in/.libs/libof_packet_in.so";
    param="pkt_size=1024 probe_snd_interval=10000 print=1";
});
```

The `param` will be fed to `init` as `config_str`.

### Good behaviour

Using a queue to store the packets during runtime and postprocess all the
packets can be good idea (for example for statistics) because oflpos can be CPU
intensive when it retrieves the packets from the board.
