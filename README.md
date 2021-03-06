#            OFLOPS: OpenFlow Operations Per Second

A benchmarking suite for OpenFlow switches.  If you are looking
to benchmark controllers, check out `.src//cbench` included with this package.

## SUMMARY

Oflops is a modular framework for testing and benchmarking OpenFlow-enabled
switches.  It uses libpcap and raw packet writing to simultaneously
emulate an OpenFlow controller and client traffic. It ships with
an existing suite of tests and users are encouraged to develop their
own tests. It has been developped to use the [NetFPGA SUME](https://github.com/NetFPGA/NetFPGA-SUME-public/wiki)
as a 4x10GBs packet generator.

## QUICK INSTALL

To clone the git repository : `git clone --recursive https://github.com/oflops-nf/oflops-sume.git`

To build the documentation, you will need `doxygen` and `doxygen-latex` for the pdf version.

The following C libraries are required for Oflops:

- libsnmp-dev
- libconfig-dev
- libpcap-dev
- libevent-dev
- libgsl0-dev
- OpenFlow : git://gitosis.stanford.edu/openflow

Debian/Ubuntu: ` sudo apt-get install libsnmp-dev libpcap-dev libconfig-dev libevent-dev libgsl0-dev doxygen doxygen-latex`

Fedora/Centos: `sudo yum install net-snmp-devel libpcap-devel libconfig-devel libevent-devel gsl-devel doxygen`

To clone OpenFlow: `git clone git://gitosis.stanford.edu/openflow`

From the src directory do:

```sh
sh boot.sh          #   if no ./configure file
./configure
make
make docs           # build API documentation in ./doc
sudo make install
```


### Note:
Having root access to the computer you are working on is mandatory since
Oflops strongly relies on libpcap which requires root privileges.


## Quick run: local software switch


1. Setup your software OpenFlow switch
    1. Make sure that any program that broadcasts on all interfaces is **off**, e.g., IPv6 routing.

   See OpenFlow README for more examples.

    2. Bring up some virtual interfaces 
        ```sh
        ip link add type veth           # add veth0,veth1
        ip link add type veth           # add veth2,veth3
        ip link add type veth           # add veth3,veth4
        for p in 0 1 2 3 4 5 ; do ifconfig veth$p up; done # Up all interfaces.
        ```
   
    3. Start the software switch:
    
        ```sh
        ofdatapath punix:/var/run/dp0.sock -i veth0,veth2 &
        ofprotocol tcp:localhost:6633 unix:/var/run/dp0.sock
        ```
        [see OpenFlow reference implementation INSTALL file for more detail]

2. Become root. Oflops uses libpcap and raw sockets, so you need root
privileges.

3. Run oflops with lo as the "control" interface and the other half of the
        `vethXX` links as two "data" interfaces

```
oflops -c lo -d veth1 -d veth3 /path/to/test/module
```

### Note :
Running oflops directly from the source directory is a pity because of
        libtool.  The following is a sample invocation for inside the src directory.

```
./oflops -c lo -d veth1 -d veth3 ./example_modules/openflow_packet_in/.libs/libof_packet_in.so
```

It is way better to write configuration files.

## Quick run: hardware switch

1. Setup your hardware switch:

    1. Physically connect at least one ethernet cable from your switch to a
 dedicated ethernet interface on the box where you will run oflops, e.g., `eth1`.
 In this context, dedicated means that no other applications are using that
 interface.  Also, some tests may require more than one data channel, so it is
 may be necesary to connect more cables to more interfaces, e.g., `eth2`.

    2. Point your switch's controller connection to the IP oflops machine on a
  free port, e.g., `6633`.   Note the interface matching the IP address, e.g.,
  `eth0`.  Note that this cannot be the same interface as in 1.a. unless you're
  doing in-band control

2. Become root.

3. Run Oflops with `eth0` as the "control" interface and `eth1` and `eth2` as "data"
interfaces

```
oflops -c eth0 -d eth1 -d eth2 /path/to/test/module
```

## Using configuration files.

Oflops is able to read and parse configuration files.
Some example configuration files can be found in [sample_configs](./sample_configs/).

## Existing Modules

TODO

## Writing New Modules

A more complete guide can be found [here](./MODULE.md).

In a few steps you can :
1) Start by reading code [here](./example_modules/) and reading the interface in [test_module.h](./test_module.h)
2) Use [the documentation](./doc/) for reference (did you `make docs`?)
3) Contribute them back to Oflops!

## History

Oflops-SUME is based on Oflops-turbo which can be found [here](https://github.com/OFLOPS-Turbo/oflops-turbo)
