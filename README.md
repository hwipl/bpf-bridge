# bpf-bridge

Simple implementation of a software ethernet bridge using bpf and tc.

## Building

Build requirements:
* llvm, clang, (gcc)
* libbpf

Quick build:

```console
$ ./build.sh
```

Testing:

```console
# ./test.sh
```

## Usage

You can use the script `bpf-brctl.sh` to configure the bridge:

```
Usage: ./bpf-brctl.sh [commands]
        addif <device>          add interface to bridge
        delif <device>          remove interface from bridge
        show                    show bridge interfaces
        showmacs                show mac addresses
```

## Examples

Adding network interface `eth3` to the bridge:

```console
# ./bpf-brctl.sh addif eth3
```

Removing network interface `eth3` from the bridge:

```console
# ./bpf-brctl.sh delif eth3
```

Showing network interfaces of the bridge:

```console
# ./bpf-brctl.sh show
slot: ifindex
=============
 0:   3
 1:   5
```

Showing known mac addresses of the bridge:

```console
# ./bpf-brctl.sh showmacs
mac          --> ifindex, age
=============================
ba55347b0dfe -->       3,   0
3a40c855bd49 -->       5,   0
```

## Details

See below for more details.

### user space part

Building with gcc:

```console
$ gcc tc_bridge_user.c -o tc_bridge_user -lbpf
```

Building with clang:

```console
$ clang tc_bridge_user.c -o tc_bridge_user -lbpf
```

### kernel part

Build instructions (based on `tc-bpf(8)`):

```console
$ clang -O2 -emit-llvm -c tc_bridge_kern.c -o - -fno-stack-protector | \
        llc -march=bpf -filetype=obj -o tc_bridge_kern.o
```

Loading:

```console
# tc qdisc add dev <dev> clsact
# tc filter add dev <dev> ingress bpf direct-action obj tc_bridge_kern.o \
        sec bridge_forward
```

Unloading:

```console
# tc qdisc del dev <dev> clsact
```

Debug output (if present):

```console
# cat /sys/kernel/debug/tracing/trace
```

Dump mac table:

```console
# bpftool map dump pinned /sys/fs/bpf/tc/globals/bpf_bridge_mac_table
```
