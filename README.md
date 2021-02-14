# bpf-bridge

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

See below for more details.

## user space part

Building with gcc:

```console
$ gcc tc_bridge_user.c -o tc_bridge_user -lbpf
```

Building with clang:

```console
$ clang tc_bridge_user.c -o tc_bridge_user -lbpf
```

## kernel part

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
