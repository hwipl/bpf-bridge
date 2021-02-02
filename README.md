# bpf-bridge

Build requirements:
* llvm, clang
* libbpf

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

Debug output:

```console
# cat /sys/kernel/debug/tracing/trace
```
