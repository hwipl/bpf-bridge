# bpf-bridge

Build requirements:
* llvm, clang
* libbpf

Build instructions (based on `tc-bpf(8)`):

```console
$ clang -O2 -emit-llvm -c tc_bridge_kern.c -o - | \
        llc -march=bpf -filetype=obj -o tc_bridge_kern.o
```
