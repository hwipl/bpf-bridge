#!/bin/bash

CLANG=/usr/bin/clang
LLC=/usr/bin/llc

$CLANG tc_bridge_user.c -o tc_bridge_user -lbpf
$CLANG -O2 -emit-llvm -c tc_bridge_kern.c -o - -fno-stack-protector | \
	$LLC -march=bpf -filetype=obj -o tc_bridge_kern.o
