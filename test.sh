#!/bin/bash

BUILD=./build.sh
IP=/usr/bin/ip
TC=/usr/bin/tc
PING=/usr/bin/ping
BRIDGE_USER=./tc_bridge_user

CAT=/usr/bin/cat
MOUNT=/usr/bin/mount
UMOUNT=/usr/bin/umount

# build everything for testing
echo "Building everything..."
$BUILD test

# create testing network namespaces
NS_BRIDGE="bpf-bridge-test-bridge"
NS_CLIENT1="bpf-bridge-test-client1"
NS_CLIENT2="bpf-bridge-test-client2"

echo "Creating testing network namespaces..."
$IP netns add $NS_BRIDGE
$IP netns add $NS_CLIENT1
$IP netns add $NS_CLIENT2

echo "Network namespaces:"
$IP netns list

# mount bpf filesystem in network bridge network namespace
echo "Mounting extra bpf filesystem..."
BPFFS=/tmp/bpf-bridge-test-bpffs
mkdir $BPFFS
$MOUNT -t bpf bpf $BPFFS

echo "BPF folders:"
$IP netns exec $NS_BRIDGE $MOUNT | grep "type bpf"
$IP netns exec $NS_BRIDGE ls $BPFFS

# add veth interfaces to network namespaces
echo "Adding veth interfaces..."
$IP netns exec $NS_BRIDGE $IP link add veth0 type veth peer name veth00
$IP netns exec $NS_BRIDGE $IP link add veth1 type veth peer name veth10

$IP netns exec $NS_BRIDGE $IP link set veth00 netns $NS_CLIENT1
$IP netns exec $NS_BRIDGE $IP link set veth10 netns $NS_CLIENT2

$IP netns exec $NS_BRIDGE $IP link set veth0 up
$IP netns exec $NS_BRIDGE $IP link set veth1 up
$IP netns exec $NS_CLIENT1 $IP link set veth00 up
$IP netns exec $NS_CLIENT2 $IP link set veth10 up

echo "Bridge interfaces:"
$IP netns exec $NS_BRIDGE $IP link show

echo "Client1 interfaces:"
$IP netns exec $NS_CLIENT1 $IP link show

echo "Client2 interfaces:"
$IP netns exec $NS_CLIENT2 $IP link show

# add ip addresses to client veth interfaces
echo "Adding ip addresses to client veth interfaces..."
$IP netns exec $NS_CLIENT1 $IP address add 192.168.1.1/24 dev veth00
$IP netns exec $NS_CLIENT2 $IP address add 192.168.1.2/24 dev veth10

echo "Client1 interface addresses:"
$IP netns exec $NS_CLIENT1 $IP address show dev veth00

echo "Client2 interface addresses:"
$IP netns exec $NS_CLIENT2 $IP address show dev veth10

# attach bpf program to bridge
echo "Attaching bpf program to bridge..."
$IP netns exec $NS_BRIDGE $TC qdisc add dev veth0 clsact
$IP netns exec $NS_BRIDGE $TC filter add dev veth0 ingress bpf \
	direct-action obj tc_bridge_kern.o sec bridge_forward
$IP netns exec $NS_BRIDGE $TC qdisc add dev veth1 clsact
$IP netns exec $NS_BRIDGE $TC filter add dev veth1 ingress bpf \
	direct-action obj tc_bridge_kern.o sec bridge_forward

echo "Bridge tc filters:"
$IP netns exec $NS_BRIDGE $TC filter show dev veth0 ingress
$IP netns exec $NS_BRIDGE $TC filter show dev veth1 ingress

# add interfaces to bridge interface map
echo "Adding interfaces to bridge interface map..."
veth0_ifindex=$($IP netns exec $NS_BRIDGE $CAT /sys/class/net/veth0/ifindex)
veth1_ifindex=$($IP netns exec $NS_BRIDGE $CAT /sys/class/net/veth1/ifindex)
$IP netns exec $NS_BRIDGE $BRIDGE_USER -a "$veth0_ifindex"
$IP netns exec $NS_BRIDGE $BRIDGE_USER -a "$veth1_ifindex"

echo "Bridge interface map interfaces:"
$IP netns exec $NS_BRIDGE $BRIDGE_USER -l

# test connectivity with ping from client1 to client2
$IP netns exec $NS_CLIENT1 $PING -c 10 192.168.1.2

# show bridge mac address table
echo "Bridge mac address table:"
$IP netns exec $NS_BRIDGE $BRIDGE_USER -s

# delete interfaces from bridge interface map
echo "Removing interfaces from bridge interface map..."
$IP netns exec $NS_BRIDGE $BRIDGE_USER -d "$veth0_ifindex"
$IP netns exec $NS_BRIDGE $BRIDGE_USER -d "$veth1_ifindex"

echo "Bridge interface map interfaces:"
$IP netns exec $NS_BRIDGE $BRIDGE_USER -l

# delete bpf program from bridge
echo "Removing bpf program from bridge..."
$IP netns exec $NS_BRIDGE $TC qdisc del dev veth0 clsact
$IP netns exec $NS_BRIDGE $TC qdisc del dev veth1 clsact

echo "Bridge tc filters:"
$IP netns exec $NS_BRIDGE $TC filter show dev veth0 ingress
$IP netns exec $NS_BRIDGE $TC filter show dev veth1 ingress

# delete veth interfaces
echo "Removing veth interfaces..."
$IP netns exec $NS_BRIDGE $IP link delete veth0 type veth
$IP netns exec $NS_BRIDGE $IP link delete veth1 type veth

echo "Bridge interfaces:"
$IP netns exec $NS_BRIDGE $IP link show

echo "Client1 interfaces:"
$IP netns exec $NS_CLIENT1 $IP link show

echo "Client2 interfaces:"
$IP netns exec $NS_CLIENT2 $IP link show

# unmount extra bpffs
echo "Umounting extra bpf filesystem..."
$UMOUNT $BPFFS
rmdir $BPFFS

echo "BPF folders:"
$IP netns exec $NS_BRIDGE $MOUNT | grep "type bpf"

# delete testing network namespaces again
echo "Removing testing network namespaces..."
$IP netns delete $NS_BRIDGE
$IP netns delete $NS_CLIENT1
$IP netns delete $NS_CLIENT2

echo "Network namespaces:"
$IP netns list