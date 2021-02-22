#!/bin/bash

BUILD=./build.sh
IP=/usr/bin/ip
TC=/usr/bin/tc
PING=/usr/bin/ping
BRCTL=./bpf-brctl.sh

MOUNT=/usr/bin/mount
UMOUNT=/usr/bin/umount

# show verbose output?
VERBOSE=false

# names of network namespaces
NS_BRIDGE="bpf-bridge-test-bridge"
NS_CLIENT1="bpf-bridge-test-client1"
NS_CLIENT2="bpf-bridge-test-client2"

# extra bpf file system and pinned bpf map file names
export BPFFS=/tmp/bpf-bridge-test-bpffs
INTERFACE_MAP=$BPFFS/tc/globals/bpf_bridge_ifs
MAC_TABLE_MAP=$BPFFS/tc/globals/bpf_bridge_mac_table

# build everything for testing
function build {
	echo "Building everything..."
	$BUILD
}

# create testing network namespaces
function create_namespaces {
	echo "Creating testing network namespaces..."
	$IP netns add $NS_BRIDGE
	$IP netns add $NS_CLIENT1
	$IP netns add $NS_CLIENT2

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Network namespaces:"
	$IP netns list
}

# delete testing network namespaces
function delete_namespaces {
	echo "Removing testing network namespaces..."
	$IP netns delete $NS_BRIDGE
	$IP netns delete $NS_CLIENT1
	$IP netns delete $NS_CLIENT2

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Network namespaces:"
	$IP netns list
}

# mount bpf filesystem in bridge network namespace
function mount_bpffs {
	echo "Mounting extra bpf filesystem..."
	mkdir $BPFFS
	$MOUNT -t bpf bpf $BPFFS

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "BPF folders:"
	$IP netns exec $NS_BRIDGE $MOUNT | grep "type bpf"
	$IP netns exec $NS_BRIDGE ls $BPFFS
}

# umount bpf filesystem in bridge network namespace
function umount_bpffs {
	echo "Umounting extra bpf filesystem..."
	$UMOUNT $BPFFS
	rmdir $BPFFS

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "BPF folders:"
	$IP netns exec $NS_BRIDGE $MOUNT | grep "type bpf"
}

# add veth interfaces to network namespaces
function add_veths {
	echo "Adding veth interfaces..."
	$IP netns exec $NS_BRIDGE $IP link add veth0 type veth peer name veth00
	$IP netns exec $NS_BRIDGE $IP link add veth1 type veth peer name veth10

	$IP netns exec $NS_BRIDGE $IP link set veth00 netns $NS_CLIENT1
	$IP netns exec $NS_BRIDGE $IP link set veth10 netns $NS_CLIENT2

	$IP netns exec $NS_BRIDGE $IP link set veth0 up
	$IP netns exec $NS_BRIDGE $IP link set veth1 up
	$IP netns exec $NS_CLIENT1 $IP link set veth00 up
	$IP netns exec $NS_CLIENT2 $IP link set veth10 up

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Bridge interfaces:"
	$IP netns exec $NS_BRIDGE $IP link show

	echo "Client1 interfaces:"
	$IP netns exec $NS_CLIENT1 $IP link show

	echo "Client2 interfaces:"
	$IP netns exec $NS_CLIENT2 $IP link show
}

# delete veth interfaces from network namespaces
function delete_veths {
	echo "Removing veth interfaces..."
	$IP netns exec $NS_BRIDGE $IP link delete veth0 type veth
	$IP netns exec $NS_BRIDGE $IP link delete veth1 type veth

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Bridge interfaces:"
	$IP netns exec $NS_BRIDGE $IP link show

	echo "Client1 interfaces:"
	$IP netns exec $NS_CLIENT1 $IP link show

	echo "Client2 interfaces:"
	$IP netns exec $NS_CLIENT2 $IP link show
}


# add ip addresses to client veth interfaces
function add_ips {
	echo "Adding ip addresses to client veth interfaces..."
	$IP netns exec $NS_CLIENT1 $IP address add 192.168.1.1/24 dev veth00
	$IP netns exec $NS_CLIENT2 $IP address add 192.168.1.2/24 dev veth10

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Client1 interface addresses:"
	$IP netns exec $NS_CLIENT1 $IP address show dev veth00

	echo "Client2 interface addresses:"
	$IP netns exec $NS_CLIENT2 $IP address show dev veth10
}

# add interfaces to bridge
function add_interfaces {
	echo "Adding interfaces to bridge..."
	$IP netns exec $NS_BRIDGE $BRCTL addif veth0
	$IP netns exec $NS_BRIDGE $BRCTL addif veth1

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Bridge tc filters:"
	$IP netns exec $NS_BRIDGE $TC filter show dev veth0 ingress
	$IP netns exec $NS_BRIDGE $TC filter show dev veth1 ingress

	echo "Bridge interface map interfaces:"
	$IP netns exec $NS_BRIDGE $BRCTL show
}

# delete interfaces from bridge
function delete_interfaces {
	echo "Removing interfaces from bridge..."
	$IP netns exec $NS_BRIDGE $BRCTL delif veth0
	$IP netns exec $NS_BRIDGE $BRCTL delif veth1

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	echo "Bridge tc filters:"
	$IP netns exec $NS_BRIDGE $TC filter show dev veth0 ingress
	$IP netns exec $NS_BRIDGE $TC filter show dev veth1 ingress

	echo "Bridge interface map interfaces:"
	$IP netns exec $NS_BRIDGE $BRCTL show

	echo "Bridge mac address table:"
	$IP netns exec $NS_BRIDGE $BRCTL showmacs
}

# run test(s)
function run_test {
	echo "Running test..."

	# test connectivity with ping from client1 to client2
	$IP netns exec $NS_CLIENT1 $PING -c 3 192.168.1.2

	if [[ "$VERBOSE" == false ]]; then
		return
	fi

	# show bridge mac address table
	echo "Bridge mac address table:"
	$IP netns exec $NS_BRIDGE $BRCTL showmacs

	# dump bpf maps
	echo "Bridge bpf_bridge_ifs:"
	bpftool map dump pinned $INTERFACE_MAP
	echo "Bridge bpf_bridge_mac_table:"
	bpftool map dump pinned $MAC_TABLE_MAP

	# disable bridge interfaces
	echo "Disabling bridge interfaces..."
	$IP netns exec $NS_BRIDGE $IP link set veth0 down
	$IP netns exec $NS_BRIDGE $IP link set veth1 down

	# wait
	echo "Waiting 3 seconds..."
	sleep 3
	echo "Bridge mac address table:"
	$IP netns exec $NS_BRIDGE $BRCTL showmacs

	# wait
	echo "Waiting 3 seconds..."
	sleep 3
	echo "Bridge mac address table:"
	$IP netns exec $NS_BRIDGE $BRCTL showmacs

	echo "Waiting 3 seconds..."
	sleep 3
	echo "Bridge mac address table:"
	$IP netns exec $NS_BRIDGE $BRCTL showmacs
}

# set verbose mode with command line argument "-v"
if [[ "$1" == "-v" ]]; then
	VERBOSE=true
fi

# build code
build

# setup test environment
create_namespaces
mount_bpffs
add_veths
add_ips
add_interfaces

# run tests
run_test

# cleanup test environment
delete_interfaces
delete_veths
umount_bpffs
delete_namespaces
