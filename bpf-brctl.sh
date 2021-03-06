#!/bin/bash

# tools
TC=/usr/bin/tc
BRIDGE_USER=./tc_bridge_user

# bpf file system and pinned bpf map file names
BPFFS="${BPFFS:-/sys/fs/bpf}"
INTERFACE_MAP="${INTERFACE_MAP:-$BPFFS/tc/globals/bpf_bridge_ifs}"
MAC_TABLE_MAP="${MAC_TABLE_MAP:-$BPFFS/tc/globals/bpf_bridge_mac_table}"

# add device to to bridge
function addif {
	dev=$1

	# attach bpf program to device
	$TC qdisc add dev "$dev" clsact
	$TC filter add dev "$dev" ingress bpf \
		direct-action obj tc_bridge_kern.o sec bridge_forward

	# add device to bpf interface map
	$BRIDGE_USER -X "$INTERFACE_MAP" -Y "$MAC_TABLE_MAP" -a "$dev"
}

# remove device from bridge
function delif {
	dev=$1

	# remove device from bpf interface map
	$BRIDGE_USER -X "$INTERFACE_MAP" -Y "$MAC_TABLE_MAP" -d "$dev"

	# remove bpf program from device
	$TC qdisc del dev "$dev" clsact
}

# show interfaces of bridge
function show {
	$BRIDGE_USER -X "$INTERFACE_MAP" -Y "$MAC_TABLE_MAP" -l
}

# show mac addresses
function showmacs {
	$BRIDGE_USER -X "$INTERFACE_MAP" -Y "$MAC_TABLE_MAP" -s
}

# print usage and exit
USAGE="Usage: $0 [commands]
        addif <device>		add interface to bridge
        delif <device>          remove interface from bridge
        show                    show bridge interfaces
        showmacs                show mac addresses
"
function usage {
	echo -n "$USAGE"
	exit 1
}

# require at least 1 command line argument
if [[ "$#" -lt 1 ]]; then
      usage
fi

# handle command line arguments without extra parameters
case "$1" in
	"show")
		show
		exit 0
		;;
	"showmacs")
		showmacs
		exit 0
		;;
esac

# require at least 2 command line arguments
if [[ "$#" -lt 2 ]]; then
      usage
fi

# handle command line arguments with one extra parameter
case "$1" in
	"addif")
		# add interface to bridge
		addif "$2"
		;;
	"delif")
		# remove interface from bridge
		delif "$2"
		;;
	*)
		usage
esac
