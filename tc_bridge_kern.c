/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tc header */
#include <linux/pkt_cls.h>

/* ethernet header */
#include <net/ethernet.h>

/* maximum age of a mac in the mac table (300s) */
#define MAX_MAC_AGE 300000000000

/* set license to gpl */
char _license[] SEC("license") = "GPL";

/* map definitions */
#define PIN_GLOBAL_NS		2
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

/* array map of indexes of all interfaces of the bridge */
struct bpf_elf_map SEC("maps") bpf_bridge_ifs = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(int),
	.size_value = sizeof(__u32),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 16,
};

/* entry in the mac address hash map below */
struct mac_table_entry {
	__u32 ifindex;
	__u32 pad;
	__u64 ts;
};

/* hash map for mapping mac address to interface index */
struct bpf_elf_map SEC("maps") bpf_bridge_mac_table = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.size_key = sizeof(struct ether_addr),
	.size_value = sizeof(struct mac_table_entry),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 2048,
};

/* clone packet in skb and forward it from interface index in_ifindex to
 * out_ifindex
 */
void _forward_clone(struct __sk_buff *skb, __u32 *in_ifindex,
		    __u32 *out_ifindex)
{
	if (!in_ifindex || !out_ifindex) {
		return;
	}
	if (*out_ifindex == 0 || *out_ifindex == *in_ifindex) {
		return;
	}
	bpf_clone_redirect(skb, *out_ifindex, 0);
}

/* forward packet in skb received on interface index in_ifindex to all
 * interfaces of the bridge (flooding)
 */
void _forward_flood(struct __sk_buff *skb, __u32 *in_ifindex)
{
	for (int i = 0; i < 16; i++) {
		int key = i;
		__u32 *out_ifindex = bpf_map_lookup_elem(&bpf_bridge_ifs, &key);
		_forward_clone(skb, in_ifindex, out_ifindex);
	}
}

/* forward packets */
SEC("bridge_forward")
int _bridge_forward(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ether_header *eth = data;

	/* check size of packet */
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	/* add ingress interface and source mac of packet to macs map */
	__u32 in_ifindex = skb->ingress_ifindex;
	uint8_t *src_mac = eth->ether_shost;
	__u64 ts = bpf_ktime_get_ns();
	struct mac_table_entry in_entry = {
		.ifindex = in_ifindex,
		.ts = ts,
	};
	bpf_map_update_elem(&bpf_bridge_mac_table, src_mac, &in_entry, BPF_ANY);

	/* forward multicast packet */
	uint8_t *dst_mac = eth->ether_dhost;
	if (dst_mac[0] & 1) {
		_forward_flood(skb, &in_ifindex);
		return TC_ACT_OK;
	}

	/* forward unicast packet */
	struct mac_table_entry *out_entry =
		bpf_map_lookup_elem(&bpf_bridge_mac_table, dst_mac);
	if (!out_entry) {
		_forward_flood(skb, &in_ifindex);
		return TC_ACT_OK;
	}
	if (ts - out_entry->ts > MAX_MAC_AGE) {
		/* entry is too old */
		bpf_map_delete_elem(&bpf_bridge_mac_table, dst_mac);
		_forward_flood(skb, &in_ifindex);
		return TC_ACT_OK;
	}
	return bpf_redirect(out_entry->ifindex, 0);
}
