/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tc header */
#include <linux/pkt_cls.h>

/* ethernet header */
#include <net/ethernet.h>

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

/* hash map for mapping mac address to interface index */
struct bpf_elf_map SEC("maps") bpf_bridge_mac_table = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.size_key = sizeof(struct ether_addr),
	.size_value = sizeof(__u32),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 2048,
};

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
	__u32 ifindex = skb->ingress_ifindex;
	uint8_t *src_mac = eth->ether_shost;
	bpf_map_update_elem(&bpf_bridge_mac_table, src_mac, &ifindex, BPF_ANY);

	return TC_ACT_OK;
}
