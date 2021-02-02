/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tc header */
#include <linux/pkt_cls.h>

/* ethernet header */
#include <net/ethernet.h>

/* set license to gpl */
char _license[] SEC("license") = "GPL";

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

	/* get ingress interface and source mac of packet */
	__u32 ifindex = skb->ingress_ifindex;
	uint8_t *from = eth->ether_shost;
	bpf_printk("bpf_bridge: if: %d", ifindex);
	bpf_printk("bpf_bridge: from[0:3]: %x:%x:%x:", from[0], from[1],
		   from[2]);
	bpf_printk("bpf_bridge: from[3:6]: %x:%x:%x", from[3], from[4],
		   from[5]);

	return TC_ACT_OK;
}
