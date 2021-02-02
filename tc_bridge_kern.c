/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tc header */
#include <linux/pkt_cls.h>

/* set license to gpl */
char _license[] SEC("license") = "GPL";

/* forward packets */
SEC("bridge_forward")
int _bridge_forward(struct __sk_buff *skb)
{
	/* get ingress interface of packet */
	__u32 ifindex = skb->ingress_ifindex;
	bpf_printk("bpf_bridge: if: %d", ifindex);

	return TC_ACT_OK;
}
