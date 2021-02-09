/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <errno.h>

/* pinned bpf map file of bridge mac table */
#define mac_table_file "/sys/fs/bpf/tc/globals/bpf_bridge_mac_table"

/* dump content of bridge mac address table to console */
void dump_mac_table() {
	/* open bridge mac table */
	int mac_table_fd = bpf_obj_get(mac_table_file);
	if (mac_table_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", mac_table_file,
			strerror(errno), errno);
		return;
	}

	/* dump all bridge mac table entries */
	__u8 next_key[6] = {0, 0, 0, 0, 0, 0};
	__u8 cur_key[6] = {0, 0, 0, 0, 0, 0};
	__u32 ifindex;
	printf("mac          --> ifindex\n");
	printf("========================\n");
	while (bpf_map_get_next_key(mac_table_fd, cur_key, next_key) == 0) {
		bpf_map_lookup_elem(mac_table_fd, next_key, &ifindex);
		for (int i = 0; i < 6; i++) {
			printf("%02x", next_key[i]);
		}
		printf(" --> %d\n", ifindex);
		memcpy(cur_key, next_key, 6);
	}
}

void main() {
	dump_mac_table();
}
