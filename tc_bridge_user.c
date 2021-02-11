/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <errno.h>

/* pinned bpf map file of bridge mac table */
#define mac_table_file "/sys/fs/bpf/tc/globals/bpf_bridge_mac_table"

/* pinned bpf map file of bridge interfaces */
#define interfaces_file "/sys/fs/bpf/tc/globals/bpf_bridge_ifs"

/* operations when iterating interface map entries */
enum iter_if_ops {
	NONE,
	FIND,
	PRINT,
};

/* iterate over interfaces map and call f(key, value) on each entry */
int _iterate_interfaces(enum iter_if_ops op, __u32 value) {
	/* open interfaces map */
	int interfaces_fd = bpf_obj_get(interfaces_file);
	if (interfaces_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", interfaces_file,
			strerror(errno), errno);
		return 0;
	}

	/* dump interface entries */
	int next_key = -1;
	int cur_key;
	__u32 cur_value;
	while (bpf_map_get_next_key(interfaces_fd, &cur_key, &next_key) == 0) {
		bpf_map_lookup_elem(interfaces_fd, &next_key, &cur_value);
		cur_key = next_key;

		/* skip empty entries */
		if (cur_value == 0) {
			continue;
		}

		/* perform "op" on each entry */
		switch (op) {
		case FIND:
			if (cur_value == value) {
				return 1;
			}
			break;
		case PRINT:
			printf("%2d:   %d\n", cur_key, cur_value);
			break;
		}
	}

	return 0;
}

/* find interface with ifindex in bridge */
int find_interface(__u32 ifindex) {
	return _iterate_interfaces(FIND, ifindex);
}

/* dump bridge interfaces to console */
void dump_interfaces() {
	printf("slot: ifindex\n");
	printf("=============\n");
	_iterate_interfaces(PRINT, 0);
}

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

int main() {
	dump_interfaces();
	dump_mac_table();
	return 0;
}
