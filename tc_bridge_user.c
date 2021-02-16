/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#ifndef TEST
/* pinned bpf map file of bridge mac table */
#define mac_table_file "/sys/fs/bpf/tc/globals/bpf_bridge_mac_table"

/* pinned bpf map file of bridge interfaces */
#define interfaces_file "/sys/fs/bpf/tc/globals/bpf_bridge_ifs"

#else
/* use pinned bpf map files in other bpffs for testing in network namespaces */
#define mac_table_file "/tmp/bpf-bridge-test-bpffs/tc/globals/bpf_bridge_mac_table"
#define interfaces_file "/tmp/bpf-bridge-test-bpffs/tc/globals/bpf_bridge_ifs"
#endif

/* entry in the mac address hash map */
struct mac_table_entry {
	__u32 ifindex;
	__u32 pad;
	__u64 ts;
};

/* operations when iterating interface map entries */
enum iter_if_ops {
	NONE,
	ADD,
	DELETE,
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
	int cur_key = -1;
	__u32 cur_value;
	while (bpf_map_get_next_key(interfaces_fd, &cur_key, &next_key) == 0) {
		bpf_map_lookup_elem(interfaces_fd, &next_key, &cur_value);
		cur_key = next_key;

		/* perform "op" on each entry */
		switch (op) {
		case NONE:
			return 0;
		case ADD:
			if (cur_value != 0) {
				break;
			}
			return bpf_map_update_elem(interfaces_fd, &cur_key,
						   &value, BPF_ANY);
		case DELETE:
			if (cur_value == value) {
				__u32 zero = 0;
				bpf_map_update_elem(interfaces_fd, &cur_key,
						    &zero, BPF_ANY);
			}
			break;
		case FIND:
			if (cur_value == value) {
				return 1;
			}
			break;
		case PRINT:
			if (cur_value == 0) {
				continue;
			}
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

/* add interface with ifindex to bridge */
void add_interface(__u32 ifindex) {
	if (find_interface(ifindex)) {
		return;
	}
	_iterate_interfaces(ADD, ifindex);
}

/* remove interface with ifindex from bridge */
void del_interface(__u32 ifindex) {
	_iterate_interfaces(DELETE, ifindex);
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
	struct mac_table_entry entry;
	printf("mac          --> ifindex, ts\n");
	printf("============================\n");
	while (bpf_map_get_next_key(mac_table_fd, cur_key, next_key) == 0) {
		bpf_map_lookup_elem(mac_table_fd, next_key, &entry);
		for (int i = 0; i < 6; i++) {
			printf("%02x", next_key[i]);
		}
		printf(" --> %d, %llu\n", entry.ifindex, entry.ts);
		memcpy(cur_key, next_key, 6);
	}
}

/* print usage to console */
void print_usage(char *name) {
	printf("Usage: %s [...]\n", name);
	printf("       -a <ifindex>      add interface\n");
	printf("       -d <ifindex>      remove interface\n");
	printf("       -l                list interfaces\n");
	printf("       -s                show mac addresses\n");
}

/* parse command line arguments and run everything from there */
int parse_args(int argc, char **argv) {
	int add = 0, del = 0, list = 0, show = 0;
	int ifindex;
	int opt;
	while ((opt = getopt(argc, argv, "a:d:ls")) != -1) {
		switch (opt) {
		case 'a':
			/* add an interface */
			add = 1;
			ifindex = atoi(optarg);
			break;
		case 'd':
			/* remove an interface */
			del = 1;
			ifindex = atoi(optarg);
			break;
		case 'l':
			/* list interfaces */
			list = 1;
			break;
		case 's':
			/* dump mac addresses */
			show = 1;
			break;
		default:
			print_usage(argv[0]);
			return 0;
		}
	}

	/* only allow exactly one command */
	if (add + del + list + show != 1) {
		print_usage(argv[0]);
		return 0;
	}

	if (add) {
		/* add an interface */
		add_interface(ifindex);
	}

	if (del) {
		/* remove an interface */
		del_interface(ifindex);
	}

	if (list) {
		/* list interfaces */
		dump_interfaces();
	}

	if (show) {
		/* dump mac addresses */
		dump_mac_table();
	}

	return 0;
}

int main(int argc, char **argv) {
	return parse_args(argc, argv);
}
