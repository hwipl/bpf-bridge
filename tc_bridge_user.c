/* libbpf headers */
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

/* pinned bpf map file of bridge mac table */
#define mac_table_file "/sys/fs/bpf/tc/globals/bpf_bridge_mac_table"

/* pinned bpf map file of bridge interfaces */
#define interfaces_file "/sys/fs/bpf/tc/globals/bpf_bridge_ifs"

/* specify bpf maps to be used */
const char *interface_map = interfaces_file;
const char *mac_table_map = mac_table_file;

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

/* iterate over interfaces map and perform op on each entry */
int _iterate_interfaces(enum iter_if_ops op, __u32 value) {
	/* open interfaces map */
	int interfaces_fd = bpf_obj_get(interface_map);
	if (interfaces_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", interface_map,
			strerror(errno), errno);
		return 0;
	}

	/* iterate over interface entries */
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
	int mac_table_fd = bpf_obj_get(mac_table_map);
	if (mac_table_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", mac_table_map,
			strerror(errno), errno);
		return;
	}

	/* dump all bridge mac table entries */
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC, &time);
	__u64 cur_ts = time.tv_sec * 1000000000UL + time.tv_nsec;
	__u8 next_key[6] = {0, 0, 0, 0, 0, 0};
	__u8 cur_key[6] = {0, 0, 0, 0, 0, 0};
	struct mac_table_entry entry;
	printf("mac          --> ifindex, age\n");
	printf("=============================\n");
	while (bpf_map_get_next_key(mac_table_fd, cur_key, next_key) == 0) {
		bpf_map_lookup_elem(mac_table_fd, next_key, &entry);
		for (int i = 0; i < 6; i++) {
			printf("%02x", next_key[i]);
		}
		printf(" --> %7d, %3llu\n", entry.ifindex,
		       (cur_ts - entry.ts) / 1000000000UL);
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
	printf("       -X                set interface bpf map\n"
	       "                         (default: %s)\n",
	       interfaces_file);
	printf("       -Y                set mac table bpf map\n"
	       "                         (default: %s)\n",
	       mac_table_file);
}

/* parse command line arguments and run everything from there */
int parse_args(int argc, char **argv) {
	int add = 0, del = 0, list = 0, show = 0;
	int ifindex;
	int opt;
	while ((opt = getopt(argc, argv, "a:d:lsX:Y:")) != -1) {
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
		case 'X':
			interface_map = optarg;
			break;
		case 'Y':
			mac_table_map = optarg;
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
