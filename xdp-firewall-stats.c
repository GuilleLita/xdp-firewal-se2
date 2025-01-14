#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>  
#include <signal.h>
#include <net/if.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "xdp-struct-definition.h"

#include "arpa/inet.h"




int main(int argc, char *argv[]){

    int  ifindex, map_fd;
    struct bpf_object *bpf_obj;

    struct datarec stats;


    if (argc != 2) {
        printf("Usage: %s IFNAME\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return 1;
    }

    const char *pin_dir =  "/sys/fs/bpf";
    char if_dir[4096];
    int len = snprintf(if_dir, 4096, "%s/%s", pin_dir, argv[1]);
    if (len < 0) {
		fprintf(stderr, "ERR: creating map parent dirname\n");
		return 1;
	}

    const char *map_name =  "xdp_counter";
    char map_dir[4096];
    len = snprintf(map_dir, 4096, "%s/%s", if_dir, map_name);
    if (len < 0) {
		fprintf(stderr, "ERR: creating map dirname\n");
		return 1; 
	}

    map_fd = bpf_obj_get(map_dir);
	if (map_fd < 0) {
        fprintf(stderr, "ERR: Opening map file\n");
		return 1;
	}
     
    __u32 key = 0;
    if ((bpf_map_lookup_elem(map_fd, &key, &stats)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
    
    printf("Total IP packets: %lld\n", stats.totalpackages);
    printf("Total IP packets Treated: %lld\n", stats.blockedcount);



    return 0;

}