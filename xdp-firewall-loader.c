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


static int ifindex;
struct xdp_program *prog = NULL;



static void poll_stats(int map_fd, int map_fd_time, int interval) {
    int key = 0;
    struct datarec value;

    printf("\n");
    while (1) {

        if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
            fprintf(stderr, "Error in bpf_map_lookup_elem\n");
            break;
        }
        printf("Total IP packets: %lld\n", value.totalpackages);
        printf("Total IP packets Treated: %lld\n", value.blockedcount);
        sleep(interval);
    }

}

int main(int argc, char *argv[])
{
    int prog_fd, map_fd, map_fd_time, ret, rules_map_fd;
    struct bpf_object *bpf_obj;

    if (argc != 2) {
        printf("Usage: %s IFNAME\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return 1;
    }
    char *filename = "xdp-firewall.bpf.o";
    char *progname = "firewall";

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    xdp_opts.open_filename = filename;
    xdp_opts.prog_name = progname;
    xdp_opts.opts = &opts;
        
    struct xdp_program *prog = xdp_program__create(&xdp_opts);
    int  err = libxdp_get_error(prog);
        if (err) {
                char errmsg[1024];
                libxdp_strerror(err, errmsg, sizeof(errmsg));
                fprintf(stderr, "ERR: loading program: %s\n", errmsg);
            return 1    ;
        }

    ret = xdp_program__attach(prog, ifindex, XDP_MODE_UNSPEC, 0);
    if (ret) {
        printf("Error, Set xdp fd on %d failed\n", ifindex);
        return ret;
    }

    prog_fd = xdp_program__fd(prog);
        if (prog_fd < 0) {
                fprintf(stderr, "ERR: xdp_program__fd failed: %d\n", prog_fd);
        return 1;
        }
    printf("XDP-PROGRAM LOADED\n");

    bpf_obj = xdp_program__bpf_obj(prog);
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xdp_counter");
    rules_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "rules_map");
    if (map_fd < 0 || rules_map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
        return rules_map_fd;
    }

    

    //Regla que dropea los paquetes ICMP de una IP
    struct rule rule1;
    rule1.active = 1;
    rule1.action = XDP_DROP;
    const char* ip = "192.168.1.109";//IP de mi ordenador
    rule1.src_ip = inet_addr(ip);
    rule1.protocol = IPPROTO_ICMP;
    printf("src_ip = %d\n", rule1.src_ip);
    rule1.dst_ip = 0;

    //OTRA Regla que dropea los paquetes ICMP de una IP
    struct rule rule2;
    rule2.active = 1;
    rule2.action = XDP_DROP;
    ip = "192.168.1.40";//IP de otro dispositivo
    rule2.src_ip = inet_addr(ip);
    rule2.protocol = IPPROTO_ICMP;
    printf("src_ip 2= %d\n", rule2.src_ip);
    rule2.dst_ip = 0;

    
    __u32 key = 0;
    struct rule value = rule1;
    if (bpf_map_update_elem(rules_map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Error, failed to set map rule value\n");
        return 1;
    }
    key = 1;
    value = rule2;
    if (bpf_map_update_elem(rules_map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Error, failed to set map rule value\n");
        return 1;
    }

    poll_stats(map_fd,map_fd_time, 2);

    return 0;
}
