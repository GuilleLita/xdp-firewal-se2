/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "./xdp-struct-definition.h"
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#define VLAN_MAX_DEPTH 10
#define MAX_RULES 10




struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct datarec);
        __uint(max_entries, 1);
}xdp_counter SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct rule);
        __uint(max_entries, MAX_RULES);
}rules_map SEC(".maps");

struct hdr_cursor {
        void *pos;
};

struct vlan_hdr {
        __be16  h_vlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr)
{
        struct ethhdr *eth = nh->pos;
        int hdrsize = sizeof(*eth);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

        /* Byte-count bounds check; check if current pointer + size of header
         * is after data_end.
         */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *ethhdr = eth;
        vlh = nh->pos;
        h_proto = eth->h_proto;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */

        /*Remember Ethernet Headers might have VLAN TAGS :)*/
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto))
                        break;

                if (vlh + 1 > data_end)
                        break;

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        nh->pos = vlh;
        return h_proto; /* ATTENTION : network-byte-order */
}


static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct iphdr **iphdr)
{
    struct iphdr *ip = nh->pos;
    int hdrsize = sizeof(*ip);

    if (nh->pos + hdrsize  > data_end)
        return -1;

    nh->pos+= hdrsize;
    *iphdr = ip;

    return ip->protocol; 
}


static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct udphdr **udphdr)
{
    struct udphdr *udp = nh ->pos;
    int hdrsize = sizeof(*udp);

    if (nh->pos + hdrsize  > data_end)
        return -1;

    nh->pos += hdrsize;
    *udphdr = udp;

    return udp->source; 
}


SEC("xdp")
int firewall(struct xdp_md *ctx){
 
   struct datarec *rec;
   
    __u32 key = 0;
    rec = bpf_map_lookup_elem(&xdp_counter, &key);


    if (!rec)
    {
        return XDP_ABORTED;
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct hdr_cursor safe;
    struct hdr_cursor *nh = &safe;
   
    
    nh->pos = data;
    
    int index = 0;
    struct ethhdr *ethhdr;  
    int icmp_sequence=1;
    

    //If ARP package, pass
    __u16 eth_type = parse_ethhdr(nh, data_end, &ethhdr);
   if (eth_type == bpf_htons(ETH_P_ARP))
    {
        return XDP_PASS;
    }
    
    //If not IP, pass
    if (eth_type != bpf_htons(ETH_P_IP))
    {   
        return XDP_PASS;
    }
    //If IP, look rule
    else{

        struct iphdr *iphdr;
        int ip_type = parse_iphdr(nh, data_end, &iphdr);
        bpf_spin_lock(&rec->lock);
        rec->totalpackages++;
        bpf_spin_unlock(&rec->lock);

        if(ip_type == -1){
            return XDP_PASS;
        }
        else{
            bpf_printk("PRE_RULE: src_ip %d, protocol %d", iphdr->addrs.saddr, iphdr->protocol);

            for(int i = 0; i<MAX_RULES; i++){
                __u32 key = i;

                struct rule *rule = bpf_map_lookup_elem(&rules_map, &key);

                if(!rule){
                    break;
                }

                if(!rule->active){
                    continue;
                }

                bpf_printk("RULE %d: src_ip %d, protocol %d", key, rule->src_ip, rule->protocol);

                if(rule->src_ip != 0 && iphdr->addrs.saddr != rule->src_ip){
                    continue;
                }

                if(rule->dst_ip != 0 && iphdr->addrs.daddr != rule->dst_ip){
                    continue;
                }

                if(rule->protocol != 0 && iphdr->protocol != rule->protocol){
                    continue;
                }

                //If all parameters are 0 the rule is matched. 

                bpf_printk("RULE %d MATCHED!!!", key);

                //Matched rule. do action
                bpf_spin_lock(&rec->lock);
                rec->blockedcount++;
                bpf_spin_unlock(&rec->lock);
                return rule->action;

            }
            
            return XDP_PASS;

        }
        
    }

    return XDP_PASS;


}

char _license[] SEC("license") = "GPL";