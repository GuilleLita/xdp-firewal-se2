/* This fileis used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#include <linux/types.h>
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data to be stored on the map */
        struct datarec {
                __u64 blockedcount;
                __u64 totalpackages;
                struct bpf_spin_lock lock;
        };

        struct rule {
                __u8 active; //Array maps initialize to 0, so this prevents looking for rules not manually initialized.
                __u8 action;
                __u32 src_ip;
                __u32 dst_ip;
                __u32 protocol;
        };

#endif 

#ifndef  MAP_SIZE
#define MAP_SIZE 100
#endif