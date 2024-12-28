

clang -O2 -o xdp-firewall xdp-firewall-loader.c -lxdp -lbpf

clang -O2 -g -target bpf -c xdp-firewall.bpf.c -o xdp-firewall.bpf.o

