if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi


export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

#Tell LIBXDP to skip dispatcher, this prevents an error when loading eBPF programs via loader.
#This creates the need to unload it manually with "sudo xdp-loader unload --all eth0"
export LIBXDP_SKIP_DISPATCHER=1 


#Unload previous xdp programs
sudo xdp-loader unload --all "$@"

./xdp-firewall "$@"

echo "BPF program unloaded"