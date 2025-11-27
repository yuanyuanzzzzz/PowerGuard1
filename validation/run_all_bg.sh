#!/bin/bash

ROOT="/data/disk1/powerguard"
SCRIPT="validation/backTra.py"

OUTFILE="background_traffic_full.csv"

# CSV header
echo "category,device,pps_idle,pps_active,pps_var_idle,pps_var_active,size_mean_idle,size_mean_active,size_var_idle,size_var_active,proto_tls_idle,proto_tls_active,proto_tcp_idle,proto_tcp_active,proto_udp_idle,proto_udp_active,proto_mdns_idle,proto_mdns_active,proto_ssdp_idle,proto_ssdp_active,proto_arp_idle,proto_arp_active,proto_dhcp_idle,proto_dhcp_active,proto_other_idle,proto_other_active,inout_ratio_idle,inout_ratio_active,num_packets_idle,num_packets_active,bts_idle,bts_active" > $OUTFILE

# category loop
for category in appliance audio camera lights tv; do
    echo ""
    echo "Category: $category"

    # device loop
    for dev in "$ROOT/$category"/*/; do
        devname=$(basename "$dev")
        echo "Processing $devname"

        # locate idle and active pcaps
        idle_pcap=$(ls "$dev" | grep -E "^idle_.*\.pcap$" | head -n 1)
        active_pcap=$(ls "$dev" | grep -E "^active_.*\.pcap$" | head -n 1)

        # check availability
        if [[ -z "$idle_pcap" || -z "$active_pcap" ]]; then
            echo "Skipping $devname because idle or active pcap is missing"
            continue
        fi

        idle_path="${dev}${idle_pcap}"
        active_path="${dev}${active_pcap}"

        # run analysis
        python3 $SCRIPT \
            --idle "$idle_path" \
            --active "$active_path" \
            --tmpdir "tmp_${devname}" \
            --category "$category" \
            --device "$devname" \
            --out "$OUTFILE"

    done
done

echo ""
echo "Background traffic extraction completed"
echo "Results saved in $OUTFILE"
