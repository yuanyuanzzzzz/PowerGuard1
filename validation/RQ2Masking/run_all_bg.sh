#!/bin/bash

ROOT="/data/disk1/powerguard"
SCRIPT="backTra.py"

OUTFILE="background_traffic_full.csv"

# remove old file first, do not write header manually
rm -f "$OUTFILE"

# category loop
for category in tv appliance audio camera lights new; do
    echo ""
    echo "Category: $category"

    # device loop
    for dev in "$ROOT/$category"/*/; do
        devname=$(basename "$dev")
        echo "Processing $devname"

        # locate idle and active pcaps
        idle_pcap=$(ls "$dev" | grep -E "^idle_.*\.pcap$" | head -n 1)
        active_pcap=$(ls "$dev" | grep -E "^active_.*\.pcap$" | head -n 1)

        if [[ -z "$idle_pcap" || -z "$active_pcap" ]]; then
            echo "Skipping $devname because idle or active pcap is missing"
            continue
        fi

        idle_path="${dev}${idle_pcap}"
        active_path="${dev}${active_pcap}"

        # run analysis
        python3 "$SCRIPT" \
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
