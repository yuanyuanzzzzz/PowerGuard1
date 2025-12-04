import os
import time
from datetime import datetime
from moniotr import start_moniotr, stop_moniotr

def run_capture(mac, device_folder, pcap_root):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"idle_{timestamp}"
    print(f"Starting background capture {tag}")

    start_moniotr(mac, tag)
    print("Waiting for forty minutes")
    time.sleep(40 * 60)

    end_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stop_moniotr(
        mac,
        tag,
        end_timestamp,
        "idle",
        device_folder,
        pcap_root
    )
    print("Capture finished")

if __name__ == "__main__":
    mac = "90:98:77:7b:6c:13"
    device_folder = "toshiba_tv"
    pcap_root = "../datacollection"

    run_capture(mac, device_folder, pcap_root)
