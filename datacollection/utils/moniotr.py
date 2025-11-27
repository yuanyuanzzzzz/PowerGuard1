import os
import re
import time
import subprocess

def get_ip_from_mac(mac_address: str) -> str:
    """
    Returns the IP address corresponding to the given MAC address by checking the ARP table.
    Assumes the ARP table is already populated (e.g., by prior communication).
    """
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True)
        arp_output = result.stdout

        mac_address = mac_address.lower().replace('-', ':')
        
        for line in arp_output.splitlines():
            if mac_address in line.lower():
                match = re.search(r"\(([\d.]+)\)", line)
                if match:
                    return match.group(1)

        return None  # MAC not found
    except Exception as e:
        print(f"Error looking up IP for MAC {mac_address}: {e}")
        return None

def normalize_mac(mac):
    parts = mac.split(":")
    normalized = [part.lstrip("0") or "0" for part in parts]
    return ":".join(normalized)

def start_moniotr(mac, tag):
    norm_mac = normalize_mac(mac)
    print(f"🟢 Starting Mon(IoT)r capture: {tag} (normalized MAC: {norm_mac})")
    result = subprocess.run([
        "sudo", "/opt/moniotr/bin/tag-experiment.sh", "start", norm_mac, tag
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    if "Tagged experiment already exists" in result.stdout:
        print(f"⚠️ Tag '{tag}' already exists — stopping and restarting.")
        subprocess.run([
            "sudo", "/opt/moniotr/bin/tag-experiment.sh", "stop", norm_mac, tag
        ], check=True)
        subprocess.run([
            "sudo", "/opt/moniotr/bin/tag-experiment.sh", "start", norm_mac, tag
        ], check=True)

def stop_moniotr(mac, tag, timestamp, state, device_folder, pcap_dir):
    norm_mac = normalize_mac(mac)
    print(f"🔴 Stopping Mon(IoT)r capture: {tag} (normalized MAC: {norm_mac})")
    result = subprocess.run([
        "sudo", "/opt/moniotr/bin/tag-experiment.sh", "stop", norm_mac, tag
    ], stdout=subprocess.PIPE, text=True)

    lines = result.stdout.splitlines()
    pcap_line = next((line for line in lines if ".pcap" in line), None)

    if pcap_line:
        original_path = pcap_line.split("Created:")[-1].strip().split(" ")[0]
        device_path = os.path.join(pcap_dir, device_folder)
        os.makedirs(device_path, exist_ok=True)
        
        new_pcap_path = os.path.join(device_path, f"{state}_{timestamp}.pcap")
        subprocess.run(["sudo", "mv", original_path, new_pcap_path], check=True)
        print(f"📁 Moved .pcap to: {new_pcap_path}")
    else:
        print("⚠️ .pcap file not found in Mon(IoT)r output")
