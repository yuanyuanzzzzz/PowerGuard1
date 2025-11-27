import subprocess
import pandas as pd
import numpy as np
import argparse
import os
from collections import Counter


###############################################################################
# tshark extraction with ports
###############################################################################

def extract_pcap_csv(pcap_path, csv_path):
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-E", "header=y",
        "-E", "separator=,",
        "-n"
    ]
    subprocess.run(cmd, stdout=open(csv_path, "w"), check=True)


###############################################################################
# device ip detection (refined)
###############################################################################

def detect_device_ip(df):
    # all addresses seen
    ips = list(df["ip.src"].dropna().values) + list(df["ip.dst"].dropna().values)
    if len(ips) == 0:
        return None

    # filter multicast and broadcast
    def ok(ip):
        if ip.startswith("224.") or ip.startswith("239."):
            return False
        if ip == "255.255.255.255":
            return False
        return True

    ips = [ip for ip in ips if ok(ip)]
    if len(ips) == 0:
        return None

    # keep LAN candidates
    lan = [ip for ip in ips if ip.startswith("192.168.") or
                                ip.startswith("10.") or
                                ip.startswith("172.")]
    if len(lan) == 0:
        return None

    return Counter(lan).most_common(1)[0][0]


###############################################################################
# port-based protocol classifier
###############################################################################

def classify_protocol(row):
    ports = []

    for p in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        v = row.get(p)
        if str(v).isdigit():
            ports.append(int(v))

    if 5353 in ports:
        return "MDNS"
    if 1900 in ports:
        return "SSDP"
    if 67 in ports or 68 in ports:
        return "DHCP"
    if 443 in ports:
        return "TLS"

    proto = str(row.get("_ws.col.Protocol"))
    if proto == "UDP":
        return "UDP"
    if proto == "TCP":
        return "TCP"
    if proto == "ARP":
        return "ARP"
    return "OTHER"


###############################################################################
# compute per-second PPS variance
###############################################################################

def compute_pps_var(df):
    if df.empty:
        return 0.0
    t = df["frame.time_epoch"].astype(float)
    t0 = t.min()
    bins = ((t - t0)).astype(int)
    series = bins.value_counts().sort_index()
    return series.var()


###############################################################################
# main analysis
###############################################################################

def analyze(df, device_ip):
    df = df.dropna(subset=["frame.time_epoch", "frame.len", "ip.src", "ip.dst"])
    df["frame.time_epoch"] = df["frame.time_epoch"].astype(float)
    df["frame.len"] = df["frame.len"].astype(int)

    # protocol mapping
    df["proto"] = df.apply(classify_protocol, axis=1)

    # packet rate
    if len(df) > 1:
        dur = df["frame.time_epoch"].max() - df["frame.time_epoch"].min()
        pps = len(df) / dur if dur > 0 else 0
    else:
        pps = 0

    # pps variance
    pps_var = compute_pps_var(df)

    # size stats
    size_mean = df["frame.len"].mean()
    size_var = df["frame.len"].var()

    # protocol proportions
    total = len(df)
    proto_counts = df["proto"].value_counts()

    def prop(p):
        return float(proto_counts.get(p, 0)) / total if total > 0 else 0.0

    # inbound outbound
    inbound = (df["ip.dst"] == device_ip).sum()
    outbound = (df["ip.src"] == device_ip).sum()
    inout_ratio = inbound / (outbound + 1e6)

    return {
        "pps": pps,
        "pps_var": pps_var,
        "size_mean": size_mean,
        "size_var": size_var,
        "proto_tls": prop("TLS"),
        "proto_tcp": prop("TCP"),
        "proto_udp": prop("UDP"),
        "proto_mdns": prop("MDNS"),
        "proto_ssdp": prop("SSDP"),
        "proto_arp": prop("ARP"),
        "proto_dhcp": prop("DHCP"),
        "proto_other": prop("OTHER"),
        "inout_ratio": inout_ratio,
        "num_packets": len(df)
    }


###############################################################################
# background traffic strength (refined)
###############################################################################

def compute_bts(idle, active):
    bts_idle = idle["pps"] + np.sqrt(idle["size_var"])
    bts_active = active["pps"] + np.sqrt(active["size_var"])
    return bts_idle, bts_active


###############################################################################
# main
###############################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--idle", required=True)
    parser.add_argument("--active", required=True)
    parser.add_argument("--tmpdir", default="tmp_bg")
    parser.add_argument("--device_ip", default=None)
    parser.add_argument("--category", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    os.makedirs(args.tmpdir, exist_ok=True)

    # extract idle pcap
    idle_csv = os.path.join(args.tmpdir, "idle.csv")
    extract_pcap_csv(args.idle, idle_csv)
    df_idle = pd.read_csv(idle_csv, dtype=str, on_bad_lines='skip')

    # auto device ip detection
    device_ip = args.device_ip or detect_device_ip(df_idle)
    if device_ip is None:
        raise RuntimeError("Cannot detect device ip")

    # extract active pcap
    active_csv = os.path.join(args.tmpdir, "active.csv")
    extract_pcap_csv(args.active, active_csv)
    df_active = pd.read_csv(active_csv, dtype=str, on_bad_lines='skip')

    # analysis
    idle_stats = analyze(df_idle, device_ip)
    active_stats = analyze(df_active, device_ip)
    bts_idle, bts_active = compute_bts(idle_stats, active_stats)

    row = {
        "category": args.category,
        "device": args.device,
        "pps_idle": idle_stats["pps"],
        "pps_active": active_stats["pps"],
        "pps_var_idle": idle_stats["pps_var"],
        "pps_var_active": active_stats["pps_var"],
        "size_mean_idle": idle_stats["size_mean"],
        "size_mean_active": active_stats["size_mean"],
        "size_var_idle": idle_stats["size_var"],
        "size_var_active": active_stats["size_var"],
        "proto_tls_idle": idle_stats["proto_tls"],
        "proto_tls_active": active_stats["proto_tls"],
        "proto_tcp_idle": idle_stats["proto_tcp"],
        "proto_tcp_active": active_stats["proto_tcp"],
        "proto_udp_idle": idle_stats["proto_udp"],
        "proto_udp_active": active_stats["proto_udp"],
        "proto_mdns_idle": idle_stats["proto_mdns"],
        "proto_mdns_active": active_stats["proto_mdns"],
        "proto_ssdp_idle": idle_stats["proto_ssdp"],
        "proto_ssdp_active": active_stats["proto_ssdp"],
        "proto_arp_idle": idle_stats["proto_arp"],
        "proto_arp_active": active_stats["proto_arp"],
        "proto_dhcp_idle": idle_stats["proto_dhcp"],
        "proto_dhcp_active": active_stats["proto_dhcp"],
        "proto_other_idle": idle_stats["proto_other"],
        "proto_other_active": active_stats["proto_other"],
        "inout_ratio_idle": idle_stats["inout_ratio"],
        "inout_ratio_active": active_stats["inout_ratio"],
        "num_packets_idle": idle_stats["num_packets"],
        "num_packets_active": active_stats["num_packets"],
        "bts_idle": bts_idle,
        "bts_active": bts_active
    }

    df_row = pd.DataFrame([row])
    header_needed = not os.path.exists(args.out)
    df_row.to_csv(args.out, mode="a", header=header_needed, index=False)
