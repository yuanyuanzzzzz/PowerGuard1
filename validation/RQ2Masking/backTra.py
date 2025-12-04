import subprocess
import pandas as pd
import numpy as np
import argparse
import os
from collections import Counter
from scipy.stats import entropy

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
    ips = list(df["ip.src"].dropna().values) + list(df["ip.dst"].dropna().values)
    if len(ips) == 0:
        return None

    def ok(ip):
        if ip.startswith("224.") or ip.startswith("239."):
            return False
        if ip == "255.255.255.255":
            return False
        return True

    ips = [ip for ip in ips if ok(ip)]
    if len(ips) == 0:
        return None

    lan = [ip for ip in ips if ip.startswith("192.168.") or
                                ip.startswith("10.") or
                                ip.startswith("172.")]
    if len(lan) == 0:
        return None

    return Counter(lan).most_common(1)[0][0]


###############################################################################
# protocol classifier
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
# per-second series
###############################################################################

def compute_pps_series(df):
    if df.empty:
        return pd.Series()
    t = df["frame.time_epoch"].astype(float)
    t0 = t.min()
    bins = ((t - t0)).astype(int)
    return bins.value_counts().sort_index()


###############################################################################
# enhanced main analysis
###############################################################################

def analyze(df, device_ip):
    df = df.dropna(subset=["frame.time_epoch", "frame.len", "ip.src", "ip.dst"])
    df["frame.time_epoch"] = df["frame.time_epoch"].astype(float)
    df["frame.len"] = df["frame.len"].astype(int)

    df["proto"] = df.apply(classify_protocol, axis=1)

    # packet rate
    if len(df) > 1:
        dur = df["frame.time_epoch"].max() - df["frame.time_epoch"].min()
        pps = len(df) / dur if dur > 0 else 0
    else:
        pps = 0

    # pps series and related stats
    pps_series = compute_pps_series(df)
    pps_var = pps_series.var() if len(pps_series) > 0 else 0
    burst_count = (pps_series > pps_series.mean() * 2).sum() if len(pps_series) > 0 else 0

    # size stats
    size_mean = df["frame.len"].mean()
    size_var = df["frame.len"].var()
    size_kurt = df["frame.len"].kurt()

    # protocol proportions
    total = len(df)
    proto_counts = df["proto"].value_counts()

    def prop(p):
        return float(proto_counts.get(p, 0)) / total if total > 0 else 0.0

    # inbound outbound
    inbound = (df["ip.dst"] == device_ip).sum()
    outbound = (df["ip.src"] == device_ip).sum()
    inout_ratio = inbound / (outbound + 1e6)

    # flow-level features
    df["flow"] = (
        df["ip.src"] + "_" +
        df["tcp.srcport"].fillna("") + "_" +
        df["ip.dst"] + "_" +
        df["tcp.dstport"].fillna("")
    )

    flow_counts = df["flow"].value_counts()
    num_flows = len(flow_counts)
    mean_pkts_per_flow = flow_counts.mean() if num_flows > 0 else 0
    top_flow_frac = flow_counts.max() / len(df) if len(df) > 0 else 0
    flow_entropy = entropy(flow_counts) if num_flows > 1 else 0

    # endpoint-level features
    num_dst_ips = df["ip.dst"].nunique()
    num_dst_ports = df["tcp.dstport"].nunique() + df["udp.dstport"].nunique()

    # Inter-arrival time stats
    if len(df) > 1:
        t = df["frame.time_epoch"].astype(float).sort_values()
        iat = t.diff().dropna()
        iat_mean = iat.mean()
        iat_var = iat.var()
    else:
        iat_mean = 0
        iat_var = 0


    return {
        # original features
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
        "num_packets": len(df),

        # enhanced features
        "burst_count": burst_count,
        "size_kurt": size_kurt,

        "num_flows": num_flows,
        "mean_pkts_per_flow": mean_pkts_per_flow,
        "top_flow_frac": top_flow_frac,
        "flow_entropy": flow_entropy,

        "num_dst_ips": num_dst_ips,
        "num_dst_ports": num_dst_ports,


        # Add to return dict:
        "iat_mean": iat_mean,
        "iat_var": iat_var,
    }


###############################################################################
# background traffic strength
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

    device_ip = args.device_ip or detect_device_ip(df_idle)
    if device_ip is None:
        raise RuntimeError("Cannot detect device ip")

    active_csv = os.path.join(args.tmpdir, "active.csv")
    extract_pcap_csv(args.active, active_csv)
    df_active = pd.read_csv(active_csv, dtype=str, on_bad_lines='skip')

    idle_stats = analyze(df_idle, device_ip)
    active_stats = analyze(df_active, device_ip)

    bts_idle, bts_active = compute_bts(idle_stats, active_stats)

    row = {
        "category": args.category,
        "device": args.device,
        **{f"{k}_idle": v for k, v in idle_stats.items()},
        **{f"{k}_active": v for k, v in active_stats.items()},
        "bts_idle": bts_idle,
        "bts_active": bts_active
    }

    df_row = pd.DataFrame([row])
    header_needed = not os.path.exists(args.out)
    df_row.to_csv(args.out, mode="a", header=header_needed, index=False)
