import asyncio
from datetime import datetime
import argparse
import logging
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "utils")))

from tapo import ApiClient
from moniotr import start_moniotr, stop_moniotr, get_ip_from_mac
from powerlogger import start_powerlogger, stop_powerlogger, set_under_attack, load_device_macs, setup_logger
from attacks import start_attack, stop_attack

logger = None


# ====================================================================
# IDLE MODE
# ====================================================================
async def run_idle(args, device):
    logger.info("starting idle monitoring")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"{args.device_folder}_idle"

    start_moniotr(args.mac_address, tag)
    key = start_powerlogger(device, "idle", args.device_folder, args.pcap_dir, args.interval, key="idle")

    await asyncio.sleep(args.duration)

    await stop_powerlogger(key, args.pcap_dir)
    stop_moniotr(args.mac_address, tag, timestamp, "idle", args.device_folder, args.pcap_dir)


# ====================================================================
# ACTIVE MODE
# ====================================================================
async def run_active(args, device):
    logger.info("starting active monitoring")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"{args.device_folder}_active"

    start_moniotr(args.mac_address, tag)

    key = start_powerlogger(device, "active", args.device_folder, args.pcap_dir, args.interval, key="active")

    await asyncio.sleep(args.duration)

    await stop_powerlogger(key, args.pcap_dir)
    stop_moniotr(args.mac_address, tag, timestamp, "active", args.device_folder, args.pcap_dir)


# ====================================================================
# ATTACK CYCLES
# ====================================================================
async def run_attack_cycles(args, attack_name, device, mode_label):
    # one cycle = settle_time attack + settle_time x 3 recovery
    # default settle_time 60s
    cycles_raw = args.duration // (args.settle_time * 4)

    # at least one cycle attack
    cycles = max(1, cycles_raw)

    logger.info(f"starting {mode_label} with {cycles} cycles using attack {attack_name}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"{args.device_folder}_{mode_label}_{attack_name}"

    args.attack = attack_name

    state = f"{mode_label}_{attack_name}"

    start_moniotr(args.mac_address, tag)
    key = start_powerlogger(device, state, args.device_folder, args.pcap_dir, args.interval, key=mode_label)

    for i in range(cycles):
        logger.info(f"cycle {i + 1} of {cycles} attack stage")

        process_name = await start_attack(args)
        if not process_name:
            logger.error("cannot get attack process name, skip this cycle")
            continue

        set_under_attack(mode_label, 1)
        await asyncio.sleep(args.settle_time)

        await stop_attack(args, process_name)
        set_under_attack(mode_label, 0)

        logger.info("recovery stage")
        await asyncio.sleep(args.settle_time * 3)

    await stop_powerlogger(key, args.pcap_dir)
    stop_moniotr(args.mac_address, tag, timestamp, state, args.device_folder, args.pcap_dir)

    logger.info("finished all attack cycles")


# ====================================================================
# MAIN
# ====================================================================
async def run_experiment(args):
    global logger

    # load MAC table
    try:
        macs = load_device_macs(args.device_label)
        args.mac_address = macs["mac"]
        args.plug_mac = macs["plug_mac"]
        args.pi_mac = macs["pi_mac"]
        logger.info(f"loaded macs {macs}")
    except Exception as e:
        logger.error(f"cannot load device macs {e}")
        return

    # resolve ips
    args.plug_ip = get_ip_from_mac(args.plug_mac)
    args.pi_ip = get_ip_from_mac(args.pi_mac)
    args.device_ip = get_ip_from_mac(args.mac_address)

    print(f"DEBUG: Plug MAC [{args.plug_mac}] resolved to IP: [{args.plug_ip}]")

    if not all([args.device_ip, args.plug_ip, args.pi_ip]):
        logger.error("cannot resolve ip addresses")
        return

    client = ApiClient(args.tapo_email, args.tapo_password)
    device = await client.p110(args.plug_ip)

    logger.info(f"experiment config {vars(args)}")

    # idle
    if "idle" in args.modes:
        await run_idle(args, device)

    # active
    if "active" in args.modes:
        await run_active(args, device)

    # attacks
    for attack in args.attacks:

        if "idle_attack" in args.modes:
            await run_attack_cycles(args, attack, device, "idle_attack")

        if "active_attack" in args.modes:
            await run_attack_cycles(args, attack, device, "active_attack")

    logger.info("experiment round complete")


# ====================================================================
# CLI
# ====================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="powerguard logger")
    parser.add_argument("--modes", nargs="+", default=["idle"])
    parser.add_argument("--device_label", required=True)
    parser.add_argument("--attacks", nargs="+", default=["syn_flood"], choices=["syn_flood", "icmp_flood", "port_scan", "os_fingerprint"])
    parser.add_argument("--tapo_email", default="iotlabucl@gmail.com")
    parser.add_argument("--tapo_password", default="IoTlabUCL")
    parser.add_argument("--pi_user", default="pi")
    parser.add_argument("--device_folder", default="antela")
    parser.add_argument("--pcap_dir", default="/data/disk1/powerguard/new")
    parser.add_argument("--interval", type=int, default=1)
    parser.add_argument("--settle_time", type=int, default=60)
    parser.add_argument("--duration", type=int, default=2400)
    parser.add_argument("--log_path", default="general.log")
    args = parser.parse_args()

    logger = setup_logger(args.log_path)
    asyncio.run(run_experiment(args))
