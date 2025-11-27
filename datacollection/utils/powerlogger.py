import asyncio
import csv
import os
import json
import logging
from datetime import datetime
from logging import getLogger

logger = getLogger("PowerGuardLogger")

_log_tasks = {}  # Track active tasks by (device_folder, state)
_log_buffers = {}
_under_attack_flags = {}  # global dictionary

# ---------------- function ----------------

def setup_logger(log_path):
    logger = logging.getLogger("PowerGuardLogger")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        fh = logging.FileHandler(log_path)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

def load_device_macs(label, json_path="devices.json"):
    with open(json_path, "r") as f:
        devices = json.load(f)
    if label not in devices:
        raise ValueError(f"Device label '{label}' not found in devices.json")
    return devices[label]

def set_under_attack(key, value):
    """under attack"""
    _under_attack_flags[key] = int(bool(value))

# ---------------- core ----------------

def start_powerlogger(device, state, device_folder, pcap_dir, interval=1, key=None):
    logger.info(f"[START] Power logging: {device_folder}/{state}")
    _log_key = (device_folder, state)

    buffer = []
    _log_buffers[_log_key] = buffer

    async def _logger_loop():
        while True:
            try:
                energy = await device.get_energy_usage()
                
                now = datetime.now().isoformat()
                attack_status = int(_under_attack_flags.get(key, 0))
                
                # read current_power
                power = energy.current_power
                
                buffer.append((now, power, attack_status))
                logger.info(f"{now} | {power} mW | under_attack={attack_status}")
            except Exception as e:
                logger.warning(f"⚠️ Power logging error: {e}")
                
                await asyncio.sleep(1)
            
            await asyncio.sleep(interval)

    task = asyncio.create_task(_logger_loop())
    _log_tasks[_log_key] = task
    return _log_key 

async def stop_powerlogger(key, pcap_dir):
    device_folder, state = key
    logger.info(f"[STOP] Power logging: {device_folder}/{state}")
    
    task = _log_tasks.pop(key, None)
    buffer = _log_buffers.pop(key, [])

    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    path = os.path.join(pcap_dir, device_folder)
    os.makedirs(path, exist_ok=True)
    file_path = os.path.join(path, f"{state}.csv")

    try:
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "power_mW", "under_attack"])
            writer.writerows(buffer)
        logger.info(f"✅ Power log saved: {file_path}")
    except Exception as e:
        logger.error(f"❌ Failed to save CSV: {e}")