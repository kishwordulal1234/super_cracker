#!/usr/bin/env python3

# ███████╗██████╗ ███████╗███╗   ██╗███████╗██╗    ██╗███████╗██████╗
# ██╔════╝██╔══██╗██╔════╝████╗  ██║██╔════╝██║    ██║██╔════╝██╔══██╗
# █████╗  ██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║ █╗ ██║█████╗  ██████╔╝
# ██╔══╝  ██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══╝  ██║███╗██║██╔══╝  ██╔══██╗
# ███████╗██║     ███████╗██║ ╚████║███████╗╚███╔███╔╝███████╗██║  ██║
# ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝
#                       🔓 PyBlast: The Ultimate Hash Cracker
#                       Author: github.com/kishwordulal1234

import argparse
import hashlib
import os
import subprocess
import threading
import json
import time
import re
import platform
from queue import Queue
from tqdm import tqdm
from rich.console import Console
from rich.panel import Panel
from rich import box
import psutil
import GPUtil

console = Console()
found = {}
lock = threading.Lock()
resume_file = ".resume.json"

# ===================== SYSTEM INFO =====================
def print_system_info():
    cpu = platform.processor()
    cores = psutil.cpu_count(logical=False)
    threads = psutil.cpu_count(logical=True)
    ram = round(psutil.virtual_memory().total / (1024**3), 2)
    os_info = platform.platform()
    freq = psutil.cpu_freq().max if psutil.cpu_freq() else 0
    gpus = GPUtil.getGPUs()
    gpu_info = "\n".join([f"GPU {g.id}: {g.name} ({g.memoryTotal}MB)" for g in gpus]) or "No GPU detected"

    info = f"""
[bold cyan]System Information[/bold cyan]
• OS: {os_info}
• CPU: {cpu} ({cores} cores, {threads} threads @ {freq:.1f}MHz)
• RAM: {ram} GB
• GPU(s):
{gpu_info}
    """
    console.print(Panel(info, box=box.ROUNDED))

# ===================== HASH TYPE DETECTOR =====================
def detect_hash_type(h):
    if re.match(r"^\$2[aby]\$", h): return "bcrypt"
    if re.match(r"^\$6\$", h): return "sha512crypt"
    if re.match(r"^\$5\$", h): return "sha256crypt"
    if len(h) == 32: return "md5"
    if len(h) == 40: return "sha1"
    if len(h) == 64: return "sha256"
    if len(h) == 128: return "sha512"
    if re.match(r"^[0-9A-Fa-f]{32}$", h): return "ntlm"
    return None

# ===================== PYTHON HASHING =====================
def hash_password(plain, hash_type, salt=None):
    if salt:
        plain = salt + plain

    if hash_type == "md5":
        return hashlib.md5(plain.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(plain.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(plain.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(plain.encode()).hexdigest()
    elif hash_type == "ntlm":
        return hashlib.new('md4', plain.encode('utf-16le')).hexdigest()
    else:
        return None

# ===================== THREAD WORKER =====================
def worker(queue, targets, hash_type, salt, pbar, resume_idx, resume_step, cracked_file, stop_event):
    global found
    while not queue.empty() and not stop_event.is_set():
        try:
            idx, password = queue.get_nowait()
        except:
            break

        for hash_value in targets:
            if hash_value in found:
                continue
            calculated = hash_password(password, hash_type, salt)
            if calculated == hash_value:
                with lock:
                    found[hash_value] = password
                    console.print(f"[bold green]✓ MATCH: '{password}' → {hash_value}[/bold green]")
                    with open(cracked_file, 'a') as cf:
                        cf.write(f"{hash_value}:{password}\n")
                    if len(found) == len(targets):
                        stop_event.set()
                        console.print("[bold green]\n✅ Cracking complete!\n🔥 Exiting...[/bold green]")
                        os._exit(0)

        if idx % resume_step == 0:
            with open(resume_file, 'w') as rf:
                json.dump({"index": idx}, rf)

        pbar.update(1)

# ===================== GPU HASHCAT =====================
def crack_with_hashcat(wordlist, hashes, hash_type_id):
    outfile = "cracked.txt"
    open(outfile, 'w').close()
    cmd = [
        "hashcat", "-a", "0", f"-m{hash_type_id}",
        hashes, wordlist,
        "--outfile", outfile, "--force", "--quiet"
    ]
    console.print(f"[cyan]⚡ Running Hashcat: {' '.join(cmd)}[/cyan]")
    subprocess.run(cmd)
    with open(outfile) as f:
        for line in f:
            h, p = line.strip().split(":", 1)
            console.print(f"[green]✓ GPU MATCH: {p} → {h}[/green]")

# ===================== SYSTEM STATS =====================
def show_stats():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    gpus = GPUtil.getGPUs()
    gpu_stats = [f"GPU {g.id}: {g.load*100:.1f}% {g.memoryUsed}/{g.memoryTotal}MB" for g in gpus]
    console.print(f"[yellow]⚙️ CPU: {cpu}% | RAM: {ram}% | {' | '.join(gpu_stats)}[/yellow]")

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wordlist', required=True)
    parser.add_argument('--hashes', required=True)
    parser.add_argument('--type', help='Hash type (or autodetect)')
    parser.add_argument('--threads', type=int, default=10)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--gpu', action='store_true')
    parser.add_argument('--salt', help='Optional salt')
    args = parser.parse_args()

    print_system_info()

    with open(args.hashes) as f:
        hash_list = [x.strip() for x in f if x.strip()]

    if not args.type:
        args.type = detect_hash_type(hash_list[0])
        console.print(f"[blue]Auto-detected hash type: {args.type}[/blue]")

    if args.gpu:
        hashcat_id = {
            "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
            "ntlm": 1000, "bcrypt": 3200
        }.get(args.type, 0)
        crack_with_hashcat(args.wordlist, args.hashes, hashcat_id)
        return

    with open(args.wordlist, encoding='utf-8', errors='ignore') as f:
        passwords = [x.strip() for x in f if x.strip()]

    start = 0
    if args.resume and os.path.exists(resume_file):
        with open(resume_file) as rf:
            start = json.load(rf).get("index", 0)
        console.print(f"[yellow]⏩ Resuming from index {start}[/yellow]")

    queue = Queue()
    for idx, pwd in enumerate(passwords):
        if idx >= start:
            queue.put((idx, pwd))

    cracked_file = "cracked.txt"
    open(cracked_file, 'a').close()
    pbar = tqdm(total=len(passwords) - start, desc="🔥 Cracking Progress")

    stop_event = threading.Event()
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(queue, hash_list, args.type, args.salt, pbar, start, 500, cracked_file, stop_event))
        t.start()
        threads.append(t)

    while any(t.is_alive() for t in threads):
        show_stats()
        time.sleep(3)

    for t in threads:
        t.join()

    pbar.close()
    console.print("[bold green]\n✅ Cracking complete![/bold green]")

if __name__ == '__main__':
    main()
