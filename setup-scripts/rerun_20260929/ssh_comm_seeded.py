#!/usr/bin/env python3
from pwn import ssh
import sys
import os
import time
import threading
import subprocess
import tempfile
import shutil
import json
import signal
import re
import fnmatch
import glob
import shlex

# Base path for chaos_eval - auto-detected from script location
# This makes the code portable: works on local dev (/evaldisk/chaos_eval) 
# and AWS (/opt/chaos_eval) without any configuration
CHAOS_BASE = os.environ.get("CHAOS_BASE", os.path.dirname(os.path.abspath(__file__)))

# Fuzzer configuration mapping.
# All ports, hosts, and SSH keys are detected dynamically.
# FUZZER_MAP = {
#     "countdown": {
#         "ssh_key": "countdown/image/stretch.id_rsa",
#         "workdir": "countdown/countdown_fuzzer",
#         "config_file": "cd_cfg",
#         "run_cmd": "./bin/syz-manager -config ./cd_cfg",
#         "vm_boot_time": 100
#     },
#     "syzkaller": {
#         "ssh_key": "syzkaller/image/bullseye.id_rsa",
#         "workdir": "syzkaller/workdir",
#         "config_file": "test.cfg",
#         "run_cmd": "./bin/syz-manager -debug -config ./test.cfg",
#         "vm_boot_time": 100
#     },
#     "actor": {
#         "ssh_key": "actor/image/bullseye.id_rsa",
#         "workdir": "actor/setup/actor",
#         "config_file": "actor.config",
#         "run_cmd": "../../src/github.com/google/syzkaller/bin/syz-manager -config actor.config",
#         "vm_boot_time": 100
#     },
#     "healer": {
#         "ssh_key": "healer/healer-image/bullseye.id_rsa",
#         "workdir": "healer/workdir",
#         "config_file": None,  # healer uses command line args
#         "run_cmd": "sudo bin/healer --debug -d bullseye.img --ssh-key bullseye.id_rsa -k ../linux/arch/x86/boot/bzImage -j 1",
#         "vm_boot_time": 50
#     },
#     "fuzzng": {
#         "ssh_key": "FuzzNG/images/bullseye.id_rsa",
#         "workdir": "FuzzNG",
#         "config_file": None,  # fuzzng uses different config
#         "run_cmd": "./scripts/fuzz.sh 1 configs/kvm.h",
#         "vm_boot_time": 100
#     },
# }

DEFAULT_USER = "root"
DEFAULT_HOST = "127.0.0.1"
REMOTE_PROBE_PATH = "/usr/local/bin/chaos_probe"

# VirtFuzz Device Configuration
# Based on VirtFuzz paper (IEEE S&P 2024): "To Boldly Go Where No Fuzzer Has Gone Before"
# Only high-priority devices with proven CVE discovery are included:
#   - wifi-scan: 73 unique functions, 6 CVEs, heap overflow in beacon parsing
#   - bluetooth: Multiple UaF/OOB bugs from 2008, connection complete event vulns  
#   - bluetooth-scan: Bluetooth with scanning for additional code paths
# Excluded (paper: "did not lead to new bug discoveries"): net, input, console
VIRTFUZZ_DEVICES = {
    "wifi-scan": {
        "definition": "hwsim-scan.json",
        "flags": ["--use-hwsim-input"],
        "priority": 1,
        "description": "WiFi scanning mode - 6 CVEs found, 22x faster than Syzkaller",
        "port_offset": 0,
    },
    "wifi-ibss": {
        "definition": "hwsim-ibss.json",
        "flags": ["--use-hwsim-input"],
        "priority": 4,
        "description": "WiFi IBSS: single radio joined to an ad-hoc network at boot",
        "port_offset": 0,
    },
    "wifi-ap": {
        "definition": "hwsim-ap.json",
        "flags": ["--use-hwsim-input"],
        "priority": 5,
        "description": "WiFi AP: hostapd access point on wlan0 at boot",
        "port_offset": 0,
    },
    "wifi-syzkaller": {
        "definition": "hwsim-syzkaller.json",
        "flags": ["--use-hwsim-input"],
        "priority": 6,
        "description": "WiFi syzkaller setup: 2 IBSS radios with fixed MACs plus scan trigger",
        "port_offset": 0,
    },
    "mode-capture": {
        "definition": "mode-capture.json",
        "flags": ["--use-hwsim-input"],
        "priority": 9,
        "description": "Diagnostic capture: radios=2, hostapd wlan0 AP + wlan1 scan/IBSS; frames dumped to shared",
        "port_offset": 0,
    },
    "bluetooth": {
        "definition": "bluetooth.json",
        "flags": ["--bt-fake-cc"],
        "priority": 2,
        "description": "Bluetooth HCI - bugs from 2008 found, connection complete vulns",
        "port_offset": 10,
    },
    "bluetooth-scan": {
        "definition": "bluetooth.json",
        # init-path kicks off the handshake --wait-for-rx is waiting on; see README Quirks.
        "flags": ["--bt-fake-cc", "--wait-for-rx", "--init-path", "resources/setup.pcap"],
        "priority": 3,
        "description": "Bluetooth with scanning - additional code paths",
        "port_offset": 20,
    },
}

# Base broker ports for VirtFuzz per mode (sequential allocation: base + device_offset + trial_offset)
# GAP of 1000 between modes to prevent collision with trial offsets (max 5 trials * 100 = 500)
# Example: c1_trial5 = 10000 + 0 + 500 = 10500, c2_trial0 = 11000 (no collision)
# Spacing must exceed the largest trial offset (trial * 100). At 1000 apart a
# 10-trial gap between modes cancelled it exactly -- c2 trial32 and c3 trial22
# both landed on 14200 and crash-looped. Kept under 32768 so these never clash
# with the ephemeral range QEMU draws from.
VIRTFUZZ_BASE_PORTS = {
    "c1": 10000,
    "c2": 16000,
    "c3": 20000,
}

# Each rerun must begin with an empty, private corpus.  The published unseeded
# condition does not import prior inputs, and the production corpus_shared is
# mixed across older modes and devices.  Keep this change in the isolated copy.
VIRTFUZZ_SHARED_CORPUS = os.environ.get("VIRTFUZZ_CORPUS_DIR")


# Physical cores 48-63 (CPUs 48-63 plus SMT siblings 112-127). Nothing else
# runs there: launch_trial.sh pins the syscall fuzzers to 64-111, whose siblings
# are 0-47. Slot is trial parity, so two concurrent trials never overlap.
# Each entry is 2 exclusive physical cores, both SMT threads (cpuN pairs with
# cpuN+64), so no two instances share a core. Spare: 60-63 and 124-127.
VIRTFUZZ_CORE_MAP = {
    ("c1", 0): "48,49,112,113", ("c1", 1): "50,51,114,115",
    ("c2", 0): "52,53,116,117", ("c2", 1): "54,55,118,119",
    ("c3", 0): "56,57,120,121", ("c3", 1): "58,59,122,123",
}


def _cpu_spec_count(spec):
    """Number of CPUs in a taskset-style list like '48,49,112,113' or '48-51'."""
    total = 0
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            total += int(hi) - int(lo) + 1
        else:
            total += 1
    return total


def virtfuzz_cores(mode, trial):
    """Return this VirtFuzz instance's dedicated core range."""
    # Explicit override for extra concurrent trials beyond the 2 static slots/mode
    # (the map is keyed on trial%2). Set on the unit's Environment so it survives restart.
    override = os.environ.get("VIRTFUZZ_CORES", "").strip()
    if override:
        return override
    slot = (int(trial) % 2) if trial else 0
    cores = VIRTFUZZ_CORE_MAP.get((mode, slot))
    if cores is None:
        print(f"[WARN] No static core map for VirtFuzz {mode} slot {slot}")
        return find_available_cores(num_cores=4)
    return cores


def find_available_cores(num_cores=4):
    """Find available CPU cores by checking CPU usage.
    
    Returns a string like '0-3' or '4,5,6,7' for cores with low utilization.
    Avoids cores already heavily used by other processes.
    """
    import psutil
    
    try:
        # Get per-core CPU usage over 1 second interval
        core_usage = psutil.cpu_percent(interval=1, percpu=True)
        total_cores = len(core_usage)
        
        # Find cores with < 50% usage
        available = [i for i, usage in enumerate(core_usage) if usage < 50.0]
        
        if len(available) >= num_cores:
            # Take first num_cores available cores
            selected = available[:num_cores]
            # Format as range if consecutive, otherwise comma-separated
            if len(selected) > 1 and selected == list(range(selected[0], selected[-1] + 1)):
                return f"{selected[0]}-{selected[-1]}"
            else:
                return ",".join(map(str, selected))
        elif available:
            # Not enough ideal cores, use what's available
            return ",".join(map(str, available[:num_cores]))
        else:
            # All cores busy, fall back to sequential allocation
            # Use high cores to avoid conflicts with system processes on low cores
            start = max(0, total_cores - num_cores)
            return f"{start}-{min(start + num_cores - 1, total_cores - 1)}"
    except Exception as e:
        print(f"[WARN] Failed to detect available cores: {e}")
        # Fallback to simple allocation
        return "0-3"


def get_fuzzer_config(fuzzer_name, mode, device=None, trial=None):
    """Generate mode-specific config for fuzzer.
    
    Args:
        fuzzer_name: Name of the fuzzer (syzkaller, countdown, actor, healer, virtfuzz)
        mode: Fuzzing mode (c1, c2, c3)
        device: VirtFuzz device (wifi-scan, bluetooth, bluetooth-scan)
        trial: Trial number for AWS multi-trial isolation. When specified:
               - Appends _trial{N} to workdir paths for unique working directories
               - Offsets HTTP ports by trial*100 to prevent port collisions
               - Creates separate image copies to prevent disk I/O contention
    
    Returns:
        Configuration dictionary with paths, ports, and commands
    """
    
    # Calculate trial suffix and port offset
    trial_suffix = f"_trial{trial}" if trial else ""
    port_offset = (trial * 100) if trial else 0
    
    if trial:
        print(f"[+] Trial mode enabled: trial={trial}")
        print(f"[+] Workdir suffix: {trial_suffix}")
        print(f"[+] Port offset: +{port_offset}")
    
    configs = {
        "countdown": {
            "ssh_key": f"{CHAOS_BASE}/countdown/image/stretch.id_rsa",
            "workdir": f"{CHAOS_BASE}/countdown/countdown_fuzzer/workdir_{mode}{trial_suffix}",
            "image": f"{CHAOS_BASE}/countdown/image/stretch_{mode}{trial_suffix}.img",
            "config_file": f"{CHAOS_BASE}/countdown/countdown_fuzzer/workdir_{mode}{trial_suffix}/cd_cfg",
            "run_cmd": f"../bin/syz-manager -config ./cd_cfg",
            "vm_boot_time": 100,
            "http_port": (56751 if mode == "c1" else (56752 if mode == "c2" else 56753)) + port_offset,
            "coverage_type": "http",
            "kernel_obj": f"{CHAOS_BASE}/countdown/linux/",
            "trial": trial,
        },
        
        "syzkaller": {
            "ssh_key": f"{CHAOS_BASE}/syzkaller/image/bullseye.id_rsa",
            "workdir": f"{CHAOS_BASE}/syzkaller/syzkaller/workdir_{mode}{trial_suffix}",
            "image": f"{CHAOS_BASE}/syzkaller/image/bullseye_{mode}{trial_suffix}.img",
            "config_file": f"{CHAOS_BASE}/syzkaller/syzkaller/workdir_{mode}{trial_suffix}/test.cfg",
            "run_cmd": f"../bin/syz-manager -config ./test.cfg",
            "vm_boot_time": 100,
            "http_port": (56748 if mode == "c1" else (56749 if mode == "c2" else 56750)) + port_offset,
            "coverage_type": "http",
            "kernel_obj": f"{CHAOS_BASE}/syzkaller/linux/",
            "trial": trial,
        },
        
        "actor": {
            "ssh_key": f"{CHAOS_BASE}/actor/image/bullseye.id_rsa",
            "workdir": f"{CHAOS_BASE}/actor/setup/actor_{mode}{trial_suffix}",
            "out_workdir" : f"{CHAOS_BASE}/actor/out/workdir_{mode}{trial_suffix}",
            "image": f"{CHAOS_BASE}/actor/image/bullseye_{mode}{trial_suffix}.img",
            "config_file": f"{CHAOS_BASE}/actor/setup/actor_{mode}{trial_suffix}/actor.config",
            "run_cmd": "../../src/github.com/google/syzkaller/bin/syz-manager -config actor.config",
            "vm_boot_time": 100,
            "http_port": (56740 if mode == "c1" else (56741 if mode == "c2" else 56742)) + port_offset,
            "coverage_type": "http",
            "kernel_obj": f"{CHAOS_BASE}/actor/linux/",
            "needs_uio": True,
            "trial": trial,
        },
        
        "healer": {
            "ssh_key": f"{CHAOS_BASE}/healer/healer-image/bullseye.id_rsa",
            "workdir": f"{CHAOS_BASE}/healer/workdir_{mode}{trial_suffix}",
            "image": f"{CHAOS_BASE}/healer/healer-image/bullseye_{mode}{trial_suffix}.img",
            "config_file": None,
            # Healer outputs coverage to output/raw_coverage/
            "run_cmd": f"bin/healer -d ../healer-image/bullseye_{mode}{trial_suffix}.img --ssh-key ../healer-image/bullseye.id_rsa -k ../linux/arch/x86/boot/bzImage -j 1 -c 2 --disable-repro",
            "vm_boot_time": 50,
            "coverage_type": "file",
            "coverage_file": f"{CHAOS_BASE}/healer/workdir_{mode}{trial_suffix}/output/raw_coverage/coverage.txt",
            "kernel_obj": f"{CHAOS_BASE}/healer/linux/",
            "trial": trial,
        },
        
        "virtfuzz": {
            "ssh_key": f"{CHAOS_BASE}/VirtFuzz/guestimage/stretch.id_rsa",
            # Workdir is now device-specific: workdir_{mode}_{device}
            # e.g., workdir_c1_wifi_scan, workdir_c1_bluetooth
            "workdir": f"{CHAOS_BASE}/VirtFuzz/workdir_{mode}{trial_suffix}",  # Base, updated below per device
            # Image is device-specific: stretch_{mode}_{device}.img - updated below per device
            "image": None,  # Will be set per device to prevent concurrent access corruption
            "config_file": None,
            "run_cmd": None,
            "vm_boot_time": 100,
            # Port is now dynamically calculated: base_port + device_offset
            "broker_port": VIRTFUZZ_BASE_PORTS.get(mode, 1337),  # Base, updated below per device
            "coverage_type": "virtfuzz",
            # VirtFuzz writes bzImage.coverage to its base directory (where it runs from)
            # since we changed it to run with 'cd {virtfuzz_base} &&'
            "coverage_file": f"{CHAOS_BASE}/VirtFuzz/bzImage.coverage",
            "kernel_obj": f"{CHAOS_BASE}/VirtFuzz/linux/",
            "device": device,
            # Shared corpus for cross-device code path discovery
            "shared_corpus": VIRTFUZZ_SHARED_CORPUS,
        }
    }
    
    config = configs.get(fuzzer_name)
    if not config:
        return None
    
    # Create workdir if not exists (skip for VirtFuzz - it has device-specific workdir set later)
    if fuzzer_name != "virtfuzz":
        os.makedirs(config["workdir"], exist_ok=True)
    
    if fuzzer_name == "virtfuzz":
        if not device:
            raise ValueError("VirtFuzz requires --device argument. Available devices:\n" +
                "\n".join(f"  {d}: {cfg['description']}" for d, cfg in 
                           sorted(VIRTFUZZ_DEVICES.items(), key=lambda x: x[1]['priority'])))
        
        if device not in VIRTFUZZ_DEVICES:
            raise ValueError(f"Unknown VirtFuzz device: {device}. Available devices:\n" +
                "\n".join(f"  {d}: {cfg['description']}" for d, cfg in 
                           sorted(VIRTFUZZ_DEVICES.items(), key=lambda x: x[1]['priority'])))
        
        device_config = VIRTFUZZ_DEVICES[device]
        device_file = device_config["definition"]
        device_flags = device_config["flags"]
        device_port_offset = device_config["port_offset"]
        
        # Device-specific workdir: workdir_{mode}_{device_sanitized}[_trial{N}]
        device_sanitized = device.replace("-", "_")
        workdir = f"{CHAOS_BASE}/VirtFuzz/workdir_{mode}_{device_sanitized}{trial_suffix}"
        config["workdir"] = workdir
        
        # Sequential port allocation: base_port + device_offset + trial_offset
        # Trial offset is already in port_offset from outer scope
        base_port = VIRTFUZZ_BASE_PORTS.get(mode, 1337)
        config["broker_port"] = base_port + device_port_offset + port_offset
        config["trial"] = trial
        
        # Per-trial coverage file, passed explicitly via --coverage-output so concurrent
        # instances don't collide on the same <kernel-basename>.coverage file in
        # virtfuzz_base (they used to, silently merging every trial's coverage together --
        # fixed in the virtfuzz-fuzz binary itself, PwnVerse/VirtFuzz commit b97ec0d).
        virtfuzz_base = f"{CHAOS_BASE}/VirtFuzz"
        config["coverage_file"] = f"{workdir}/bzImage.coverage"
        
        print(f"[+] VirtFuzz device: {device} (priority {device_config['priority']})")
        print(f"[+] Description: {device_config['description']}")
        print(f"[+] Broker port: {config['broker_port']} (base {base_port} + device_offset {device_port_offset} + trial_offset {port_offset})")
        
        # Build VirtFuzz command with absolute paths
        virtfuzz_base = f"{CHAOS_BASE}/VirtFuzz"
        qemu_bin = f"{virtfuzz_base}/qemu/build/qemu-system-x86_64"
        
        # For VirtFuzz, we want per-trial images to avoid I/O contention
        # First, find a base image that exists, then set trial-specific target path
        # The copy logic later in main() will create the trial copy if needed
        base_image_candidates = [
            f"{virtfuzz_base}/guestimage/stretch_{mode}_{device_sanitized}.img",
            f"{virtfuzz_base}/guestimage/stretch_{mode}.img",
        ]
        base_image = None
        for candidate in base_image_candidates:
            if os.path.exists(candidate):
                base_image = candidate
                print(f"[+] Found VirtFuzz base image: {base_image}")
                break
        if not base_image:
            print(f"[-] No VirtFuzz base image found. Tried: {base_image_candidates}")
            return None
        
        # Set the desired trial-specific image path (will be copied if doesn't exist)
        if trial_suffix:
            # Use trial-specific image for isolation
            image_file = f"{virtfuzz_base}/guestimage/stretch_{mode}_{device_sanitized}{trial_suffix}.img"
            # Check if trial image already exists, otherwise copy will happen later
            if os.path.exists(image_file):
                print(f"[+] Using existing trial image: {image_file}")
            else:
                print(f"[+] Trial image will be created: {image_file} (from {base_image})")
        else:
            image_file = base_image
            print(f"[+] Using VirtFuzz image: {image_file}")
        config["image"] = image_file
        # Store base image for the copy logic
        config["base_image"] = base_image
        kernel_file = f"{virtfuzz_base}/linux/arch/x86/boot/bzImage"
        device_def = f"{virtfuzz_base}/device-definitions/{device_file}"
        virtfuzz_bin = f"{virtfuzz_base}/target/release/virtfuzz-fuzz"
                
        # VirtFuzz now uses shared_dir for ramoops path (patched version)
        # The actual shared directory is already created by prepare_workdir()
        shared_dir = f"{workdir}/shared"
        
        # Get broker port for this mode
        broker_port = config["broker_port"]
        
        # Static disjoint cores. Dynamic detection raced: every mode took the
        # first idle CPUs, landing on the syscall fuzzers' SMT siblings.
        allocated_cores = virtfuzz_cores(mode, trial)
        print(f"[+] VirtFuzz {mode} trial={trial} pinned to cores: {allocated_cores}")
        
        # Create shared corpus directory for cross-device corpus sharing
        shared_corpus_dir = config.get("shared_corpus")
        if not shared_corpus_dir:
            raise ValueError("Set VIRTFUZZ_CORPUS_DIR to a fresh per-trial directory")
        if (os.path.exists(shared_corpus_dir) and os.listdir(shared_corpus_dir)
                and not os.path.exists(workdir)):
            raise ValueError(f"Refusing nonempty rerun corpus: {shared_corpus_dir}")
        os.makedirs(shared_corpus_dir, exist_ok=True)
        
        # Build command with device-specific flags
        # Run from VirtFuzz directory so QEMU can find its BIOS files using relative paths
        # This is critical - QEMU's -L option needs the pc-bios path relative to where it runs
        # Convert absolute paths to relative paths from virtfuzz_base
        rel_qemu = "./qemu/build/qemu-system-x86_64"
        rel_kernel = "./linux/arch/x86/boot/bzImage"
        rel_image = os.path.relpath(image_file, virtfuzz_base)
        rel_device_def = f"./device-definitions/{device_file}"
        rel_shared_dir = os.path.relpath(shared_dir, virtfuzz_base)
        # Default is a single global crashes/ shared by every mode, device and trial,
        # so artifacts can't be attributed. Other fuzzers already scope theirs per-trial.
        rel_crashes = os.path.relpath(os.path.join(workdir, "crashes"), virtfuzz_base)
        rel_corpus = os.path.relpath(shared_corpus_dir, virtfuzz_base)
        
        cmd_parts = [
            f"cd {virtfuzz_base} &&",
            # LibAFL reads --cores as indices into this process's affinity list,
            # not as absolute CPU ids, so set the real mask here first.
            f"taskset -c {allocated_cores}",
            "./target/release/virtfuzz-fuzz",
            f"--qemu {rel_qemu}",
            f"--image {rel_image}",
            f"--kernel {rel_kernel}",
            f"--device-definition {rel_device_def}",
            f"--port {broker_port}",
            f"--cores 0-{_cpu_spec_count(allocated_cores) - 1}",
            "--stages standard",
            "--enable-ramoops",
            "--enable-qemu-logging",
            "--record-coverage",
            f"--coverage-output {config['coverage_file']}",
            f"--shared-dir {rel_shared_dir}",
            f"--crashes {rel_crashes}",
            # Use shared corpus for cross-device code path discovery
            f"--corpus {rel_corpus}",
            # CRITICAL: Tell QEMU where to find BIOS files (fixes "could not load PC BIOS" error)
            # Using single quotes to preserve the argument as one string for clap parsing
            "'--qemu-args=-L ./qemu/pc-bios'",
        ]
        
        # Add device-specific flags from VIRTFUZZ_DEVICES config
        for flag in device_flags:
            cmd_parts.append(flag)
        # Diagnostic-only SSH access is opt-in and is never set for final runs.
        debug_ssh_port = os.environ.get("VIRTFUZZ_DEBUG_SSH_PORT")
        if debug_ssh_port:
            cmd_parts.extend(["--enable-debug-ssh", f"--ssh-port {int(debug_ssh_port)}"])
        
        print(f"[+] Device-specific flags: {device_flags}")
        print(f"[+] Shared corpus: {shared_corpus_dir}")
        
        config["run_cmd"] = " ".join(cmd_parts)

        # Seeded runs: import the extracted 802.11 seed corpus at launch.
        seed_inputs = os.environ.get("VIRTFUZZ_INITIAL_INPUTS")
        if seed_inputs and os.path.isdir(seed_inputs):
            config["run_cmd"] += f" --initial-inputs {shlex.quote(seed_inputs)}"
            print(f"[+] Initial inputs: {seed_inputs}")

    return config

def start_pc_timestamping(fuzzer_name, mode, config):
    """Start lightweight PC timestamper (Phase 1: no symbolization during fuzzing)"""
    
    coverage_type = config["coverage_type"]
    
    if coverage_type == "http":
        cmd = [
            "python3", f"{CHAOS_BASE}/pc_timestamper.py",
            "--port", str(config["http_port"]),
            "--outdir", config["workdir"],
            "--pc-first-seen-file", "pc_first_seen.json",
            "--interval", "60"
        ]
    elif coverage_type == "virtfuzz":
        cmd = [
            "python3", f"{CHAOS_BASE}/pc_timestamper.py",
            "--virtfuzz-coverage", config["coverage_file"],
            "--outdir", config["workdir"],
            "--pc-first-seen-file", "pc_first_seen.json",
            "--interval", "60"
        ]
    else:
        cmd = [
            "python3", f"{CHAOS_BASE}/pc_timestamper.py",
            "--rawcover", config["coverage_file"],
            "--outdir", config["workdir"],
            "--pc-first-seen-file", "pc_first_seen.json",
            "--interval", "60"
        ]
    
    print(f"[+] Starting lightweight PC timestamper for {fuzzer_name} mode {mode}")
    log_path = os.path.join(config["workdir"], f"pc_timestamp_{mode}.log")
    
    # Use unbuffered output so logs appear immediately
    proc = subprocess.Popen(
        cmd,
        stdout=open(log_path, "a"),
        stderr=subprocess.STDOUT,
        cwd=CHAOS_BASE,
        env=dict(os.environ, PYTHONUNBUFFERED="1")
    )
    print(f"[+] PC timestamp log: {log_path}")
    return proc


def setup_fuzzer_environment(fuzzer_name, mode, config):
    """Run all pre-flight setup steps"""
    
    os.makedirs(config["workdir"], exist_ok=True)
    
    # VirtFuzz uses device-specific images that are set up separately
    # Skip chaos_probe setup here since each device image needs its own setup
    if fuzzer_name == "virtfuzz":
        print(f"[+] VirtFuzz uses device-specific images - chaos_probe setup should be done per-device")
        print(f"[+] Using device-specific image: {config.get('image', 'not yet set')}")
        print(f"[+] Environment setup complete for VirtFuzz")
        return
    
    chaos_probe_script = f"{CHAOS_BASE}/chaos_probe.sh"
    chaos_probe_source = f"{CHAOS_BASE}/chaos_probe.c"

    # Compile to a private path. A shared output path lets a concurrently
    # launching trial copy this binary while the linker has it truncated,
    # silently installing a 0-byte or partially linked probe.
    probe_dir = tempfile.mkdtemp(prefix=".chaos_probe_build_", dir=CHAOS_BASE)
    chaos_probe_bin = os.path.join(probe_dir, "chaos_probe")
    try:
        subprocess.run(f"gcc -ggdb3 -static -O0 -o {chaos_probe_bin} {chaos_probe_source}", shell=True, check=True)

        # Fail loudly rather than install an unusable probe: an empty file runs
        # under /bin/sh as an empty script, so the guest reports success.
        with open(chaos_probe_bin, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                print(f"[-] Compiled chaos_probe is not a valid ELF")
                sys.exit(1)

        print(f"[+] Running setup_chaos_probe.sh for {fuzzer_name} mode={mode}")
        result = subprocess.run([
            "sudo", f"{CHAOS_BASE}/setup_chaos_probe.sh",
            config["image"],
            chaos_probe_bin,
            chaos_probe_script,
            mode
        ], capture_output=True, text=True)

        print(result.stdout)

        if result.returncode != 0:
            print(f"[-] setup_chaos_probe.sh failed: {result.stderr}")
            sys.exit(1)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    # UIO modules are installed by setup_chaos_probe.sh itself (needed for
    # Actor's ivshmem) -- no separate step required here.

    print(f"[+] Environment setup complete")


def create_config(fuzzer_name, mode, config):
    """Create config file for fuzzer if it doesn't exist.
    
    Creates mode-specific config files for syzkaller, countdown, and actor.
    Healer and VirtFuzz use CLI args, so no config files are needed.
    
    Returns True if config was created or already exists, False on error.
    """
    if fuzzer_name not in ["syzkaller", "countdown", "actor"]:
        # Healer and VirtFuzz don't use config files
        return True
    
    config_file = config.get("config_file")
    if not config_file:
        return True
    
    if os.path.exists(config_file):
        print(f"[+] Config file already exists: {config_file}")
        return True
    
    workdir = config["workdir"]
    http_port = config["http_port"]
    kernel_obj = config["kernel_obj"]
    
    # Ensure workdir exists
    os.makedirs(workdir, exist_ok=True)
    
    if fuzzer_name == "syzkaller":
        image = config["image"]
        ssh_key = config["ssh_key"]
        cfg = {
            "target": "linux/amd64",
            "http": f"0.0.0.0:{http_port}",
            "workdir": workdir,
            "kernel_obj": kernel_obj,
            "image": image,
            "sshkey": ssh_key,
            "syzkaller": f"{CHAOS_BASE}/syzkaller/syzkaller",
            "procs": 1,
            "type": "qemu",
            "reproduce": False,
            "vm": {
                "count": 1,
                "kernel": f"{kernel_obj}arch/x86/boot/bzImage",
                "cmdline": "net.ifnames=0 console=ttyS0 root=/dev/sda rw rootfstype=ext4 ramoops.mem_address=0x140000000 ramoops.mem_size=0x6400000 ramoops.record_size=0x100000 ramoops.console_size=0x2800000 ramoops.pmsg_size=0x1400000 null_blk.nr_devices=1 null_blk.zoned=1 null_blk.zone_size=256 mac80211_hwsim.radios=2 dummy_hcd.num=1 nokaslr security=selinux nomodeset fbcon=disable",
                "cpu": 2,
                "mem": 4096,
                "qemu_args": "-enable-kvm -smp 2,sockets=2,cores=1 -virtfs local,id=shared_dev,path=./shared,security_model=none,mount_tag=hostshare -object memory-backend-file,id=ramoops_mem,size=0x6400000,mem-path=./shared/ramoops.bin,share=on -device pc-dimm,id=ramoops_dimm,memdev=ramoops_mem,addr=0x140000000 -m 4096M,slots=1,maxmem=4196M -device intel-hda -device hda-duplex -device virtio-gpu-pci,edid=false -nic user,model=e1000e"
            },
            "max_crash_logs": 15
        }

    elif fuzzer_name == "countdown":
        # Countdown uses relative paths from workdir
        cfg = {
            "target": "linux/amd64",
            "http": f"127.0.0.1:{http_port}",
            "workdir": "./workdir",
            "kernel_obj": "../../linux/",
            "image": f"../../image/stretch_{mode}.img",
            "sshkey": "../../image/stretch.id_rsa",
            "syzkaller": "../",
            "procs": 1,
            "type": "qemu",
            "reproduce": False,
            "vm": {
                "count": 1,
                "kernel": "../../linux/arch/x86/boot/bzImage",
                "cmdline": "net.ifnames=0 console=ttyS0 root=/dev/sda rw rootfstype=ext4 ramoops.mem_address=0x140000000 ramoops.mem_size=0x6400000 ramoops.record_size=0x100000 ramoops.console_size=0x2800000 ramoops.pmsg_size=0x1400000 null_blk.nr_devices=1 null_blk.zoned=1 null_blk.zone_size=256 mac80211_hwsim.radios=2 dummy_hcd.num=1 nokaslr security=selinux nomodeset fbcon=disable",
                "cpu": 2,
                "mem": 4096,
                "qemu_args": "-enable-kvm -smp 2,sockets=2,cores=1 -virtfs local,id=shared_dev,path=./shared,security_model=none,mount_tag=hostshare -object memory-backend-file,id=ramoops_mem,size=0x6400000,mem-path=./shared/ramoops.bin,share=on -device pc-dimm,id=ramoops_dimm,memdev=ramoops_mem,addr=0x140000000 -m 4096M,slots=1,maxmem=4196M -device intel-hda -device hda-duplex -device virtio-gpu-pci,edid=false -nic user,model=e1000e"
            },
            "max_crash_logs": 15
        }

    elif fuzzer_name == "actor":
        # Actor uses relative paths from setup/actor_{mode}
        # Get trial suffix to match the actual out_workdir path
        trial = config.get("trial")
        trial_suffix = f"_trial{trial}" if trial else ""
        # Name is used for unique ivshmem paths when multiple Actor trials run on same instance
        actor_name = f"actor_{mode}{trial_suffix}"
        cfg = {
            "name": actor_name,
            "target": "linux/amd64",
            "http": f":{http_port}",
            "workdir": f"../../out/workdir_{mode}{trial_suffix}",
            "image": f"../../image/bullseye_{mode}{trial_suffix}.img",
            "kernel_obj": "../../linux",
            "sshkey": "../../image/bullseye.id_rsa",
            "syzkaller": "../../src/github.com/google/syzkaller",
            "procs": 1,
            "reproduce": False,
            "type": "qemu",
            "vm": {
                "count": 1,
                "kernel": "../../linux/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 4096,
                "cmdline": "net.ifnames=0 console=ttyS0 root=/dev/sda rw rootfstype=ext4 loglevel=4 selinux=0 nopat iomem=relaxed ramoops.mem_address=0x140000000 ramoops.mem_size=0x6400000 ramoops.record_size=0x100000 ramoops.console_size=0x2800000 ramoops.pmsg_size=0x1400000 null_blk.nr_devices=1 null_blk.zoned=1 null_blk.zone_size=256 mac80211_hwsim.radios=2 dummy_hcd.num=1 nokaslr security=selinux nomodeset fbcon=disable",
                "qemu_args": "-enable-kvm -smp 2,sockets=2,cores=1 -virtfs local,id=shared_dev,path=./shared,security_model=none,mount_tag=hostshare -object memory-backend-file,id=ramoops_mem,size=0x6400000,mem-path=./shared/ramoops.bin,share=on,prealloc=on -device pc-dimm,id=ramoops_dimm,memdev=ramoops_mem,addr=0x140000000 -m 4096M,slots=1,maxmem=4196M -device intel-hda -device hda-duplex -device virtio-gpu-pci"
            },
            "max_crash_logs": 15,
            "ignores": [
                "WARNING: The mand mount option has been deprecated and",
                "WARNING: fbcon: Driver 'bochs-drmdrmfb' missed to adjust virtual screen size*",
                "WARNING: fbcon: Driver 'vkmsdrmfb' missed to adjust virtual screen size*"
            ],
            "disable_syscalls": []
        }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(cfg, f, indent=4)
        print(f"[+] Created config file: {config_file}")
        return True
    except Exception as e:
        print(f"[-] Failed to create config file {config_file}: {e}")
        return False


# Wall-clock start of a trial, kept in its workdir so a restart only runs what is left.
TRIAL_START_FILE = ".trial_start"


def read_trial_start(workdir):
    try:
        with open(os.path.join(workdir, TRIAL_START_FILE)) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def trial_start_time(workdir):
    """Return the trial's first start time, recording now if this is its first run."""
    started = read_trial_start(workdir)
    if started is None:
        started = time.time()
        try:
            with open(os.path.join(workdir, TRIAL_START_FILE), "w") as f:
                f.write(f"{started:.0f}\n")
        except OSError as e:
            print(f"[-] Could not record trial start ({e}), clock will reset on restart")
    return started


# Trial results that must survive a restart; prepare_workdir runs on every launch.
KEEP_ACROSS_RESTART = ("pc_first_seen.json", "pc_timestamp_*.log", "relation_collect_*.log",
                       "fuzzer_output.log", TRIAL_START_FILE)


def kept_across_restart(name):
    return any(fnmatch.fnmatch(name, pattern) for pattern in KEEP_ACROSS_RESTART)


def remove_stale(dirpath, patterns):
    """rm -rf each glob pattern under dirpath, sparing files kept across restarts."""
    for pattern in patterns:
        for target in glob.glob(os.path.join(dirpath, pattern)):
            if kept_across_restart(os.path.basename(target)):
                continue
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target, ignore_errors=True)
            else:
                try:
                    os.remove(target)
                except OSError:
                    pass


def reset_shared_dir(shared_dir):
    """Clear a trial's shared dir but keep whatever CVE state it has accumulated.

    prepare_workdir also runs on a systemd auto-restart, and deleting cve_states/
    there discards every CVE the trial has found so far while its coverage
    counters survive -- the trial then reports full coverage against partial bug
    data. To start a trial genuinely fresh, remove the workdir explicitly.
    """
    keep = {"cve_state.bin", "cve_states"}
    try:
        entries = os.listdir(shared_dir)
    except OSError:
        return
    for name in entries:
        if name in keep:
            continue
        target = os.path.join(shared_dir, name)
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.remove(target)
            except OSError:
                pass


def reset_virtfuzz_workdir(workdir):
    """Clear a VirtFuzz workdir but keep its accumulated results.

    VirtFuzz wiped the whole workdir here, which on a systemd auto-restart threw
    away CVE state AND coverage (pc_first_seen.json / pc_timestamp_*.log), not
    just the scratch files. Keep results, drop everything else. To start a trial
    genuinely fresh, remove the workdir explicitly.
    """
    keep_top = {"shared", "crashes", "bzImage.coverage"}
    keep_shared = {"cve_state.bin", "cve_states", "chaos_probe.log"}
    try:
        entries = os.listdir(workdir)
    except OSError:
        return
    for name in entries:
        if name in keep_top or kept_across_restart(name):
            continue
        target = os.path.join(workdir, name)
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                os.remove(target)
            except OSError:
                pass
    shared_dir = os.path.join(workdir, "shared")
    if os.path.isdir(shared_dir):
        for name in os.listdir(shared_dir):
            if name in keep_shared:
                continue
            target = os.path.join(shared_dir, name)
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target, ignore_errors=True)
            else:
                try:
                    os.remove(target)
                except OSError:
                    pass


def prepare_workdir(fuzzer_name, mode, config):
    """Prepare clean workdir with required structure for each fuzzer.
    
    This function:
    1. Creates config file if it doesn't exist
    2. Cleans stale files from previous runs
    3. Creates required directory structure (shared/, bin/, etc.)
    4. Copies required files (ptrs.txt, binaries)
    5. Validates that existing configs have reproduce=false
    """
    
    # Create config file if it doesn't exist
    if not create_config(fuzzer_name, mode, config):
        print(f"[-] Failed to create config for {fuzzer_name} {mode}")
        sys.exit(1)
    
    workdir = config["workdir"]
    
    if fuzzer_name == "syzkaller":
        # Clean stale files from previous runs
        stale_patterns = [
            "*.log", "instance-lock", "repro.txt",
            "stats", "*.py", "cve_repro_commands.sh", "log", "log_*",
            "*.json", "rawcover", "instance*"
        ]
        remove_stale(workdir, stale_patterns)

        p = os.path.join(workdir, "crashes")
        if os.path.exists(p) and os.listdir(p):
            print(f"[+] {p} already has content, treating as resume, skipping wipe")
        else:
            subprocess.run(f"rm -rf {p}", shell=True)
        
        # Create required directories
        shared_dir = os.path.join(workdir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        reset_shared_dir(shared_dir)
        
        # Validate test.cfg (should have been created by create_config)
        cfg_path = os.path.join(workdir, "test.cfg")
        if not os.path.exists(cfg_path):
            print(f"[-] Config file not found: {cfg_path}")
            print(f"[-] Config auto-creation may have failed")
            sys.exit(1)
        
        with open(cfg_path, 'r') as f:
            try:
                cfg = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[-] Invalid JSON in {cfg_path}: {e}")
                sys.exit(1)
        
        if cfg.get("reproduce") != False:
            print(f"[-] {cfg_path} has reproduce={cfg.get('reproduce')}, must be false")
            sys.exit(1)
        
        print(f"[+] Validated {cfg_path}: reproduce=false")
        
    elif fuzzer_name == "countdown":
        # Clean stale files from previous runs
        stale_patterns = [
            "*.log", "log_*", "workdir_*", "*.json", "rawcover"
        ]
        remove_stale(workdir, stale_patterns)
        
        # Create required directories
        shared_dir = os.path.join(workdir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        reset_shared_dir(shared_dir)
        
        # Validate cd_cfg (should have been created by create_config)
        cfg_path = os.path.join(workdir, "cd_cfg")
        if not os.path.exists(cfg_path):
            print(f"[-] Config file not found: {cfg_path}")
            print(f"[-] Config auto-creation may have failed")
            sys.exit(1)
        
        with open(cfg_path, 'r') as f:
            try:
                cfg = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[-] Invalid JSON in {cfg_path}: {e}")
                sys.exit(1)
        
        if cfg.get("reproduce") != False:
            print(f"[-] {cfg_path} has reproduce={cfg.get('reproduce')}, must be false")
            sys.exit(1)
        
        print(f"[+] Validated {cfg_path}: reproduce=false")
        
    elif fuzzer_name == "actor":
        setup_dir = config["workdir"]
        out_workdir = config["out_workdir"]
        
        # Clean setup directory
        setup_stale = ["*.log", "log_*", "*.json", "rawcover", "out.json"]
        remove_stale(setup_dir, setup_stale)
        
        # Create shared in setup dir
        shared_dir = os.path.join(setup_dir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        reset_shared_dir(shared_dir)
        
        # Clean out_workdir
        out_stale = [
            "instance-lock", "stats", "*.py",
            "cve_repro_commands.sh", "*.json"
        ]
        os.makedirs(out_workdir, exist_ok=True)
        remove_stale(out_workdir, out_stale)

        p = os.path.join(out_workdir, "crashes")
        if os.path.exists(p) and os.listdir(p):
            print(f"[+] {p} already has content, treating as resume, skipping wipe")
        else:
            subprocess.run(f"rm -rf {p}", shell=True)
        
        # Copy ptrs.txt to out_workdir
        ptrs_src = f"{CHAOS_BASE}/actor/linux/ptrs.txt"
        ptrs_dst = os.path.join(out_workdir, "ptrs.txt")
        if os.path.exists(ptrs_src):
            subprocess.run(f"cp {ptrs_src} {ptrs_dst}", shell=True)
            print(f"[+] Copied ptrs.txt to {ptrs_dst}")
        else:
            print(f"[-] ptrs.txt not found at {ptrs_src}")
            sys.exit(1)
        
        # Validate actor.config (should have been created by create_config)
        cfg_path = os.path.join(setup_dir, "actor.config")
        if not os.path.exists(cfg_path):
            print(f"[-] Config file not found: {cfg_path}")
            print(f"[-] Config auto-creation may have failed")
            sys.exit(1)
        
        with open(cfg_path, 'r') as f:
            try:
                cfg = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[-] Invalid JSON in {cfg_path}: {e}")
                sys.exit(1)
        
        if cfg.get("reproduce") != False:
            print(f"[-] {cfg_path} has reproduce={cfg.get('reproduce')}, must be false")
            sys.exit(1)
        
        print(f"[+] Validated {cfg_path}: reproduce=false")
        
    elif fuzzer_name == "healer":
        # Clean stale files
        stale_patterns = [
            "*.log", "ev1_*.log", "*.json", "out.json",
            "instance*", "stats"
        ]
        remove_stale(workdir, stale_patterns)

        for protected in ["output/crashes", "output/raw_coverage"]:
            p = os.path.join(workdir, protected)
            if os.path.exists(p) and os.listdir(p):
                print(f"[+] {p} already has content, treating as resume, skipping wipe")
            else:
                subprocess.run(f"rm -rf {p}", shell=True)
        
        # Remove loose syz-* binaries in workdir root (should be in bin/)
        subprocess.run(f"rm -f {workdir}/syz-*", shell=True)
        
        # Create required directories
        shared_dir = os.path.join(workdir, "shared")
        bin_dir = os.path.join(workdir, "bin")
        linux_amd64_dir = os.path.join(bin_dir, "linux_amd64")
        output_dir = os.path.join(workdir, "output")
        
        os.makedirs(shared_dir, exist_ok=True)
        os.makedirs(bin_dir, exist_ok=True)
        os.makedirs(linux_amd64_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        reset_shared_dir(shared_dir)
        
        # Source directories for binaries
        # Try multiple locations in order of preference:
        # 1. healer/test_workdir/bin (pre-built)
        # 2. syzkaller/syzkaller/bin (from syzkaller build)
        healer_bin = f"{CHAOS_BASE}/healer/target/release/healer"
        syz_bin_candidates = [
            f"{CHAOS_BASE}/healer/test_workdir/bin",
            f"{CHAOS_BASE}/syzkaller/syzkaller/bin",
        ]
        
        # Find first available syz bin directory
        syz_bin_dir = None
        for candidate in syz_bin_candidates:
            if os.path.exists(candidate) and os.path.isdir(candidate):
                syz_bin_dir = candidate
                print(f"[+] Found syz binaries at: {syz_bin_dir}")
                break
        
        if not syz_bin_dir:
            print(f"[-] No syz binaries found in: {syz_bin_candidates}")
            sys.exit(1)
        
        # Copy healer binary
        if os.path.exists(healer_bin):
            subprocess.run(f"cp {healer_bin} {bin_dir}/", shell=True)
            print(f"[+] Copied healer binary to {bin_dir}")
        else:
            print(f"[-] healer binary not found at {healer_bin}")
            sys.exit(1)
        
        # Copy syz-* tools
        syz_tools = ["syz-cover", "syz-repro", "syz-symbolize", "syz-sysgen"]
        for tool in syz_tools:
            src = os.path.join(syz_bin_dir, tool)
            if os.path.exists(src):
                subprocess.run(f"cp {src} {bin_dir}/", shell=True)
            else:
                print(f"[WARN] {tool} not found at {src}, skipping (may not be required)")
        
        # Copy linux_amd64 binaries
        linux_amd64_src = os.path.join(syz_bin_dir, "linux_amd64")
        if os.path.exists(linux_amd64_src):
            subprocess.run(f"cp {linux_amd64_src}/* {linux_amd64_dir}/", shell=True)
            print(f"[+] Copied linux_amd64 binaries to {linux_amd64_dir}")
        else:
            print(f"[-] linux_amd64 directory not found at {linux_amd64_src}")
            sys.exit(1)
        
        # Healer uses CLI args, --disable-repro is in run_cmd, no config file to validate
        print(f"[+] Healer workdir prepared with bin/ structure")
        
    elif fuzzer_name == "virtfuzz":
        # Keep results across restarts; drop scratch. See reset_virtfuzz_workdir.
        if os.path.exists(workdir):
            reset_virtfuzz_workdir(workdir)
        os.makedirs(workdir, exist_ok=True)
        
        # Create shared directory (required by VirtFuzz and for ramoops)
        shared_dir = os.path.join(workdir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        
        print(f"[+] VirtFuzz workdir cleaned: {workdir}")
    
    print(f"[+] Workdir preparation complete for {fuzzer_name}")
    return True


def download_corpus(fuzzer_name, mode, config):
    """Download corpus for the fuzzer before starting.
    
    - syzkaller, countdown: Download corpus.db from GitHub releases to workdir
    - actor: Download corpus.db from GitHub releases to out_workdir
    - healer: Copy files from existing clone to output/corpus/
    - virtfuzz: Skip (no corpus needed)
    """
    
    if fuzzer_name == "virtfuzz":
        print(f"[+] Skipping corpus download for {fuzzer_name}")
        
        # Create VirtFuzz marker file in shared directory
        shared_dir = os.path.join(config["workdir"], "shared")
        marker_file = os.path.join(shared_dir, "VIRTFUZZ_MODE")
        os.makedirs(shared_dir, exist_ok=True)
        with open(marker_file, "w") as f:
            f.write("virtfuzz\n")
        print(f"[+] Created VirtFuzz marker file: {marker_file}")
        
        return True
    
    corpus_url = "https://github.com/cmu-pasta/linux-kernel-enriched-corpus/releases/download/latest/corpus.db"
    
    if fuzzer_name in ["syzkaller", "countdown"]:
        workdir = config["workdir"]
        os.makedirs(workdir, exist_ok=True)
        corpus_path = os.path.join(workdir, "corpus.db")
        
        if os.path.exists(corpus_path):
            print(f"[+] Corpus already exists at {corpus_path}, skipping download")
            return True
        
        print(f"[+] Downloading corpus.db for {fuzzer_name} to {workdir}")
        result = subprocess.run(
            ["wget", "-q", "--show-progress", "-O", corpus_path, corpus_url],
            cwd=workdir
        )
        
        if result.returncode != 0:
            print(f"[-] Failed to download corpus.db")
            return False
        
        print(f"[+] Corpus downloaded successfully to {corpus_path}")
        return True
    
    elif fuzzer_name == "actor":
        # Actor corpus goes to out_workdir, not setup workdir
        out_workdir = config.get("out_workdir", config["workdir"])
        os.makedirs(out_workdir, exist_ok=True)
        corpus_path = os.path.join(out_workdir, "corpus.db")
        
        if os.path.exists(corpus_path):
            print(f"[+] Corpus already exists at {corpus_path}, skipping download")
            return True
        
        print(f"[+] Downloading corpus.db for {fuzzer_name} to {out_workdir}")
        result = subprocess.run(
            ["wget", "-q", "--show-progress", "-O", corpus_path, corpus_url],
            cwd=out_workdir
        )
        
        if result.returncode != 0:
            print(f"[-] Failed to download corpus.db")
            return False
        
        print(f"[+] Corpus downloaded successfully to {corpus_path}")
        return True
    
    elif fuzzer_name == "healer":
        workdir = config["workdir"]
        output_corpus_dir = os.path.join(workdir, "output", "corpus")
        
        if os.path.exists(output_corpus_dir) and os.listdir(output_corpus_dir):
            print(f"[+] Corpus already exists at {output_corpus_dir}, skipping copy")
            return True
        
        os.makedirs(output_corpus_dir, exist_ok=True)
        
        # Use existing clone at CHAOS_BASE/linux-kernel-enriched-corpus
        enriched_corpus_path = f"{CHAOS_BASE}/linux-kernel-enriched-corpus"
        files_dir = os.path.join(enriched_corpus_path, "files")
        
        if not os.path.exists(files_dir):
            print(f"[-] Enriched corpus files directory not found at {files_dir}")
            return False
        
        print(f"[+] Copying corpus files from {files_dir} to {output_corpus_dir}")
        # Use find + xargs to handle large number of files (avoids "Argument list too long")
        result = subprocess.run(
            f"find {files_dir} -type f -print0 | xargs -0 -I {{}} cp {{}} {output_corpus_dir}/",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[-] Failed to copy corpus files: {result.stderr}")
            return False
        
        print(f"[+] Corpus files copied successfully to {output_corpus_dir}")
        return True

    return True


# Fuzzers that download the raw enriched corpus and need it minimized once,
# under C3, before any C1/C2/C3 trial uses it. VirtFuzz uses its own
# domain-specific corpus_shared and is not part of this.
MINIMIZABLE_FUZZERS = ["syzkaller", "countdown", "actor", "healer"]

# Trial id reserved for the one-time minimization run. Must stay outside the
# real trial range (1-10) and safe for port_offset = trial*100 (countdown's
# base port 56753 is the tightest: trial must stay <= 87).
MINIMIZE_TRIAL_ID = 50

# Bounds one-time corpus minimization: candidates=0 never reliably fires.
MINIMIZE_BUDGET_SECONDS = 4 * 3600
MINIMIZE_STALL_FRACTION = 0.10  # trailing rate < 10% of peak observed rate...
MINIMIZE_PATIENCE_SECONDS = 2 * 3600  # ...sustained this long => stop early
MINIMIZE_POLL_INTERVAL_SECONDS = 30


def _minimization_progress_path(fuzzer_name, config):
    # countdown's real corpus.db is nested under workdir/, unlike the others.
    if fuzzer_name == "healer":
        return os.path.join(config["workdir"], "output", "corpus"), "dir"
    if fuzzer_name == "countdown":
        return os.path.join(config["workdir"], "workdir", "corpus.db"), "file"
    if fuzzer_name == "actor":
        workdir = config.get("out_workdir", config["workdir"])
        return os.path.join(workdir, "corpus.db"), "file"
    return os.path.join(config["workdir"], "corpus.db"), "file"  # syzkaller


def _minimization_progress_size(path, kind):
    try:
        if kind == "dir":
            return len(os.listdir(path))
        return os.path.getsize(path)
    except OSError:
        return None


def _minimized_corpus_paths(fuzzer_name):
    """Where the persistent, reusable minimized corpus lives for a fuzzer.

    syzkaller/countdown/actor produce a single packed corpus.db; healer
    stores individual files, so its minimized artifact is a directory.
    """
    base = f"{CHAOS_BASE}/{fuzzer_name}"
    if fuzzer_name == "healer":
        artifact = os.path.join(base, "minimized_corpus")
    else:
        artifact = os.path.join(base, "minimized_corpus.db")
    marker = os.path.join(base, "minimized_corpus.done")
    lock = os.path.join(base, "minimized_corpus.lock")
    return artifact, marker, lock


def ensure_minimized_corpus(fuzzer_name):
    """Make sure a minimized, C3-converged corpus exists for this fuzzer.

    Idempotent and safe to call before every trial launch: no-ops immediately
    if the marker file is already present, waits for an in-progress run from
    a concurrently-launched sibling mode to finish rather than duplicating
    it, and only actually runs the one-time C3 minimization pass otherwise.
    """
    import shutil

    if fuzzer_name not in MINIMIZABLE_FUZZERS:
        return True

    artifact, marker, lock = _minimized_corpus_paths(fuzzer_name)

    if os.path.exists(marker):
        print(f"[+] Minimized corpus already present for {fuzzer_name}, skipping minimization")
        return True

    # Another trial's launch (e.g. a sibling mode started in the same wave)
    # may already be minimizing this fuzzer's corpus. Wait for it instead of
    # racing a second C3 run -- but if the lock holder died without cleaning
    # up (e.g. killed -9, scope torn down), treat the lock as stale rather
    # than waiting forever for a marker that will never appear.
    outer_start = time.time()
    own_lock = False
    while True:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(lock_fd, str(os.getpid()).encode())
            os.close(lock_fd)
            own_lock = True
            break
        except FileExistsError:
            pass

        if os.path.exists(marker):
            print(f"[+] Minimized corpus for {fuzzer_name} became available")
            return True

        try:
            with open(lock, "r") as f:
                holder_pid = int(f.read().strip())
            os.kill(holder_pid, 0)
            holder_alive = True
        except ProcessLookupError:
            holder_alive = False
        except (ValueError, FileNotFoundError):
            holder_alive = False
        except PermissionError:
            holder_alive = True

        if not holder_alive:
            print(f"[-] Stale minimization lock for {fuzzer_name} (holder pid dead), removing")
            try:
                os.remove(lock)
            except OSError:
                pass
            continue

        if time.time() - outer_start > 72 * 3600:
            print(f"[-] Timed out waiting for {fuzzer_name} minimization to complete")
            return False

        print(f"[+] Minimization in progress for {fuzzer_name} (pid {holder_pid} alive), waiting...")
        time.sleep(30)

    try:
        print(f"[+] No minimized corpus found for {fuzzer_name}, running one-time C3 minimization pass")
        config = get_fuzzer_config(fuzzer_name, "c3", trial=MINIMIZE_TRIAL_ID)
        if not config:
            print(f"[-] Could not build minimization config for {fuzzer_name}")
            return False

        # Mirror the trial-specific-image creation step from the main launch
        # flow (__main__): a trial's image doesn't exist until copied from
        # the mode's base image.
        if config.get("image") and not os.path.exists(config["image"]):
            trial_image = config["image"]
            base_image = config.get("base_image")
            if not base_image:
                base_image = trial_image.replace(f"_trial{MINIMIZE_TRIAL_ID}", "")
            if not os.path.exists(base_image):
                print(f"[-] Base image not found for {fuzzer_name} minimization: {base_image}")
                return False
            print(f"[+] Creating trial-specific image for minimization: {trial_image}")
            result = subprocess.run(
                f"cp --reflink=auto '{base_image}' '{trial_image}'",
                shell=True, capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"[-] Failed to copy base image: {result.stderr}")
                return False

        if "http_port" in config:
            kill_process_on_port(config["http_port"])
        if "broker_port" in config:
            kill_process_on_port(config["broker_port"])

        setup_fuzzer_environment(fuzzer_name, "c3", config)

        if not prepare_workdir(fuzzer_name, "c3", config):
            print(f"[-] Workdir preparation failed for {fuzzer_name} minimization pass")
            return False

        # Deliberately the raw enriched-corpus fetch, not this function --
        # this is exactly the seed material we want minimized.
        if not download_corpus(fuzzer_name, "c3", config):
            print(f"[-] Raw corpus fetch failed for {fuzzer_name} minimization pass")
            return False

        proc = start_fuzzer(fuzzer_name, config["workdir"], config["run_cmd"], config["vm_boot_time"])
        if proc is None:
            print(f"[-] Failed to start {fuzzer_name} for minimization pass")
            return False

        src, src_kind = _minimization_progress_path(fuzzer_name, config)
        print(f"[+] Minimizing {fuzzer_name}: tracking {src} ({src_kind}), "
              f"budget={MINIMIZE_BUDGET_SECONDS/3600:.1f}h, stops early if growth "
              f"drops below {MINIMIZE_STALL_FRACTION*100:.0f}% of its peak rate for "
              f"{MINIMIZE_PATIENCE_SECONDS/60:.0f}min")
        start_time = time.time()
        last_size = _minimization_progress_size(src, src_kind)
        last_sample_time = start_time
        peak_rate = 0.0
        stall_since = None
        try:
            while True:
                if proc.poll() is not None:
                    print(f"[-] Fuzzer process exited unexpectedly during minimization")
                    return False

                elapsed = time.time() - start_time
                if elapsed > MINIMIZE_BUDGET_SECONDS:
                    print(f"[+] Minimization budget ({MINIMIZE_BUDGET_SECONDS/3600:.1f}h) "
                          f"reached for {fuzzer_name}, stopping")
                    break

                time.sleep(MINIMIZE_POLL_INTERVAL_SECONDS)

                now = time.time()
                size = _minimization_progress_size(src, src_kind)
                rate = 0.0
                if size is not None and last_size is not None:
                    dt = now - last_sample_time
                    if dt > 0:
                        rate = max(0.0, (size - last_size) / dt)
                    peak_rate = max(peak_rate, rate)
                    if peak_rate > 0 and rate < MINIMIZE_STALL_FRACTION * peak_rate:
                        if stall_since is None:
                            stall_since = now
                        elif now - stall_since >= MINIMIZE_PATIENCE_SECONDS:
                            print(f"[+] {fuzzer_name}: growth stalled below "
                                  f"{MINIMIZE_STALL_FRACTION*100:.0f}% of peak rate for "
                                  f"{MINIMIZE_PATIENCE_SECONDS/60:.0f}min, stopping early "
                                  f"({elapsed/3600:.1f}h elapsed)")
                            break
                    else:
                        stall_since = None
                last_size, last_sample_time = size, now
                print(f"[+] {fuzzer_name}: progress={size} elapsed={elapsed/60:.0f}min "
                      f"rate={rate:.2f}/s peak_rate={peak_rate:.2f}/s "
                      f"stalled_for={0 if stall_since is None else (now - stall_since)/60:.0f}min")
        finally:
            print(f"[+] Stopping {fuzzer_name} minimization run")
            kill_process_tree(proc)
            time.sleep(5)  # let the corpus artifact flush before we read it

        final_size = _minimization_progress_size(src, src_kind)
        if fuzzer_name == "healer":
            if final_size is None or final_size == 0:
                print(f"[-] No corpus produced by {fuzzer_name} minimization pass at {src}")
                return False
            if os.path.exists(artifact):
                shutil.rmtree(artifact)
            shutil.copytree(src, artifact)
        else:
            if final_size is None:
                print(f"[-] No corpus.db produced by {fuzzer_name} minimization pass at {src}")
                return False
            shutil.copy(src, artifact)

        with open(marker, "w") as f:
            f.write(f"minimized at {time.ctime()}, final progress={final_size} ({src_kind})\n")

        print(f"[+] Minimized corpus for {fuzzer_name} saved to {artifact}")
        return True
    finally:
        try:
            os.remove(lock)
        except OSError:
            pass


def load_minimized_corpus(fuzzer_name, config, seed_corpus=None):
    """Copy the pre-minimized corpus (or seed_corpus, if given) into a real trial's workdir.

    Replaces download_corpus() for the four fuzzers minimized above -- the
    raw corpus is never fed into an actual C1/C2/C3 trial directly.
    """
    import shutil

    artifact, marker, _ = _minimized_corpus_paths(fuzzer_name)
    if seed_corpus:
        artifact = seed_corpus
    elif not os.path.exists(marker):
        print(f"[-] No minimized corpus marker for {fuzzer_name}; call ensure_minimized_corpus() first")
        return False

    if fuzzer_name == "healer":
        dest = os.path.join(config["workdir"], "output", "corpus")
        if os.path.exists(dest) and os.listdir(dest):
            print(f"[+] Corpus already present at {dest}, skipping copy")
            return True
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copytree(artifact, dest, dirs_exist_ok=True)
    else:
        workdir = config["workdir"] if fuzzer_name != "actor" else config.get("out_workdir", config["workdir"])
        # cd_cfg sets syz-manager's workdir to ./workdir, so countdown reads corpus.db from there.
        if fuzzer_name == "countdown":
            workdir = os.path.join(workdir, "workdir")
        os.makedirs(workdir, exist_ok=True)
        dest = os.path.join(workdir, "corpus.db")
        if os.path.exists(dest):
            print(f"[+] Corpus already present at {dest}, skipping copy")
            return True
        shutil.copy(artifact, dest)

    print(f"[+] Loaded minimized corpus for {fuzzer_name} into {dest}")
    return True


def kill_process_on_port(port):
    """Kill any process listening on the specified port.
    
    Returns True if a process was killed, False otherwise.
    """
    try:
        # Find process using the port with lsof
        lsof_cmd = f"lsof -ti :{port}"
        result = subprocess.run(
            lsof_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            print(f"[+] Found {len(pids)} process(es) using port {port}")
            
            for pid in pids:
                pid = pid.strip()
                if pid:
                    print(f"[+] Killing process {pid} on port {port}")
                    try:
                        # Try to kill the process group first
                        os.killpg(int(pid), 9)
                    except:
                        # If that fails, kill the process directly
                        subprocess.run(f"kill -9 {pid}", shell=True)
                    time.sleep(1)
            
            print(f"[+] Processes on port {port} have been killed")
            return True
        else:
            print(f"[+] No process found using port {port}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout while checking for processes on port {port}")
        return False
    except Exception as e:
        print(f"[-] Error killing process on port {port}: {e}")
        return False


def detect_qemu_port(fuzzer_workdir, fuzzer_name, image_path=None):
    """Detect QEMU SSH port for the fuzzer.
    
    Strategy: Use the image path to uniquely identify the VM since each mode
    has a unique image file like bullseye_c1.img, bullseye_c2.img, etc.
    Falls back to fuzzer_name if image_path is not provided.
    """
    try:
        abs_workdir = os.path.abspath(fuzzer_workdir)
        
        # Build list of identifiers to search for, in order of preference
        # 1. Use image filename (most reliable - unique per mode)
        # 2. Use fuzzer_name (less specific, matches all modes)
        identifiers = []
        
        # Full path first: unique per fuzzer even when the basename collides
        # (e.g. syzkaller/actor/healer all template to bullseye_c3_trial80.img).
        if image_path:
            identifiers.append(os.path.abspath(image_path))
            image_basename = os.path.basename(image_path)
            identifiers.append(image_basename)
            image_name_noext = os.path.splitext(image_basename)[0]
            if image_name_noext not in identifiers:
                identifiers.append(image_name_noext)
        
        # Add fuzzer_name as fallback
        if fuzzer_name and fuzzer_name not in identifiers:
            identifiers.append(fuzzer_name)
        
        # Add workdir basename as last resort
        workdir_name = os.path.basename(abs_workdir)
        if workdir_name and workdir_name not in identifiers:
            identifiers.append(workdir_name)
        
        print(f"[+] Looking for QEMU port with identifiers: {identifiers}")
        
        # Get all QEMU processes first
        ps_cmd = "ps aux | grep qemu-system"
        result = subprocess.run(
            ps_cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            encoding="utf-8",
            timeout=5
        )
        
        if result.returncode != 0 or not result.stdout.strip():
            print(f"[-] No QEMU processes found")
            return None
        
        lines = result.stdout.split('\n')
        target_vm_port = None
        
        # Try each identifier until we find a matching QEMU process
        for identifier in identifiers:
            for line in lines:
                # Skip grep lines and non-matching lines
                if 'grep' in line or identifier not in line:
                    continue
                
                # Must have hostfwd for SSH
                if 'hostfwd=tcp:' not in line:
                    continue
                
                try:
                    # Extract port: hostfwd=tcp:127.0.0.1:PORT-:22 or hostfwd=tcp::PORT-:22
                    port_section = line.split('hostfwd=tcp:')[1].split()[0]
                    
                    # Handle three formats:
                    # 1. hostfwd=tcp:127.0.0.1:PORT-:22  (explicit bind)
                    # 2. hostfwd=tcp::PORT-:22           (bind to 0.0.0.0)
                    # 3. hostfwd=tcp:PORT-:22            (old format)
                    
                    if port_section.startswith(':'):
                        # Format: ::PORT-:22
                        port_str = port_section[1:].split('-')[0].split(':')[0]
                    elif ':' in port_section:
                        # Format: 127.0.0.1:PORT-:22
                        port_str = port_section.split(':')[1].split('-')[0]
                    else:
                        # Format: PORT-:22
                        port_str = port_section.split('-')[0]
                    
                    port = int(port_str)
                    
                    # Check if this VM has ramoops or virtfs (indicators of target VM)
                    if 'ramoops' in line or 'virtfs' in line or 'hostshare' in line:
                        target_vm_port = port
                        print(f"[+] Found target VM (with ramoops/virtfs) matching '{identifier}' on port: {port}")
                        return target_vm_port
                        
                except (IndexError, ValueError) as e:
                    print(f"[-] Failed to parse port from line: {line[:100]}...")
                    print(f"[-] Error: {e}")
                    continue
        
        if target_vm_port:
            print(f"[+] Detected target QEMU port: {target_vm_port}")
            return target_vm_port
        else:
            print(f"[-] No matching QEMU process with hostfwd found for identifiers: {identifiers}")
            return None
        
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout while detecting port")
        return None
    except Exception as e:
        print(f"[-] Error detecting port: {e}")
        return None


def kill_process_tree(proc):
    """Kill a process and all its children recursively."""
    try:
        import psutil
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        
        # Kill children first
        for child in children:
            try:
                print(f"[+] Killing child process {child.pid} ({child.name()})")
                child.kill()
            except psutil.NoSuchProcess:
                pass
        
        # Kill parent
        try:
            parent.kill()
        except psutil.NoSuchProcess:
            pass
        
        # Wait for termination
        gone, alive = psutil.wait_procs(children + [parent], timeout=3)
        for p in alive:
            try:
                print(f"[!] Force killing stubborn process {p.pid}")
                p.kill()
            except psutil.NoSuchProcess:
                pass
    except Exception as e:
        print(f"[-] Error in kill_process_tree: {e}")
        # Fallback to killpg
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception as e2:
            print(f"[-] Fallback killpg also failed: {e2}")


_ready_watchers = {}


def signal_fuzzer_ready(abs_workdir, log_file, log_start=0):
    """Acknowledge, per guest boot, that VirtFuzz has executed since that boot.

    The guest publishes its boot_id and waits for us to echo it back; we only do so
    after the LibAFL execution counter advances past where it stood when that boot
    appeared. VirtFuzz has no in-guest process for the guest to detect on its own,
    and the counter survives QEMU resets, so an advance is the honest liveness proof.
    Without this the guest arms during boot and systemd's own syscalls get recorded
    as fuzzing discoveries.
    """
    shared = os.path.join(abs_workdir, "shared")
    marker = os.path.join(shared, "FUZZER_READY")
    boot_id_file = os.path.join(shared, "BOOT_ID")

    # Retire any watcher left over from an earlier start_fuzzer on this workdir,
    # otherwise restarts accumulate threads each holding a stale counter.
    previous = _ready_watchers.get(abs_workdir)
    if previous:
        previous.set()
    stop = threading.Event()
    _ready_watchers[abs_workdir] = stop

    for path in (marker, boot_id_file):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def watch():
        acked_boot = None
        pending_boot = None
        baseline = None
        while not stop.is_set():
            try:
                try:
                    with open(boot_id_file) as fh:
                        boot = fh.read().strip()
                except FileNotFoundError:
                    boot = ""

                with open(log_file, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    # The log appends across restarts; ignore counts from before this start.
                    f.seek(max(log_start, f.tell() - 65536))
                    tail = f.read().decode("utf-8", "ignore")
                counts = [int(n) for n in re.findall(r"executions: (\d+)", tail)]
                current = max(counts) if counts else 0

                if boot and boot != acked_boot:
                    if boot != pending_boot:
                        # Re-baseline on every new boot id, never reuse an older one,
                        # or an advance from before this boot could acknowledge it.
                        pending_boot = boot
                        baseline = current
                    elif current > baseline:
                        os.makedirs(shared, exist_ok=True)
                        with open(marker, "w") as fh:
                            fh.write(boot)
                        acked_boot = boot
                elif not boot:
                    pending_boot = None
                    baseline = None
            except FileNotFoundError:
                pass
            stop.wait(3)

    threading.Thread(target=watch, daemon=True).start()


def _rerun_command_with_resume_seeds(fuzzer_name, workdir, run_cmd):
    """On a process restart, import only real corpus inputs from this trial.

    LibAFL's --corpus is an output directory; it does not restore the in-memory
    corpus after the process exits.  --initial-inputs is the import route.
    Metadata and lock files in the output directory must not be imported.
    """
    if fuzzer_name != "virtfuzz":
        return run_cmd
    corpus = os.environ.get("VIRTFUZZ_CORPUS_DIR")
    if not corpus or not os.path.isdir(corpus):
        return run_cmd
    input_files = [entry for entry in os.scandir(corpus)
                   if not entry.name.startswith(".") and entry.is_file(follow_symlinks=False)]
    if not input_files:
        return run_cmd
    seed_dir = os.path.join(os.path.dirname(corpus),
                            f"resume_seeds_{os.path.basename(workdir)}")
    os.makedirs(seed_dir, exist_ok=True)
    for entry in input_files:
        dest = os.path.join(seed_dir, entry.name)
        if not os.path.exists(dest):
            shutil.copy2(entry.path, dest)
    print(f"[+] Resuming VirtFuzz from {len(input_files)} corpus inputs in {seed_dir}")
    return f"{run_cmd} --initial-inputs {shlex.quote(seed_dir)}"


def start_fuzzer(fuzzer_name, workdir, run_cmd, vm_boot_time, max_retries=2):
    """Start the fuzzer in background and wait for VM to boot.
    
    Returns the subprocess.Popen object for the fuzzer process.
    Retries if port is already in use by killing the blocking process.
    """
    import subprocess
    import tempfile
    
    abs_workdir = os.path.abspath(workdir)
    if not os.path.exists(abs_workdir):
        print(f"[-] Workdir does not exist: {abs_workdir}")
        return None
    for attempt in range(max_retries):
        if attempt > 0:
            print(f"[+] Retry attempt {attempt + 1}/{max_retries}")
        
        attempt_cmd = _rerun_command_with_resume_seeds(fuzzer_name, abs_workdir, run_cmd)
        print(f"[+] Starting fuzzer '{fuzzer_name}' in {abs_workdir}")
        print(f"[+] Run command: {attempt_cmd}")
        
        try:
            # Redirect fuzzer output to log file so it doesn't interfere with interactive shell
            log_file = os.path.join(abs_workdir, "fuzzer_output.log")
            log_start = os.path.getsize(log_file) if os.path.exists(log_file) else 0
            log_fd = open(log_file, 'a')
            
            # Start fuzzer in background with output going to log file
            proc = subprocess.Popen(
                attempt_cmd,
                shell=True,
                cwd=abs_workdir,
                stdout=log_fd,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                preexec_fn=os.setsid  # Create new process group for clean termination
            )
            
            print(f"[+] Fuzzer process started (PID: {proc.pid})")
            print(f"[+] Fuzzer output is being logged to: {log_file}")
            if fuzzer_name == "virtfuzz":
                signal_fuzzer_ready(abs_workdir, log_file, log_start)
            print(f"[+] Waiting up to {vm_boot_time}s for VM to boot...")
            
            # Wait and check if process exits prematurely
            wait_time = min(10, vm_boot_time)  # Check after 10 seconds or less
            time.sleep(wait_time)
            
            # Check if process is still running
            if proc.poll() is not None:
                print(f"[-] Fuzzer exited prematurely!")
                print(f"[-] This may indicate a configuration issue")
                
                if attempt >= max_retries - 1:
                    return None
                else:
                    print(f"[-] Retrying...")
                    time.sleep(2)
                    continue
            
            # Process is still running, wait for the rest of the boot time
            remaining_time = vm_boot_time - wait_time
            if remaining_time > 0:
                print(f"[+] Waiting {remaining_time} more seconds for VM to fully boot...")
                time.sleep(remaining_time)
            
            # Final check if process is still running
            if proc.poll() is not None:
                print(f"[-] Fuzzer exited during boot wait!")
                print(f"[-] This may indicate a configuration issue")
                
                if attempt >= max_retries - 1:
                    return None
                continue
            
            print(f"[+] Fuzzer appears to be running, proceeding to SSH")
            return proc
            
        except Exception as e:
            print(f"[-] Failed to start fuzzer: {e}")
            if attempt >= max_retries - 1:
                return None
    
    return None


def build_ssh_session(host, port, user, keyfile=None, password=None, timeout=700):
    """Create an SSH session using pwntools' ssh wrapper.

    Prefer keyfile if provided. Returns pwntools SSH object or None.
    Disables host key checking since VMs are ephemeral and ports change.
    """
    try:
        if keyfile:
            ssh_session = ssh(user, host, port=port, keyfile=keyfile,
                              timeout=timeout, ignore_config=True)
        elif password:
            ssh_session = ssh(user, host, port=port, password=password,
                              timeout=timeout, ignore_config=True)
        print(f"[+] SSH connected to {host}:{port} as {user}")
        return ssh_session
    except Exception as e:
        print(f"[-] SSH connection to {host}:{port} failed: {e}")
        return None

def get_report(ssh_session, remote_probe_path):
    """Get a fresh report from the running probe.
    
    The probe should be running in background, so we just query it for reports.
    We check the device file directly or use a reporting mechanism.
    """
    # Validate session is still connected
    if ssh_session is None:
        print("[-] SSH session is None")
        return None
    
    # Quick connectivity check before running command
    try:
        ssh_session.run("true", timeout=5)
    except Exception as e:
        print(f"[-] SSH session not active: {e}")
        return None
    
    cmd = f"{remote_probe_path} --get-report"
    try:
        print(f"[+] Running: {cmd}")
        channel = ssh_session.run(cmd)
        
        # Read all output from the channel
        try:
            output = channel.recvall(timeout=20).decode('utf-8', errors='replace')
        except:
            # If timeout, get whatever is available
            try:
                output = channel.recv(timeout=10).decode('utf-8', errors='replace')
            except:
                output = ""
        
        channel.close()
        
        # Filter out repetitive initialization messages
        lines = output.split('\n')
        filtered_lines = []
        for line in lines:
            # Skip common initialization/opening messages
            if any(skip in line for skip in [
                "Opened /dev/probe_cve successfully",
                "Crash mode set successfully",
                "bash: line"
            ]):
                continue
            filtered_lines.append(line)
        
        filtered_output = '\n'.join(filtered_lines).strip()
        
        return filtered_output if filtered_output else "No new data"
    except Exception as e:
        print(f"[-] Failed to get report: {e}")
        return None
    

def start_relation_collector(fuzzer_name, mode, config):
    """Start relation_collect.py for countdown fuzzer"""
    
    if fuzzer_name != "countdown":
        return None
    
    relation_script = f"{CHAOS_BASE}/countdown/py-tools/relation_collect.py"
    
    if not os.path.exists(relation_script):
        print(f"[!] relation_collect.py not found, skipping")
        return None
    
    print(f"[+] Starting relation_collect.py for countdown")
    
    log_path = os.path.join(config["workdir"], f"relation_collect_{mode}.log")
    proc = subprocess.Popen(
        ["python3", relation_script],
        cwd=f"{CHAOS_BASE}/countdown/py-tools",
        stdout=open(log_path, "a"),
        stderr=subprocess.STDOUT
    )
    
    print(f"[+] relation_collect.py started (PID: {proc.pid})")
    print(f"[+] Relation collector log: {log_path}")
    return proc


def poll_reports_every_n_hours(ssh_session, remote_probe_path, fuzzer_proc, host, port, user, keyfile, fuzzer_name, workdir, image_path=None, hours=1):
    """Poll for reports with automatic port re-detection.
    
    Uses a mutable state container to allow the thread to update SSH session
    and port values that persist across reconnections.
    """
    # Use mutable container to allow thread to update values
    # This fixes the nonlocal issue with function parameters
    state = {
        'ssh_session': ssh_session,
        'port': port,
        'consecutive_failures': 0
    }
    
    # Shorter interval for crash mode - VMs restart frequently
    # Poll every 30 seconds instead of 30 minutes
    interval = 30  # seconds
    max_failures = 3
    
    def poll_loop():
        while True:
            print(f"[+] Polling for reports...")
            report = get_report(state['ssh_session'], remote_probe_path)
            if report is not None:
                state['consecutive_failures'] = 0  # Reset on success
                print("=" * 80)
                print("[REPORT START]")
                print(report)
                print("[REPORT END]")
                print("=" * 80)
            else:
                state['consecutive_failures'] += 1
                print(f"[-] Failed to fetch report this cycle (failures: {state['consecutive_failures']}/{max_failures})")
                
                # Try to reconnect after consecutive failures
                if state['consecutive_failures'] >= max_failures:
                    print("[!] Multiple failures detected, attempting to re-detect port and reconnect SSH...")
                    try:
                        if state['ssh_session']:
                            state['ssh_session'].close()
                    except:
                        pass
                    state['ssh_session'] = None  # don't let get_report() reuse a dead session

                    time.sleep(5)  # Brief wait before re-detection

                    # Re-detect the QEMU port (VM may have restarted with new port)
                    print("[+] Re-detecting QEMU port...")
                    new_port = detect_qemu_port(workdir, fuzzer_name, image_path)

                    if new_port and new_port != state['port']:
                        print(f"[+] Detected new port: {new_port} (old port was {state['port']})")
                        state['port'] = new_port
                    elif not new_port:
                        print(f"[-] Could not detect new port, using old port {state['port']}")
                    else:
                        print(f"[+] Port unchanged: {state['port']}")

                    # Retry reconnection with growing waits -- observed VM reboots
                    # take ~100-190s, so a single 10s wait almost always fired too
                    # early and left the session dead until the next failure cycle.
                    reconnect_attempts = 6
                    reconnect_wait = 20  # seconds between attempts
                    for attempt in range(1, reconnect_attempts + 1):
                        print(f"[+] Waiting {reconnect_wait}s for VM to stabilize (attempt {attempt}/{reconnect_attempts})...")
                        time.sleep(reconnect_wait)
                        try:
                            new_session = build_ssh_session(host, state['port'], user, keyfile=keyfile)
                            if new_session:
                                state['ssh_session'] = new_session
                                state['consecutive_failures'] = 0
                                print("[+] SSH session reconnected successfully")
                                break
                            else:
                                print(f"[-] Reconnect attempt {attempt} failed, will retry")
                        except Exception as e:
                            print(f"[-] Reconnection error on attempt {attempt}: {e}")
                    else:
                        print("[-] All reconnect attempts exhausted, will re-detect and retry next cycle")
            
            time.sleep(interval)
        
    report_thread = threading.Thread(target=poll_loop, daemon=True)
    report_thread.start()
    return report_thread


def parse_args():
    """Parse command line arguments with argparse for better AWS compatibility."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Start a kernel fuzzer with chaos_probe integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
VirtFuzz devices (priority order based on IEEE S&P 2024 paper):
  wifi-scan        - WiFi scanning mode - 6 CVEs found, 22x faster than Syzkaller

Examples:
  python ssh_comm.py syzkaller c1
  python ssh_comm.py syzkaller c1 --trial 2  # AWS multi-trial mode
  python ssh_comm.py virtfuzz c1 --device wifi-scan
  python ssh_comm.py healer c2 --duration 86400
        """
    )
    
    parser.add_argument("fuzzer", choices=["countdown", "syzkaller", "actor", "healer", "virtfuzz"],
                        help="Fuzzer to run")
    parser.add_argument("mode", choices=["c1", "c2", "c3"],
                        help="Fuzzing mode (c1, c2, or c3)")
    parser.add_argument("--device", type=str, default=None,
                        help="VirtFuzz device to fuzz (required for virtfuzz). Options: wifi-scan, bluetooth, bluetooth-scan")
    parser.add_argument("--duration", type=int, default=0,
                        help="Maximum fuzzing duration in seconds (0 = unlimited, default). "
                             "The fuzzer will run for this duration then exit gracefully.")
    parser.add_argument("--workdir", type=str, default=None,
                        help="Override the default workdir path (for AWS job isolation)")
    parser.add_argument("--trial", type=int, default=None,
                        help="Trial number for AWS multi-trial isolation. When specified, "
                             "creates unique workdirs (workdir_{mode}_trial{N}) and offsets "
                             "ports by trial*100 to prevent collisions between parallel jobs.")
    parser.add_argument("--seed-corpus", type=str, default=None,
                        help="Seed corpus file (corpus.db) to load instead of the fuzzer's "
                             "minimized corpus; skips the minimization pass.")

    args = parser.parse_args()
    
    # Also check JOB_ID environment variable for trial extraction
    # Format: {fuzzer}_{mode}_trial{N} (e.g., syzkaller_c1_trial2)
    if args.trial is None:
        job_id = os.environ.get("JOB_ID", "")
        if job_id and "_trial" in job_id:
            try:
                trial_str = job_id.split("_trial")[-1]
                args.trial = int(trial_str)
                print(f"[+] Extracted trial={args.trial} from JOB_ID={job_id}")
            except (ValueError, IndexError):
                pass
    
    return args


def run_with_duration(fuzzer_proc, pc_timestamp_proc, relation_proc, config, duration, fuzzer):
    """Run fuzzer with optional duration limit.

    If duration > 0, exits after duration seconds.
    If duration == 0, runs indefinitely until interrupted or fuzzer exits.

    Returns: (exit_code, fuzzer_proc) -- fuzzer_proc may differ from the one
    passed in if it was restarted after an early exit; the caller's own
    cleanup must use the returned proc, not its original one.
    """
    start_time = trial_start_time(config["workdir"]) if duration > 0 else time.time()
    
    def should_exit():
        """Check if we should exit due to duration limit."""
        if duration <= 0:
            return False
        elapsed = time.time() - start_time
        return elapsed >= duration
    
    def remaining_time():
        """Get remaining time in seconds."""
        if duration <= 0:
            return float('inf')
        elapsed = time.time() - start_time
        return max(0, duration - elapsed)
    
    if duration > 0:
        print(f"[+] Duration limit: {duration}s ({duration/3600:.1f} hours)")
    else:
        print(f"[+] Running indefinitely (press Ctrl+C to stop)")
    
    restart_count = 0
    max_restarts = 20

    try:
        while not should_exit():
            # Check if fuzzer is still running
            if fuzzer_proc and fuzzer_proc.poll() is not None:
                if restart_count >= max_restarts:
                    print(f"[-] Fuzzer restarted {restart_count} times already, giving up")
                    return 1, fuzzer_proc
                restart_count += 1
                print(f"[!] Fuzzer process exited early with {remaining_time():.0f}s remaining, "
                      f"restarting ({restart_count}/{max_restarts})")
                kill_process_tree(fuzzer_proc)
                fuzzer_proc = start_fuzzer(fuzzer, config["workdir"], config["run_cmd"], config["vm_boot_time"])
                if not fuzzer_proc:
                    print("[-] Failed to restart fuzzer process, giving up")
                    return 1, fuzzer_proc
                time.sleep(5)
                continue

            # Sleep for a minute or until duration expires
            sleep_time = min(60, remaining_time())
            if sleep_time > 0:
                time.sleep(sleep_time)

        if duration > 0:
            print(f"[+] Duration limit ({duration}s) reached, exiting gracefully")
        return 0, fuzzer_proc

    except KeyboardInterrupt:
        print("[+] User interrupt detected")
        return 0, fuzzer_proc


if __name__ == "__main__":
    args = parse_args()
    
    fuzzer = args.fuzzer
    mode = args.mode
    device = args.device
    duration = args.duration
    workdir_override = args.workdir
    trial = args.trial
    
    if mode not in ["c1", "c2", "c3"]:
        print(f"[-] Invalid mode: {mode}. Must be c1, c2, or c3")
        sys.exit(1)
    
    try:
        config = get_fuzzer_config(fuzzer, mode, device, trial)
    except ValueError as e:
        print(f"[-] {e}")
        sys.exit(1)
    
    if not config:
        print(f"[-] Unknown fuzzer: {fuzzer}")
        print(f"[*] Known fuzzers: countdown, syzkaller, actor, healer, virtfuzz")
        sys.exit(1)
    
    # Override workdir if specified (for AWS job isolation)
    if workdir_override:
        print(f"[+] Using overridden workdir: {workdir_override}")
        config["workdir"] = workdir_override
        # Update related paths that depend on workdir
        if config.get("coverage_file"):
            # Update coverage file path to be in the new workdir
            coverage_basename = os.path.basename(config["coverage_file"])
            config["coverage_file"] = os.path.join(workdir_override, coverage_basename)
    
    # Restarted after its window already closed: exit 0 so systemd does not restart it again.
    started = read_trial_start(config["workdir"])
    if duration > 0 and started is not None and time.time() - started >= duration:
        print(f"[+] Trial started {time.ctime(started)} and its {duration}s window is over, exiting")
        sys.exit(0)

    # Handle trial-specific images: if trial image doesn't exist, copy from base image
    # This prevents I/O contention when running multiple trials on the same machine
    if config.get("trial") and config.get("image"):
        trial_image = config["image"]
        if not os.path.exists(trial_image):
            # Use stored base_image if available (VirtFuzz), otherwise derive from trial suffix
            if config.get("base_image"):
                base_image = config["base_image"]
            else:
                # Derive base image path by removing the trial suffix
                trial_suffix = f"_trial{config['trial']}"
                base_image = trial_image.replace(trial_suffix, "")
            
            if os.path.exists(base_image):
                print(f"[+] Creating trial-specific image: {trial_image}")
                print(f"[+] Copying from base image: {base_image}")
                result = subprocess.run(
                    f"cp --reflink=auto '{base_image}' '{trial_image}'",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    print(f"[-] Failed to copy base image: {result.stderr}")
                    sys.exit(1)
                print(f"[+] Trial image created successfully")
            else:
                print(f"[-] Base image not found: {base_image}")
                sys.exit(1)
    
    # VirtFuzz image is set per-device in get_fuzzer_config, check it there
    if config["image"] and not os.path.exists(config["image"]):
        print(f"[-] Image not found: {config['image']}")
        sys.exit(1)
    
    print(f"[+] Cleaning any other process using the same port")
    if "http_port" in config:
        kill_process_on_port(config["http_port"])
    if "broker_port" in config:
        kill_process_on_port(config["broker_port"])
    time.sleep(2)
    
    os.environ["RUST_BACKTRACE"] = "1"
    
    setup_fuzzer_environment(fuzzer, mode, config)
    
    if not prepare_workdir(fuzzer, mode, config):
        print(f"[-] Workdir preparation failed, exiting")
        sys.exit(4)

    if fuzzer in MINIMIZABLE_FUZZERS:
        # C1/C2/C3 all share one corpus, minimized once under C3 so that
        # C1's unconditional crash doesn't turn raw-corpus replay into a
        # triage storm. See framework/eval/README.md, "Corpus policy".
        if not args.seed_corpus and not ensure_minimized_corpus(fuzzer):
            print(f"[-] Corpus minimization failed, exiting")
            sys.exit(5)
        if not load_minimized_corpus(fuzzer, config, args.seed_corpus):
            print(f"[-] Loading minimized corpus failed, exiting")
            sys.exit(5)
    else:
        if not download_corpus(fuzzer, mode, config):
            print(f"[-] Corpus download failed, exiting")
            sys.exit(5)
    
    pc_timestamp_proc = start_pc_timestamping(fuzzer, mode, config)
    
    # Start countdown-specific relation collector
    relation_proc = None
    if fuzzer == "countdown":
        relation_proc = start_relation_collector(fuzzer, mode, config)

    
    fuzzer_proc = start_fuzzer(
        fuzzer, 
        config["workdir"],
        config["run_cmd"],
        config["vm_boot_time"]
    )
    
    if not fuzzer_proc:
        print(f"[-] Failed to start fuzzer, exiting")
        pc_timestamp_proc.kill()
        sys.exit(6)
    
    # VirtFuzz doesn't need SSH - it fuzzes via VirtIO and logs to files
    if fuzzer == "virtfuzz":
        print(f"[+] VirtFuzz is running - monitoring via logs and coverage")
        print(f"[+] Fuzzer log: {config['workdir']}/fuzzer_output.log")
        print(f"[+] Coverage file: {config['coverage_file']}")
        print(f"[+] Shared directory: {config['workdir']}/shared")
        print(f"[+] Chaos probe reports should appear in shared directory")
        
        try:
            exit_code, fuzzer_proc = run_with_duration(fuzzer_proc, pc_timestamp_proc, relation_proc, config, duration, fuzzer)
        finally:
            print("[+] Cleaning up VirtFuzz processes...")
            if pc_timestamp_proc:
                kill_process_tree(pc_timestamp_proc)
            if fuzzer_proc:
                kill_process_tree(fuzzer_proc)
        
        sys.exit(exit_code)
    
    print(f"[+] Detecting QEMU port...")
    time.sleep(10)
    port = detect_qemu_port(config["workdir"], fuzzer, config.get("image"))
    if not port:
        print(f"[-] Could not detect port, cannot proceed")
        fuzzer_proc.kill()
        pc_timestamp_proc.kill()
        sys.exit(7)
    
    print(f"[+] Using detected port: {port}")
    
    # Duration tracking for SSH-based fuzzers
    start_time = trial_start_time(config["workdir"]) if duration > 0 else time.time()
    
    def should_exit_duration():
        if duration <= 0:
            return False
        return (time.time() - start_time) >= duration
    
    # Keep trying to establish and maintain connection
    reconnect_attempts = 0
    max_reconnect_attempts = 30  # C1 VM reboots observed to take 100-190s; 10x10s was too tight
    giving_up = False  # distinguishes a real failure from a clean duration-reached exit

    # Separate cap for restarting the fuzzer process itself (distinct from SSH
    # reconnect_attempts above, which is for transient connection failures).
    fuzzer_restart_count = 0
    max_fuzzer_restarts = 20

    try:
        while reconnect_attempts < max_reconnect_attempts and not should_exit_duration():
            try:
                # Re-detect port on reconnection attempts (VM may have restarted)
                if reconnect_attempts > 0:
                    print(f"[+] Reconnection attempt {reconnect_attempts}/{max_reconnect_attempts}")
                    time.sleep(10)
                    new_port = detect_qemu_port(config["workdir"], fuzzer, config.get("image"))
                    if new_port:
                        if new_port != port:
                            print(f"[+] Port changed from {port} to {new_port}")
                        port = new_port
                    else:
                        print(f"[-] Could not detect port, using old port {port}")
                
                ssh_sess = build_ssh_session(DEFAULT_HOST, port, DEFAULT_USER, keyfile=config["ssh_key"])
                if not ssh_sess:
                    raise Exception("SSH session could not be established")

                print("[+] Starting continuous monitoring...")
                if duration > 0:
                    remaining = duration - (time.time() - start_time)
                    print(f"[+] Time remaining: {remaining:.0f}s ({remaining/3600:.1f} hours)")
                reconnect_attempts = 0  # Reset on successful connection
                poll_reports_every_n_hours(ssh_sess, REMOTE_PROBE_PATH, fuzzer_proc, DEFAULT_HOST, port, DEFAULT_USER, config["ssh_key"], fuzzer, config["workdir"], config.get("image"), hours=1)

                try:
                    while not should_exit_duration():
                        time.sleep(60)
                        if fuzzer_proc and fuzzer_proc.poll() is not None:
                            print("[!] Fuzzer process has exited, stopping")
                            break

                    if should_exit_duration():
                        print(f"[+] Duration limit ({duration}s) reached, exiting gracefully")
                        break

                    # Fuzzer process died before duration elapsed (e.g. healer treats a
                    # failed VM reboot as fatal and exits, unlike syz-manager's own
                    # infinite crash-retry). Restart it in place instead of letting the
                    # outer loop's SSH-reconnect logic chase a process that no longer
                    # exists -- that's what degenerated into detect_qemu_port's basename
                    # fallback grabbing an unrelated fuzzer's VM (see git history).
                    if fuzzer_restart_count >= max_fuzzer_restarts:
                        print(f"[-] Fuzzer restarted {fuzzer_restart_count} times already, giving up")
                        giving_up = True
                        break
                    fuzzer_restart_count += 1
                    kill_process_tree(fuzzer_proc)
                    print(f"[+] Restarting fuzzer process ({fuzzer_restart_count}/{max_fuzzer_restarts})")
                    fuzzer_proc = start_fuzzer(fuzzer, config["workdir"], config["run_cmd"], config["vm_boot_time"])
                    if not fuzzer_proc:
                        raise Exception("Failed to restart fuzzer process")
                    new_port = detect_qemu_port(config["workdir"], fuzzer, config.get("image"))
                    if new_port:
                        port = new_port
                    time.sleep(5)
                    continue

                except KeyboardInterrupt:
                    print("[+] Exiting on user interrupt")
                    raise  # Re-raise to exit outer loop
                            
            except KeyboardInterrupt:
                # User pressed Ctrl+C - exit gracefully
                print("[+] User interrupt detected, exiting...")
                raise  # Re-raise to trigger cleanup
                
            except Exception as e: 
                reconnect_attempts += 1
                print(f"[-] Fatal error in main loop: {e}")
                if reconnect_attempts >= max_reconnect_attempts:
                    print(f"[-] Max reconnection attempts ({max_reconnect_attempts}) reached, giving up")
                    giving_up = True
                    break
                print(f"[-] Will retry connection in 20 seconds (Ctrl+C to abort)...")
                try:
                    time.sleep(20)
                except KeyboardInterrupt:
                    print("[+] User interrupt during retry wait, exiting...")
                    raise  # Exit immediately on Ctrl+C during sleep
                    
    except KeyboardInterrupt:
        print("[+] Cleaning up after user interrupt...")
    finally:
        # Always cleanup, regardless of how we exit
        print("[+] Cleaning up fuzzer processes...")
        if relation_proc:
            kill_process_tree(relation_proc)
        if pc_timestamp_proc:
            kill_process_tree(pc_timestamp_proc)
        if fuzzer_proc:
            kill_process_tree(fuzzer_proc)

    sys.exit(1) if giving_up else sys.exit(0)
