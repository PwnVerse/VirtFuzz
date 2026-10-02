#!/usr/bin/env bash
set -euo pipefail

mode=${1:?mode required}
trial=${2:?trial required}
cores=${3:?CPU list required}
duration=${4:?duration required}
case "$mode" in c2|c3) ;; *) echo "unsupported mode: $mode" >&2; exit 2;; esac
[[ "$trial" =~ ^[0-9]+$ && "$duration" =~ ^[0-9]+$ ]] || exit 2
[[ "$cores" =~ ^[0-9]+(,[0-9]+){0,3}$ ]] || { echo "one to four CPU ids required" >&2; exit 2; }

vf=/evaldisk/chaos_eval/VirtFuzz
runroot=$vf/rerun_20260929
seeds=${VIRTFUZZ_INITIAL_INPUTS:-$vf/seeds_80211_enriched}
image=$vf/guestimage/stretch_${mode}_wifi_scan_trial${trial}.img
workdir=$vf/workdir_${mode}_wifi_scan_trial${trial}
corpus=$runroot/corpus_${mode}_trial${trial}
unit=virtfuzz-seeded-${mode}-trial${trial}
case "$mode" in c2) baseport=16000;; c3) baseport=22000;; esac
port=$((baseport + trial * 100))

[[ -f "$image" && -d "$corpus" && ! -e "$workdir" ]] || {
    echo "image/corpus missing or workdir exists" >&2; exit 3;
}
[[ -z "$(find "$corpus" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "corpus is not empty" >&2; exit 3;
}
[[ -d "$seeds" && -n "$(find "$seeds" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "seed dir missing or empty: $seeds" >&2; exit 3;
}
[[ -z "$(ss -H -ltn "sport = :$port")" ]] || {
    echo "port $port is occupied" >&2; exit 3;
}
if systemctl --user is-active --quiet "$unit.service"; then
    echo "unit $unit already active" >&2; exit 3;
fi

systemd-run --user --unit="$unit" \
    --property=Restart=on-failure --property=RestartSec=30 \
    --property=MemoryHigh=20G --property=MemoryMax=24G \
    --property=RuntimeMaxSec="$((duration + 3600))" \
    --setenv=CHAOS_BASE=/evaldisk/chaos_eval \
    --setenv=TMPDIR=/evaldisk/chaos_eval/tmp \
    --setenv=VIRTFUZZ_CORPUS_DIR="$corpus" \
    --setenv=VIRTFUZZ_CORES="$cores" \
    --setenv=VIRTFUZZ_INITIAL_INPUTS="$seeds" \
    ${VIRTFUZZ_DEBUG_SSH_PORT:+--setenv=VIRTFUZZ_DEBUG_SSH_PORT=$VIRTFUZZ_DEBUG_SSH_PORT} \
    /evaldisk/chaos_eval/venv/bin/python3 \
    /home/ritvik/virtfuzz_rerun_20260929/ssh_comm_seeded.py \
    virtfuzz "$mode" --trial "$trial" --device wifi-scan --duration "$duration"

printf 'launched unit=%s port=%s cores=%s corpus=%s seeds=%s\n' "$unit" "$port" "$cores" "$corpus" "$seeds"
