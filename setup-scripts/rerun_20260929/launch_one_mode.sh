#!/usr/bin/env bash
set -euo pipefail
mode=${1:?mode}; trial=${2:?trial}; device=${3:?device}; cores=${4:?cores}; duration=${5:?duration}
seeds=${VIRTFUZZ_INITIAL_INPUTS:-/evaldisk/chaos_eval/VirtFuzz/seeds_80211_final}
vf=/evaldisk/chaos_eval/VirtFuzz
runroot=$vf/rerun_20260929
dsan=${device//-/_}
image=$vf/guestimage/stretch_${mode}_${dsan}_trial${trial}.img
workdir=$vf/workdir_${mode}_${dsan}_trial${trial}
corpus=$runroot/corpus_${mode}_trial${trial}
unit=virtfuzz-seeded-${device}-${mode}-trial${trial}
case "$mode" in c2) baseport=16000;; c3) baseport=20000;; esac
case "$device" in bluetooth) doff=10;; bluetooth-scan) doff=20;; *) doff=0;; esac
port=$((baseport + doff + trial * 100))
[[ -f "$image" && -d "$corpus" && ! -e "$workdir" ]] || { echo "preflight failed ($image/$corpus/$workdir)" >&2; exit 3; }
[[ -z "$(find "$corpus" -mindepth 1 -maxdepth 1 -print -quit)" ]] || { echo "corpus not empty" >&2; exit 3; }
[[ -d "$seeds" ]] || { echo "seeds missing $seeds" >&2; exit 3; }
[[ -z "$(ss -H -ltn "sport = :$port")" ]] || { echo "port $port busy" >&2; exit 3; }
systemd-run --user --unit="$unit" \
    --property=Restart=on-failure --property=RestartSec=30 \
    --property=MemoryHigh=20G --property=MemoryMax=24G \
    --property=RuntimeMaxSec="$((duration + 3600))" \
    --setenv=CHAOS_BASE=/evaldisk/chaos_eval --setenv=TMPDIR=/evaldisk/chaos_eval/tmp \
    --setenv=VIRTFUZZ_CORPUS_DIR="$corpus" --setenv=VIRTFUZZ_CORES="$cores" \
    --setenv=VIRTFUZZ_INITIAL_INPUTS="$seeds" \
    /evaldisk/chaos_eval/venv/bin/python3 \
    /home/ritvik/virtfuzz_rerun_20260929/ssh_comm_seeded.py \
    virtfuzz "$mode" --trial "$trial" --device "$device" --duration "$duration"
printf 'launched %s port=%s cores=%s seeds=%s\n' "$unit" "$port" "$cores" "$seeds"
