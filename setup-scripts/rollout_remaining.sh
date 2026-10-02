#!/usr/bin/env bash
# Restart running VirtFuzz trials WITHOUT resetting their 72h window.
#
# The wrapper (ssh_comm_seeded.py) derives the deadline from <workdir>/.trial_start,
# which survives restarts, so a relaunched trial runs only the remaining hours.
# Transient systemd units are garbage-collected on stop, so each trial is
# stopped, its image optionally patched, and relaunched with systemd-run using
# the same unit name, properties, environment and ExecStart.
#
# Image patch: for wifi-ibss / wifi-ap / wifi-syzkaller the ready-marker unit is
# refreshed from setup-scripts/ready-marker.service (After=<real unit>), so the
# marker really fires last (needed for binaries <= 3a09977; c3afc37 derives the
# per-device line itself).
#
# Usage: rollout_remaining.sh [unit ...]      # default: all virtfuzz-seeded-* units
#        VF=... WRAP=... PY=... MARKER=... rollout_remaining.sh
set -u
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
here=$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)
VF=${VF:-/evaldisk/chaos_eval/VirtFuzz}
WRAP=${WRAP:-/home/ritvik/virtfuzz_rerun_20260929/ssh_comm_seeded.py}
PY=${PY:-/evaldisk/chaos_eval/venv/bin/python3}
MARKER=${MARKER:-$here/ready-marker.service}
LOG=${LOG:-/workdisk/ritvik/scratch_virtfuzz/rollout_$(date +%Y%m%d_%H%M%S).log}
exec > >(tee -a "$LOG") 2>&1
echo "rollout start $(date -Is) log=$LOG"

if [ "$#" -gt 0 ]; then
    BASES=""
    for u in "$@"; do BASES="$BASES ${u%.service}"; done
else
    BASES=$(systemctl --user list-units --all --plain --no-legend 'virtfuzz-seeded-*' 2>/dev/null \
        | awk '{print $1}' | sed 's/\.service$//')
fi

for base in $BASES; do
    u="$base.service"
    n="${base#virtfuzz-seeded-}"
    tr="${n##*-trial}"
    pol="${n%-trial*}"; pol="${pol##*-}"
    dev="${n%-${pol}-trial${tr}}"
    ds="${dev//-/_}"
    img="$VF/guestimage/stretch_${pol}_${ds}_trial${tr}.img"
    wd="$VF/workdir_${pol}_${ds}_trial${tr}"

    env=$(systemctl --user show -p Environment --value "$u" 2>/dev/null)
    cores=""; corpus=""; seeds=""
    for kv in $env; do
        case "$kv" in
            VIRTFUZZ_CORES=*) cores="${kv#*=}" ;;
            VIRTFUZZ_CORPUS_DIR=*) corpus="${kv#*=}" ;;
            VIRTFUZZ_INITIAL_INPUTS=*) seeds="${kv#*=}" ;;
        esac
    done

    if [ ! -f "$wd/.trial_start" ] || [ ! -d "$corpus" ] || [ -z "$cores" ]; then
        echo "SKIP $u (preflight: ts=$([ -f "$wd/.trial_start" ] && echo y || echo n) corpus=$corpus cores=$cores)"
        continue
    fi

    echo "--- $u dev=$dev cores=$cores seeds=$seeds"
    systemctl --user stop "$u" || { echo "STOP FAILED $u"; continue; }
    echo "    stopped"

    case "$dev" in
        wifi-ibss|wifi-ap|wifi-syzkaller)
            debugfs -w -R 'rm /etc/systemd/system/ready-marker.service' "$img" >/dev/null 2>&1
            debugfs -w -R "write $MARKER /etc/systemd/system/ready-marker.service" "$img" >/dev/null 2>&1
            got=$(debugfs -R 'cat /etc/systemd/system/ready-marker.service' "$img" 2>/dev/null | grep -c '^After=')
            echo "    image patched (After lines=$got, img=$(basename "$img"))"
            ;;
        *) echo "    no image patch for $dev" ;;
    esac

    ts=$(cat "$wd/.trial_start")
    rem=$(( ts + 259200 - $(date +%s) + 3600 ))
    systemd-run --user --unit="$base" \
        --property=Restart=on-failure --property=RestartSec=30 \
        --property=MemoryHigh=20G --property=MemoryMax=24G --property=RuntimeMaxSec="$rem" \
        --setenv=CHAOS_BASE=/evaldisk/chaos_eval --setenv=TMPDIR=/evaldisk/chaos_eval/tmp \
        --setenv=VIRTFUZZ_CORPUS_DIR="$corpus" --setenv=VIRTFUZZ_CORES="$cores" \
        --setenv=VIRTFUZZ_INITIAL_INPUTS="$seeds" \
        "$PY" "$WRAP" virtfuzz "$pol" --trial "$tr" --device "$dev" --duration 259200 \
        || { echo "RELAUNCH FAILED $u"; continue; }
    sleep 3
    act=$(systemctl --user show -p ActiveState --value "$u" 2>/dev/null)
    ts2=$(cat "$wd/.trial_start")
    echo "    relaunched state=$act ts_before=$ts ts_after=$ts2 remaining=$((${rem}-3600))s"
    [ "$ts" = "$ts2" ] || echo "    WARNING: .trial_start changed!"
done
echo "rollout done $(date -Is)"
echo "active units: $(systemctl --user list-units --plain --no-legend 'virtfuzz-seeded-*' 2>/dev/null | grep -c running)"
