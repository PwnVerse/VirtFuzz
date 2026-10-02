#!/usr/bin/env bash
set -euo pipefail

mode=${1:?mode required}
trial=${2:?trial required}
case "$mode" in c2|c3) ;; *) echo "unsupported mode: $mode" >&2; exit 2;; esac
[[ "$trial" =~ ^[0-9]+$ ]] || { echo "trial must be numeric" >&2; exit 2; }

vf=/evaldisk/chaos_eval/VirtFuzz
runroot=$vf/rerun_20260929
base=$vf/guestimage/stretch_${mode}.img
image=$vf/guestimage/stretch_${mode}_wifi_scan_trial${trial}.img
workdir=$vf/workdir_${mode}_wifi_scan_trial${trial}
corpus=$runroot/corpus_${mode}_trial${trial}

[[ -f "$base" && ! -e "$image" && ! -e "$workdir" && ! -e "$corpus" ]] || {
    echo "refusing existing/missing base, image, workdir or corpus" >&2
    exit 3
}

mkdir -p "$runroot"
cp --sparse=always --reflink=auto "$base" "$image"
debugfs -w -R \
  'symlink /etc/systemd/system/multi-user.target.wants/permanent-scan.service ../permanent-scan.service' \
  "$image"
debugfs -R 'stat /etc/systemd/system/multi-user.target.wants/permanent-scan.service' "$image" 2>&1 \
  | grep -F 'Fast link dest: "../permanent-scan.service"' >/dev/null
debugfs -R 'cat /etc/debian_version' "$image" 2>/dev/null | grep -Fx '9.13' >/dev/null
debugfs -R 'cat /etc/init.d/chaos_probe' "$image" 2>/dev/null \
  | grep -F -- "--mode=$mode" >/dev/null
debugfs -R 'cat /etc/init.d/chaos_probe' "$image" 2>/dev/null \
  | grep -F 'STABILIZE=0' >/dev/null
mkdir "$corpus"
printf 'prepared image=%s corpus=%s\n' "$image" "$corpus"
