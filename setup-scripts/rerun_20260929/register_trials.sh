#!/usr/bin/env bash
set -euo pipefail
reg=/evaldisk/chaos_eval/trial_registry.tsv

append_once() {
    local mode=$1 trial=$2 status=$3 note=$4
    if awk -F '\t' -v m="$mode" -v t="$trial" \
        '$1=="virtfuzz" && $2==m && $3==t {found=1} END {exit !found}' "$reg"; then
        echo "already registered: $mode trial$trial"
        return
    fi
    printf 'virtfuzz\t%s\t%s\t%s\t%s\n' "$mode" "$trial" "$status" "$note" >> "$reg"
}

for mode in c2 c3; do
    append_once "$mode" 81 discarded '2026-09-29 setup start; two logical CPUs, stopped for SMT correction'
    append_once "$mode" 82 discarded '2026-09-29 setup start; two logical CPUs, stopped for SMT correction'
    append_once "$mode" 83 running '2026-09-29 24h unseeded rerun, four logical CPUs, fresh corpus'
    append_once "$mode" 84 running '2026-09-29 24h unseeded rerun, four logical CPUs, fresh corpus'
    append_once "$mode" 90 legacy '2026-09-29 10m smoke, outside campaign numbering'
    append_once "$mode" 92 legacy '2026-09-29 scan diagnostic, outside campaign numbering'
done
append_once c3 91 legacy '2026-09-29 failed SSH diagnostic; patched QEMU has no user-net backend'

printf 'next c2=%s c3=%s\n' \
  "$(/evaldisk/chaos_eval/next_trial.sh virtfuzz c2)" \
  "$(/evaldisk/chaos_eval/next_trial.sh virtfuzz c3)"
