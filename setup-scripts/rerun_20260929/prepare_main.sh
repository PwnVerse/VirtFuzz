#!/usr/bin/env bash
set -euo pipefail
dir=/home/ritvik/virtfuzz_rerun_20260929

for mode in c2 c3; do
    for trial in 85 86; do
        "$dir/prepare_image.sh" "$mode" "$trial"
    done
done
