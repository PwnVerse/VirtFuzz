#!/usr/bin/env bash
set -euo pipefail
dir=/home/ritvik/virtfuzz_rerun_20260929
vf=/evaldisk/chaos_eval/VirtFuzz
duration=259200
unset VIRTFUZZ_DEBUG_SSH_PORT

for spec in 'c2 85 30,31,94,95' 'c2 86 32,33,96,97' 'c3 85 34,35,98,99' 'c3 86 36,37,100,101'; do
    read -r mode trial cores <<< "$spec"
    image=$vf/guestimage/stretch_${mode}_wifi_scan_trial${trial}.img
    workdir=$vf/workdir_${mode}_wifi_scan_trial${trial}
    corpus=$vf/rerun_20260929/corpus_${mode}_trial${trial}
    [[ -f "$image" && ! -e "$workdir" && -d "$corpus" ]] || {
        echo "preflight failed for $mode trial$trial" >&2; exit 3;
    }
    [[ -z "$(find "$corpus" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
        echo "nonempty corpus for $mode trial$trial" >&2; exit 3;
    }
done

"$dir/launch_one.sh" c2 85 30,31,94,95 "$duration"
"$dir/launch_one.sh" c2 86 32,33,96,97 "$duration"
"$dir/launch_one.sh" c3 85 34,35,98,99 "$duration"
"$dir/launch_one.sh" c3 86 36,37,100,101 "$duration"
