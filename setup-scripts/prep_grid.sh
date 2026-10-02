#!/bin/bash
# Prepare the per-trial guest images for the ChaosKernel VirtFuzz grid.
#
# For each trial it copies the policy base image (stretch_<mode>.img) and
# enables exactly one device setup unit, plus:
#   - ready-marker.service for ibss/ap/syzkaller images. That unit carries the
#     same Description as permanent-scan.service ("Permanently scan for WiFi")
#     and is ordered After the real device unit, so its "Started ..." line is
#     the last boot-unit line for binaries that wait for the hardcoded
#     wifi-scan marker (see setup-scripts/README.md, "Readiness model").
#   - hostapd.service for ap images (custom unit; the stock Debian unit is
#     disabled in the base image by guestimage/create-image.sh).
# wifi-scan images get the real permanent-scan.service symlink only;
# bluetooth/bluetooth-scan need no unit (readiness is frame-RX based).
#
# Usage: prep_grid.sh            # uses SPECS below
#        VF=... RUNROOT=... prep_grid.sh
#
# Existing images are skipped, so this is safe to re-run and to extend.
set -u
here=$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)
vf=${VF:-/evaldisk/chaos_eval/VirtFuzz}
runroot=${RUNROOT:-$vf/rerun_20260929}
ready=$here/ready-marker.service
hostapd=$here/hostapd.service

prep() {
    local mode=$1 trial=$2 dev=$3 kind=$4
    local img=$vf/guestimage/stretch_${mode}_${dev}_trial${trial}.img
    if [ -e "$img" ]; then
        echo "SKIP existing $img"
        return 0
    fi
    cp --sparse=always --reflink=auto $vf/guestimage/stretch_${mode}.img "$img" || return 1
    case $kind in
        scan)
            debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/permanent-scan.service ../permanent-scan.service' "$img" >/dev/null 2>&1 ;;
        ibss)
            debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/ibss.service ../ibss.service' "$img" >/dev/null 2>&1 ;;
        ap)
            debugfs -w -R "write $hostapd /etc/systemd/system/hostapd.service" "$img" >/dev/null 2>&1
            debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/hostapd.service ../hostapd.service' "$img" >/dev/null 2>&1 ;;
        syzkaller)
            debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/setup-syzkaller.service ../setup-syzkaller.service' "$img" >/dev/null 2>&1 ;;
    esac
    if [ "$kind" != scan ]; then
        debugfs -w -R "write $ready /etc/systemd/system/ready-marker.service" "$img" >/dev/null 2>&1
        debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/ready-marker.service ../ready-marker.service' "$img" >/dev/null 2>&1
    fi
    mkdir -p "$runroot/corpus_${mode}_trial${trial}"
    echo "prepared $img ($kind)"
}

while read -r mode trial dev kind; do
    prep "$mode" "$trial" "$dev" "$kind"
done <<'SPECS'
c2 103 wifi_scan scan
c2 104 wifi_scan scan
c2 105 wifi_scan scan
c3 103 wifi_scan scan
c3 104 wifi_scan scan
c3 108 wifi_scan scan
c2 106 wifi_ibss ibss
c2 107 wifi_ibss ibss
c2 108 wifi_ibss ibss
c3 109 wifi_ibss ibss
c3 110 wifi_ibss ibss
c3 111 wifi_ibss ibss
c2 109 wifi_ap ap
c2 110 wifi_ap ap
c2 111 wifi_ap ap
c3 112 wifi_ap ap
c3 113 wifi_ap ap
c3 114 wifi_ap ap
c2 112 wifi_syzkaller syzkaller
c2 113 wifi_syzkaller syzkaller
c2 114 wifi_syzkaller syzkaller
c3 115 wifi_syzkaller syzkaller
c3 116 wifi_syzkaller syzkaller
c3 117 wifi_syzkaller syzkaller
SPECS
