# setup-scripts — ChaosKernel local additions

This directory holds the local (ChaosKernel) build/ops helpers for this fork.
It is **not** part of the upstream seemoo-lab artifact; `setup-qemu.sh` is the
upstream QEMU build recipe, the other files are ours.

Base: `seemoo-lab/VirtFuzz @ 6b76b12` (artifact)
Fork: `PwnVerse/VirtFuzz main` (this tree; campaign branch)

## Local changes vs the upstream artifact

Kernel-side (built from `linux/` with `make_clang.sh`, see below):

* CVE/BUGFIX injection + `chaos_probe` instrumentation, `log_cve`/`MODE_C3`
  printk serialization (ChaosKernel; required for the campaign).
* Both device annotations are compiled into one image:
  `kernel-patches/apply.sh` + `annotate-80211.sh` + `annotate-bluetooth.sh`
  (upstream README applies only the target's annotate script).
* `make_clang.sh` additionally enables `CONFIG_STAGING`, `CONFIG_IVSHMEM`,
  `CONFIG_BT_VIRTIO`, KCOV/KASAN and the per-CVE configs, then
  `git restore .config` at the end — the tracked `.config` is the restore,
  the build config is the `.config.old` left over by `olddefconfig`.

Fuzzer-side (`src/qemu`, `fuzz/src`):

* `d69823e` absorb boot-tail timeouts (`max_tolerated_timeouts` 0→3, 5 s settle).
* `75fee85` wait for the last boot-unit dmesg line instead of a fixed 5 s sleep.
* `3a09977` reset the VM if it is not ready within 180 s.
* `c3afc37` derive the readiness marker per device from its `systemd.wants=`
  kernel parameter (`DeviceConfiguration::ready_marker()`), and track banner
  and marker independently so boot-log order does not matter.
* `b97ec0d` `--coverage-output` (per-trial coverage file; concurrent instances
  used to share one `<kernel>.coverage`).
* `d3e1b05` 4 vCPU / 4 GB per VM (upstream 1/2), `loglevel=5` (upstream 8),
  `--enable-ramoops`, `--shared-dir`, `--qemu-args`; `bluetooth.json` config
  `000000FF` → `000000FF00`.

Guest/images:

* `chaos_probe` + `ready-marker.service` infrastructure; per-trial image copies
  with exactly one device setup unit enabled (see below).

## Readiness model (why this matters)

Before the fuzzer sends inputs it waits for **both**:
1. the login banner (`Debian GNU/Linux`), then
2. the device's boot-completion line.

`75fee85` hardcoded line 2 to `"Started Permanently scan for WiFi"` — the
`permanent-scan.service` line, i.e. wifi-scan only. Other modes were made to
pass by installing `ready-marker.service` (same `Description`) via symlink, but
it was not ordered after the real setup unit, so readiness could fire **before**
IBSS join / hostapd / syzkaller setup had finished; and the `3a09977` 180 s cap
then reset VMs that were still legitimately booting (seen as
`Error while waiting for VM: NotReady`).

Fix (both sides, harmless together):

* **Images**: `ready-marker.service` now carries
  `After=ibss.service hostapd.service setup-syzkaller.service`, so its line is
  genuinely the last one. Required for binaries ≤ `3a09977`.
* **Binary** (`c3afc37`): the line is derived from the device's command line,
  so future builds no longer depend on the marker unit at all.

Per-device completion lines:

| device          | unit pulled by `systemd.wants=` | completion line |
|-----------------|---------------------------------|-----------------|
| wifi-scan       | permanent-scan.service          | `Started Permanently scan for WiFi` |
| wifi-ibss       | ibss.service                    | `Started Activate IBSS` |
| wifi-ap         | hostapd.service                 | `Started Hostapd IEEE 802.11 AP` |
| wifi-syzkaller  | setup-syzkaller.service         | `SYZKALLER SETUP FINISHED` |
| bluetooth(-scan)| (none)                          | first RX frame (`--wait-for-rx`) |

## Integrating into future trials

1. **VirtFuzz binary**: `cargo build --release -p virtfuzz-fuzz` on `main`
   (must include `c3afc37`; check `md5sum target/release/virtfuzz-fuzz`).
   Rebuilding while trials run changes the on-disk binary — running brokers keep
   the deleted inode, but any restart picks up the new build. Rebuild only
   between waves, or restart all trials together afterwards.
2. **Kernel**: `cd linux && ./make_clang.sh clang fuzz`. For a fresh tree apply
   the patches by hand (upstream `apply.sh` is only a helper; this tree's
   patches are already applied): `kernel-patches/apply.sh`,
   `annotate-80211.sh`, `annotate-bluetooth.sh`. Verify symbols exist:
   `grep -E "virtbt_probe|hwsim_virtio_probe|kcov_ivshmem" linux/System.map`.
3. **QEMU**: `setup-scripts/setup-qemu.sh` (8.2.2 + `qemu-patch.patch`;
   verify the binary exposes `virtio-general-pci`).
4. **Images**: `setup-scripts/prep_grid.sh` (edit `SPECS` for the new grid).
   For every non-scan wifi image it installs `ready-marker.service` from this
   directory; for ap images it also installs `hostapd.service`. Base images are
   `guestimage/stretch_<c2|c3>.img` (Debian 9.13 + `chaos_probe`, probe mode and
   `STABILIZE=0` are set per policy by the image build).
5. **Launch**: per trial, `systemd-run --user --unit=virtfuzz-seeded-<dev>-<pol>-trial<N>`
   with `VIRTFUZZ_CORPUS_DIR`, `VIRTFUZZ_CORES`, `VIRTFUZZ_INITIAL_INPUTS`
   (see the campaign launcher), wrapper
   `ssh_comm_seeded.py virtfuzz <pol> --trial <N> --device <dev> --duration 259200`.
   The wrapper records `<workdir>/.trial_start` and always runs only the
   remaining time, so restarts never reset the 72 h window.
6. **Restart / patch images without losing time**: `setup-scripts/rollout_remaining.sh`
   (optionally with unit names). It stops each unit (transient units are
   garbage-collected — they cannot be `start`ed again), patches the
   ready-marker, and recreates the unit with `systemd-run`, preserving
   `.trial_start`.
7. **Verify after any (re)launch**:
   * unit `active`, `.trial_start` unchanged, expected remaining hours;
   * image has Debian `9.13`, probe mode + `STABILIZE=0`, the correct
     `multi-user.target.wants/<unit>` symlink, and `ready-marker.service`
     with the `After=` line for non-scan wifi;
   * no repeated `Error while waiting for VM: NotReady` in `fuzzer_output.log`;
   * heartbeats (`(GLOBAL) run time`) resume and executions grow.

## Campaign launcher (reference copy)

`rerun_20260929/` mirrors the launcher used for the seeded 72 h grid, so future
waves do not depend on `/home/ritvik/virtfuzz_rerun_20260929` alone:

* `ssh_comm_seeded.py` — wrapper used by all running trials. It derives each
  trial's deadline from `<workdir>/.trial_start` (restarts run only the
  remaining time), keeps `pc_first_seen.json`/coverage/corpus across restarts,
  and on restart imports the trial's non-hidden corpus inputs via
  `--initial-inputs`.
* `ssh_comm_rerun.py` — unseeded predecessor used by `launch_one.sh`.
* `launch_one_mode.sh <mode> <trial> <device> <cores> <duration>` — per-trial
  `systemd-run` launcher for all devices; `launch_one_seeded.sh` is the older
  wifi-scan-only variant.
* `prepare_image.sh <mode> <trial>` / `prepare_main.sh` — per-trial image +
  corpus creation (scan variant; use `prep_grid.sh` for the 4-device grid).
* `launch_main.sh`, `register_trials.sh` — wave launcher and registry update.
* `RUNBOOK.md` — the 2026-09-29 audit: paper-vs-local differences, CPU-lane and
  port allocation, launch/validation gates.

Paths inside the scripts default to `/evaldisk/chaos_eval/VirtFuzz` and
`/home/ritvik/virtfuzz_rerun_20260929`; `launch_one_mode.sh` reads
`VIRTFUZZ_INITIAL_INPUTS`, and `rollout_remaining.sh` (above) accepts `VF`,
`WRAP`, `PY`, `MARKER` overrides.

## Reproduce one trial per VirtFuzz mode

All commands run from the repo root; `VF=/evaldisk/chaos_eval/VirtFuzz`.

Prerequisites (once):
```
cargo build --release -p virtfuzz-fuzz            # fuzzer binary
(cd linux && ./make_clang.sh clang fuzz)          # annotated kernel, KCOV/KASAN
setup-scripts/setup-qemu.sh                       # patched QEMU 8.2.2
```
Base images `guestimage/stretch_c2.img` / `stretch_c3.img` must be probe-injected
(Debian 9.13; `/etc/init.d/chaos_probe` carrying `--mode=c2|c3` and
`STABILIZE=0`; `chaos_probe.service` enabled). `prepare_image.sh` asserts all of
this; the injector is `/evaldisk/chaos_eval/setup_chaos_probe.sh` together with
`chaos_probe` + `chaos_probe.sh`.

| mode | device definition | device flags | image unit | completion line | seeds |
|---|---|---|---|---|---|
| wifi-scan | hwsim-scan.json | `--use-hwsim-input` | permanent-scan.service | `Started Permanently scan for WiFi` | seeds_80211_final |
| wifi-ibss | hwsim-ibss.json | `--use-hwsim-input` | ibss.service | `Started Activate IBSS` | seeds_80211_final |
| wifi-ap | hwsim-ap.json | `--use-hwsim-input` | hostapd.service | `Started Hostapd IEEE 802.11 AP` | seeds_80211_final |
| wifi-syzkaller | hwsim-syzkaller.json | `--use-hwsim-input` | setup-syzkaller.service | `SYZKALLER SETUP FINISHED` | seeds_80211_final_syzkaller |
| bluetooth-scan | bluetooth.json | `--bt-fake-cc --wait-for-rx --init-path resources/setup.pcap` | none (RX readiness) | first HWSIM RX frame | seeds_bt_empty |

Image prep for policy `<pol>` (c2/c3), trial `<N>`, device `<dev>`; broker port
is `16000+<N>*100` (c2) or `20000+<N>*100` (c3), plus 20 for bluetooth-scan:
```
IMG=guestimage/stretch_<pol>_<dev>_trial<N>.img
cp --sparse=always --reflink=auto guestimage/stretch_<pol>.img "$IMG"
# enable the mode's unit, e.g. wifi-ibss:
debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/ibss.service ../ibss.service' "$IMG"
# non-scan wifi modes also get the ready-marker (skip for wifi-scan/bluetooth):
debugfs -w -R "write setup-scripts/ready-marker.service /etc/systemd/system/ready-marker.service" "$IMG"
debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/ready-marker.service ../ready-marker.service' "$IMG"
# wifi-ap additionally installs setup-scripts/hostapd.service as hostapd.service
mkdir -p rerun_20260929/corpus_<pol>_trial<N>
```
(`setup-scripts/prep_grid.sh` does all of this for a whole grid; edit `SPECS`.)

Launch (4 exclusive logical CPUs = 2 physical cores incl. SMT siblings):
```
VIRTFUZZ_INITIAL_INPUTS=$VF/<seeds from table> \
  setup-scripts/rerun_20260929/launch_one_mode.sh <pol> <N> <device> <cpus> 259200
```
This creates `virtfuzz-seeded-<device>-<pol>-trial<N>.service` with
`Restart=on-failure`, memory caps and `RuntimeMaxSec=duration+1h`, and records
`workdir_<pol>_<dev>_trial<N>/.trial_start` used for remaining-time restarts.

Verify after launch/restart:
* unit active, `.trial_start` unchanged, expected remaining time;
* guest cmdline has `mac80211_hwsim.radios=*` and `systemd.wants=<image unit>`
  (from the device JSON `command_line_params`);
* in `fuzzer_output.log`, each boot reaches the completion line before fuzzing
  and does not repeat `Error while waiting for VM: NotReady`;
* heartbeats (`(GLOBAL) run time`) and executions grow.

## Notes / gotchas

* Console `[ OK ]` lines in `fuzzer_output.log` can be dropped under load; do
  not use their absence as proof a unit did not start. Judge readiness by the
  heartbeats and `NotReady` counter.
* Same-execution evidence rules of the campaign still apply; restarting a trial
  starts a new fuzzer epoch (heartbeat coverage resets, `pc_first_seen.json`
  and the corpus persist).
* `resources/setup.pcap` and `--wait-for-rx --bt-fake-cc` are the artifact's
  Bluetooth quirks; bluetooth readiness intentionally does not use a marker.
