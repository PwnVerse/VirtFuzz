# VirtFuzz C2/C3 rerun audit (2026-09-29)

## What the paper actually did

- The controlled WLAN evaluation used a Linux 5.19 target, KASAN only, and a
  Debian Stretch guest shared with Syzkaller. It ran VirtFuzz with and without
  prerecorded seeds for 24 hours, three repetitions of each condition.
- WLAN seeds were recorded with VirtFuzz's physical-device proxy using an
  Intel Wireless-AC 9260 in a Thinkpad T495. The authors scanned nearby
  networks, attempted connections, and operated a VM access point.
- The paper's scan service is the `permanent-scan.service` in this artifact.
  It says services are selected by the kernel command line.
- Sources: [paper](https://uni-goettingen.de/de/document/download/6b0d1e9d8e2fb7f57cc1a2fab1b071e7.pdf/huster_S%26P24.pdf),
  [artifact](https://github.com/seemoo-lab/VirtFuzz).

## Local findings and corrections

1. The prior summary's claim that the paper used Bullseye was wrong. The paper
   and README both say Stretch. The image script's default `RELEASE=bullseye`
   does not describe the explicit `-d stretch` used in the README.
2. The published Git tree has proxy recording code and a Bluetooth setup PCAP,
   but no WLAN seed directory. The local checkout and evaluation tree likewise
   contain no identified prerecorded WLAN seeds. The host exposes no WLAN NIC.
   Therefore the paper's **seeded** arm cannot be reproduced exactly here.
3. `ssh_comm.py` passes `--corpus VirtFuzz/corpus_shared` but never passes
   `--initial-inputs`. In `fuzz/src/main.rs`, files are imported only through
   `--initial-inputs`; otherwise `generate_initial_inputs` starts from random
   inputs. The 1,070,556 files currently in `corpus_shared` do not prove that
   any preceding trial was seeded from them. The log's initial corpus count of
   zero is consistent with that source path.
4. Both live C2/C3 base images are Debian 9.13 with systemd 232. They contain
   the scan service, `ip`, and `iw`, but no enabling symlink in
   `multi-user.target.wants`. The JSON uses `systemd.wants=...`; the earlier
   trials show no scan-service activation. The rerun must use a private image
   with the service enabled, then verify its runtime activity.
5. The active seeded Syzkaller/Countdown campaign currently owns CPU lanes in
   42-63 plus SMT siblings. The previous static VirtFuzz map overlaps these
   lanes. Use exclusive physical cores 30-37 **and their SMT siblings** for the
   four reruns. The active syscall trials also use four logical CPUs spanning
   two physical cores. The standard launcher is different: Syzkaller,
   Countdown, Actor, and Healer C3 use four logical CPUs on four physical
   cores (one SMT thread each), while Healer C1/C2 use two physical cores
   with both SMT threads. Therefore the new allocation matches the *active*
   reruns and historical VirtFuzz, not every earlier comparison trial.
   Smoke tests used 28-29 and 38-41.
6. C2's incidental probe reports include boot-path events; C3's prior scan VM
   sometimes rebooted before the heartbeat. Neither a boot report nor the
   absence of one is evidence of an input-triggered WiFi finding. Keep
   boot-context reports separate and require first-execution timing.
7. `ssh_comm.py` creates `.trial_start` after `start_fuzzer` has already waited
   100 seconds for boot. Early coverage samples may predate this file by tens
   of seconds. Do not use it as the host launch time or as proof that a report
   preceded the first fuzzer execution.

## Run definition

- Two independent **unseeded** 72-hour trials in each of C2 and C3: trial IDs
  85 and 86, four trials total. This matches the current campaign duration.
  The paper used 24 hours, three repetitions, and Linux 5.19; this study uses
  72 hours, two repetitions, and an injected-probe Linux 6.14 target. Never
  present results as the paper's 5.19 findings.
- Use `hwsim-scan.json`, `--use-hwsim-input`, the existing patched kernel/QEMU,
  `--stages standard`, ramoops, per-trial coverage, and four LibAFL clients per
  trial (`--cores 0-3`). The latter matches our prior VirtFuzz campaign and
  the four-logical-CPU resource allocation of the currently active fuzzers; it
  differs from the artifact README's two-client WLAN example.
- Create one copy of each mode's Stretch image per trial. Add only the
  `multi-user.target.wants/permanent-scan.service` symlink to each copy. Do not
  edit the base image or production launcher.
- Give every trial its own fresh, empty `--corpus` output directory. Do not
  import mixed historical inputs. Use an isolated copy of `ssh_comm.py` that
  takes the corpus path from `VIRTFUZZ_CORPUS_DIR`. It also preserves crash,
  coverage, and probe evidence across an unexpected process restart and
  imports only this trial's nonhidden corpus inputs through `--initial-inputs`
  after such a restart. Keep workdirs, images, ports, and coverage separate.
- Ports: C2/85=24500, C2/86=24600, C3/85=30500, C3/86=30600.
  CPU masks: C2/85=30,31,94,95; C2/86=32,33,96,97;
  C3/85=34,35,98,99; C3/86=36,37,100,101.
- C2/C3 trial-90 smoke tests and trial-92 guest-side service diagnostics
  verified scan activity before any full run. Trial 91 C3 tested debug SSH
  but could not boot because this patched QEMU has no user-network backend.

## Validation and interpretation gates

- Before launch: the target image and workdir must not exist, the corpus must
  be empty, the intended ports must be free, the CPUs must not overlap active
  campaign affinity, and the image must show Stretch, the C2/C3 probe mode,
  `STABILIZE=0`, and the scan-service symlink.
- During the smoke test: confirm the *guest* starts `permanent-scan.service`
  and runs `iw wlan0 scan`; confirm nonzero VirtFuzz executions and more than
  one heartbeat across boots. Static image inspection alone is insufficient.
- During full trials: record actual process affinity, ports, first execution,
  scan and heartbeat counts, QEMU restart/crash counts, input rate, coverage,
  and probe reports with boot IDs and times. Stop/mark invalid if the service
  is inert, the corpus is contaminated, or workers exit/restart persistently.
- Analyze C2 and C3 separately. Attribute findings to post-execution input
  activity only with a supporting stack/timeline; classify boot-path reports
  as baseline artifacts. Do not pool C2 crash-loop throughput with C3.

## Launch and early validation

- Both modes passed a scan activation smoke test with a guest-written status
  log. The disposable C3 and C2 guests reported `permanent-scan.service`
  enabled and active, and observed `iw wlan0 scan` processes. C3 showed two
  distinct `iw` PIDs nine seconds apart. The diagnostic service is present
  only in trial-92 guest images, never in the four full-run images.
- Trial IDs 81/82 were started with only one SMT thread per physical core,
  then stopped and retained as discarded setup runs. Trial IDs 83/84 had the
  correct CPU topology but were started for 24 hours. When the user selected
  72 hours, they were stopped and retained as discarded partial starts.
  Their early C2 runs did reach mac80211 receive/scan-receive functions; that
  observation is kept as setup evidence, not as a result of the 72-hour runs.
  Registry entries mark 81-84 discarded and 90-92 legacy.
- Fresh 72-hour units 85/86 were launched on 2026-09-29. They use the ports
  and CPU masks above. `.trial_start` was written at 20:25:55 UTC, after the
  launcher's boot wait. Live cgroup inspection found every VirtFuzz and QEMU
  thread within its allocated four-CPU mask, with all four logical CPUs
  actually used in each trial. The old 83/84 services are stopped.
- At 20:40 UTC, all four fresh trials had nonzero executions and growing
  private corpora: C2 85/86 about 87k/127k executions, C3 85/86 about
  106k/107k. Probe heartbeats were present in each. C2 had 11 crash inputs
  per trial, while C3 had none; raw C2 signatures include injected
  `handle_crash_mode` crashes and are not new-bug findings. C3 trial 85 had
  already sampled `ieee80211_rx_list`, `ieee80211_rx_handlers`, and
  `ieee80211_scan_rx` PCs; the other three had only the VirtIO receive marker
  at this checkpoint. This is early coverage evidence, not a final outcome.
- An operational summary is scheduled for 2026-10-02 22:00 UTC at
  `VirtFuzz/rerun_20260929/operational_summary.json`. It records executions,
  corpus, crashes, probe heartbeats, and marker PCs; it never labels raw
  crashes as bugs. Classification by stack and boot/execution timeline remains
  necessary before any finding claim.
