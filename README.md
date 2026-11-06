> # ⚠️ THIS IS NOT A SECURITY TOOL. DO NOT USE IT.
>
> **Stasis-LSM is an unfinished proof-of-concept. It does not protect you
> from ransomware. It will miss real attacks, it will flag benign programs,
> and it has no tests, no configuration validation, and no support.**
>
> **Do not run this on a production system, a shared machine, or any host
> you care about. It is a learning project and a portfolio piece — nothing
> more. If you are relying on it to defend a real machine, you are not
> protected.**
>
> This repository is **not maintained** and the author does not intend to
> resume development. There will be no fixes, no releases, and no security
> patches. Pull requests and issues are not monitored.
>
> If you found this because you want ransomware protection for a real
> system: use something else. Snapshots, immutable backups, EDR, endpoint
> policies, `chattr +i` on critical trees, and a tested restore procedure
> are all real. This is not.

# Stasis-LSM

A behavioural-ransomware-detection **learning project** built on Linux
eBPF LSM hooks and Rust.

![Rust](https://img.shields.io/badge/Rust-2024_edition-orange)
![eBPF](https://img.shields.io/badge/eBPF-LSM-blue)
![Status](https://img.shields.io/badge/status-abandoned_proof--of--concept-critical)

---

## What this is / what this is not

**This is:**

- A personal project written out of curiosity about eBPF, LSM hooks, ring
  buffers, and Rust userspace/kernel-boundary work.
- A concrete, readable end-to-end example of attaching eBPF LSM programs
  from Rust, reading events from a ring buffer, and feeding them into a
  state machine.
- A demonstration of one *idea* for behavioural ransomware detection
  (per-process heuristics over a short window).
- A portfolio piece.

**This is not:**

- A security product.
- A finished project. It is abandoned.
- A replacement for backups, snapshots, EDR, or any real defence.
- Reliable. It has known false positives and known false negatives, and
  neither has been measured.
- Audited, fuzzed, tested, or reviewed by anyone.
- Supported. There is no maintainer, no issue tracker, and no roadmap.
  There never will be.

**Do not deploy it. Do not depend on it. Do not assume it will work.**

---

## Overview

Stasis-LSM watches process behaviour across five kernel hooks and scores
each process on a one-second window. If the behaviour *looks* like
ransomware — high file-open rate, broad directory dispersion, targeting of
high-value file extensions, and a balanced write+unlink loop — the process
is escalated to an `Alerted` state. Quiet processes are temporarily
whitelisted in-kernel so the fast path stays cheap.

The two halves are:

- **`src/bpf/stasis_lsm.bpf.c`** — a C eBPF program attaching to LSM hooks
  and a scheduler tracepoint, emitting events via an 18 MiB ring buffer.
- **Rust userspace** — consumes the ring buffer, runs per-PID state
  machines, evaluates heuristics, pushes decisions back into eBPF maps, and
  renders a ratatui TUI.

The interesting part, for anyone reading the code, is the mechanics: how the
five events are wired up, how the whitelist/tripwire map is used to keep the
fast path short without letting a compromised process hide forever, and how
the Rust side handles the union-typed event samples. The detection idea
itself is a sketch, not a validated method.

---

## How it works

### Kernel side (eBPF)

```
┌────────────────────────────────────────────────────────────────────┐
│ LSM hooks                                     event_rb (18 MiB)    │
│  • lsm.s/file_open          ─────────────┐                          │
│  • lsm.s/bprm_creds_for_exec ────────────┼──▶  struct event_sample │
│  • lsm/file_permission        ───────────┤                          │
│  • lsm.s/path_unlink          ───────────┘                          │
│                                                                     │
│ Tracepoint                                                          │
│  • sched/sched_process_exit   ──────────────▶  struct event_sample  │
│                                                                     │
│ Maps                                                                │
│  • whitelist         PID → u32 (PERM_WHITELIST or dynamic counter)  │
│  • blacklist         PID → u8  (allocated, never written to)        │
│  • ignored_prefixes  32 × 256-byte path prefixes                    │
└────────────────────────────────────────────────────────────────────┘
```

| Hook | Sleepable | Path resolution | Event emitted |
|------|-----------|-----------------|---------------|
| `lsm.s/file_open` | ✅ | `bpf_d_path()` (full path) | `EVENT_FILE_OPEN` |
| `lsm.s/bprm_creds_for_exec` | ✅ | `bpf_d_path()` w/ `bprm->filename` fallback | `EVENT_PROCESS_EXEC` |
| `lsm.s/path_unlink` | ✅ | `bpf_d_path()` on parent dir + leaf name | `EVENT_FILE_UNLINK` |
| `lsm/file_permission` | ❌ | leaf `dentry->d_name.name` only | `EVENT_FILE_WRITE` |
| `tracepoint/sched/sched_process_exit` | — | — | `EVENT_PROCESS_EXIT` |

The distinction matters: `bpf_d_path()` is only callable from *sleepable*
LSM hooks, which is why the `file_permission` hook can only see the leaf
filename, and why the `ignored_prefixes` map is a plain array rather than
an `LPM_TRIE` (LPM tries cannot be used with sleepable programs).

To keep the ring buffer clean, the kernel drops events for:

- **Virtual filesystems** by superblock magic (`proc`, `sysfs`, `tmpfs`,
  `devpts`, `cgroup`, `cgroup2`, `bpf`, `anon_inode`, `debugfs`).
- **Ignored path prefixes** configured from userspace (`/tmp`, `/dev`,
  `/var/cache`, `/mnt/c`) via `bpf_loop`, bounded at 32 iterations.
- **Cache churn**: any path containing the substring `/.cache/`.

### Whitelist & tripwire mechanism

The `whitelist` map is a `u32 → u32` map where the value has two meanings:

- `0xFFFFFFFF` (`PERM_WHITELIST`) — permanently bypass all checks.
- any other value — a **dynamic counter**. Each time a hooked event fires
  the kernel atomically increments it via `__sync_fetch_and_add`. Once it
  reaches `TRIPWIRE_THRESHOLD` (default 10 000) the entry is deleted and
  the process returns to full monitoring.

The tripwire exists so that a process cannot hide behind a temporary
whitelist forever: if the kernel keeps seeing activity it will eventually
evict the entry and force a re-evaluation. Both `bprm_creds_for_exec` and
`sched_process_exit` delete any stale whitelist/blacklist entry so PID
recycling is not a bypass vector.

*In practice this mechanism is not hardened. It is a sketch. Do not rely on
it for anything.*

### Userspace pipeline

```
ring buffer ──▶ mpsc (65 536) ──▶ ProcessTracker ──▶ heuristics
                    ▲                                  │
                    │                                  ▼
              BPF command channel              Decision::*
                    │
                    ▼
             whitelist map update
```

- **`src/bpf/mod.rs`** — `#[repr(C)]` mirrors of the kernel structs, plus
  `unsafe impl Plain` for zero-copy parsing with the `plain` crate, and safe
  `path_str()` / `comm_str()` helpers.
- **`src/process/mod.rs`** — a `DashMap<pid, ProcessContext>` that maintains
  a per-process state machine (`Idle → Monitoring → EvaluationPending →
  Whitelisted / Alerted`) with abort handles for the monitoring timer.
- **`src/suspicion/mod.rs`** — the heuristic engine.
- **`src/tui/mod.rs`** — a ratatui dashboard with three panels (processes,
  alerts, logs), `Tab` to switch panels and `q` to detach the TUI while
  monitoring keeps running in the background.

The event queue is sized at 65 536 × 272 bytes ≈ 18 MiB, intended to buffer
about two seconds of a ~15 000 files/sec sweep. Whether it does is untested.

---

## Detection model

Each monitored process is evaluated over a 1-second window after it is first
seen. Userspace computes four weighted heuristic scores from the events
observed during that window, then aggregates them.

| Heuristic | Weight | What it looks for | Rationale |
|-----------|--------|-------------------|-----------|
| **File Open Rate** | 0.3 | opens/sec — `>600` → 1.0, `>300` → 0.6, `>50` → 0.2 | Ransomware opens many files quickly. |
| **Directory Dispersion** | 0.2 | distinct parent directories — `>15` → 1.0, `>5` → 0.6, `>2` → 0.2 | Ransomware walks broad trees. |
| **High-Value Targets** | 0.2 | ratio of opens with a curated extension (docs, archives, media, databases, keys, certs) — `>0.8` → 1.0, `>0.5` → 0.6, `>0.2` → 0.2 (needs ≥5 opens) | Ransomware targets user data, not system files. |
| **Read/Write Asymmetry** | 0.3 | `(writes + unlinks) / opens` — in `[0.7, 2.5]` with unlinks `>15` → 1.0, `>5` → 0.7, else 0.3; or unlinks `>20` alone → 0.8 | Ransomware loops open→write→unlink. |

**The thresholds are educated guesses.** They are not calibrated against a
corpus, not validated against known ransomware samples, and not evaluated
for false-positive rate. They are a demonstration of the shape of a
detection idea, not a working detector.

The weighted average `final_score` drives the decision:

| Score | Decision | Userspace action | Kernel action |
|-------|----------|------------------|---------------|
| `≥ 0.5` | `Alert` | Enter `Alerted { cooldown_until, alert_count }`; re-alert every 5 s | — |
| `0.1 – 0.5` | `KeepMonitoring` | Return to `Idle`; re-evaluate on next burst | — |
| `< 0.1` | `WhitelistTemp` | Enter `Whitelisted { expiry: Some(_) }` for 10–45 s | `WhitelistAdd { pid, value: 0 }` |

A background task transitions the process back out of `Whitelisted` when
the expiry elapses and deletes the BPF map entry.

---

## Requirements

### Kernel

- Linux **5.7+** (needs both `BPF_MAP_TYPE_RINGBUF` and `BPF_LSM`).
- `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
- `bpf` must be in the active LSM list. Check with:

  ```bash
  cat /sys/kernel/security/lsm
  ```

  If `bpf` is missing, add it to the kernel command line, e.g.
  `lsm=lockdown,yama,integrity,apparmor,bpf`, and reboot.
- Running requires `CAP_BPF` + `CAP_PERFMON` + `CAP_MAC_ADMIN` (or `sudo`
  during development).

### Build toolchain

- Rust **2024 edition** (recent stable).
- `clang` + `lld` with BPF target support.
- `libbpf` development headers discoverable via `pkg-config`
  (Debian/Ubuntu: `libbpf-dev`, Fedora: `libbpf-devel`).
- `vmlinux.h` is pulled from
  [libbpf/vmlinux.h](https://github.com/libbpf/vmlinux.h) at a pinned git
  revision in `Cargo.toml` and copied into `src/bpf/include/` by `build.rs`.

---

## Building and running

> Reminder: **do not run this on anything you care about.** It is unfinished,
> untested, and can produce false positives (which means it will alert on
> benign programs) and false negatives (which means it will silently miss
> real ransomware).

```bash
cargo build --release
sudo ./target/release/stasis-lsm
```

### TUI

- `Tab` — cycle between the process, alert and log panels.
- `q` — detach the TUI and return to a plain CLI log stream. Monitoring
  continues in the background; press any key to re-attach.
- Session logs are appended to `/tmp/stasis_engine.log`.

There are **no other controls.** You cannot kill, block, or whitelist a
process from the dashboard. That was planned and never built.

---

## Project structure

```
.
├── build.rs                    # compiles the BPF skeleton, copies vmlinux.h
├── Cargo.toml
└── src
    ├── main.rs                 # setup, ring buffer consumer, event dispatcher
    ├── bpf
    │   ├── mod.rs              # #[repr(C)] event structs, Plain impls
    │   ├── stasis_lsm.bpf.c    # the eBPF program
    │   └── include/vmlinux.h   # generated by build.rs
    ├── process/mod.rs          # per-PID state machine, whitelist orchestration
    ├── suspicion/mod.rs        # heuristics + aggregation engine
    └── tui/mod.rs              # ratatui dashboard
```

---

## What works

- [x] Five kernel hooks (open / exec / write / unlink / exit) with virtual-FS
      and prefix filtering in-kernel.
- [x] 18 MiB ring buffer with back-pressure handling in userspace.
- [x] `plain`-based zero-copy deserialisation of the `event_sample` union.
- [x] Per-process state machine with abortable monitoring timers.
- [x] Four behavioural heuristics with weighted aggregation.
- [x] Temporary + permanent whitelisting enforced on both sides of the
      kernel boundary.
- [x] Tripwire counter to prevent indefinite in-kernel whitelisting.
- [x] PID-recycling defence via `sched_process_exit` cleanup.
- [x] ratatui dashboard with a CLI fallback and a persistent session log.

That list is a description of what the code *attempts*. None of it has been
validated. See below.

---

## What is not implemented, and will not be

This section is not a roadmap. The project is abandoned; these items are
listed so that anyone reading the code does not spend time looking for them
or assume they are just "not done yet."

- ❌ **Hash-based permanent whitelist.** Currently `is_permanently_whitelisted()`
  is a hard-coded set of directory prefixes (`/usr/bin/`, `/bin/`,
  `/usr/sbin/`, `…/cargo`, `…/rustc`). This is not a trust model; it's a
  placeholder. **There is no plan to replace it.**
- ❌ **Blocking.** The `blacklist` map exists in BPF, is read on every hook,
  and is **never written to** by userspace. Blocking does not work.
- ❌ **Interactive TUI.** The dashboard is read-only. The `BpfWhitelistAdd`,
  `BpfWhitelistRemove` and `BpfWhitelistCounterUpdate` UI event variants are
  defined and **never sent or handled**. You cannot kill, block, or act on a
  process from the TUI.
- ❌ **Additional heuristics.** Entropy inspection, file-format detection,
  filename-pattern matching, unlink-rate-only heuristics: all absent.
- ❌ **Heuristic tuning.** No calibration data, no evaluation corpus, no
  measured false-positive or false-negative rate.
- ❌ **Concurrency correctness.** A burst of events arriving while an
  evaluation is in flight is silently discarded in several places.
- ❌ **Automated tests.** There are none. Neither the heuristics nor the
  state machine are unit-tested. Not one `#[test]` exists.
- ❌ **Graceful shutdown.** `Ctrl-C` terminates the process without detaching
  programs cleanly.
- ❌ **Self-protection.** A `SIGKILL` to the daemon disables all detection.
- ❌ **Path normalisation.** Prefix matching operates on the string returned
  by `bpf_d_path()`, which may differ from what userspace sees through bind
  mounts or mount namespaces.
- ❌ **Configuration.** No config file. Thresholds are compile-time constants
  in the source.

---

## Why you should not use this

Even setting aside that it is abandoned, the *shape* of the tool is
unsuitable for real deployment:

- **It is a monitor, not a blocker.** It reports suspicious activity; it does
  not stop it. (See "blocking" above.)
- **False positives are expected.** `cargo build`, `rust-analyzer`, `tar`,
  `ripgrep` over a home directory, and many extraction tools will trip the
  read/write-asymmetry and directory-dispersion heuristics. This has not
  been measured — it has been observed during development and left alone.
- **False negatives are certain.** A ransomware binary that throttles itself
  to stay under 300 opens/sec, stays inside a small number of directories,
  or targets extensions outside the hard-coded list will not be flagged.
- **The thresholds are guesses.** There is no data behind any number in
  `src/suspicion/mod.rs`.
- **No privilege separation.** It runs as root and does not drop privileges.
- **No packaging.** It is a `cargo build`-and-pray project.
- **No maintainer.** If a kernel update breaks it, it stays broken. There
  will be no patch.

If you want ransomware protection for a real machine: snapshots, offline
backups, EDR, and a tested restore procedure are the correct answer. This
project is not.

---

## What I took away

Five things I know now that I didn't know at commit one. None of them are
specific to ransomware detection; all of them are specific to writing eBPF.

- **The verifier is the real API.** Half the interesting decisions in
  `stasis_lsm.bpf.c` were made because of verifier constraints, not because
  they were the natural way to write C. `bpf_loop(32, …)` for the prefix
  filter, the `len > 0 && len < 192` guard in `path_unlink` that exists
  solely to stop the verifier from splitting registers, the choice of a
  plain array map over `LPM_TRIE` — all of these are the code you write
  when the first question is "what will the verifier accept" instead of
  "what is simplest." Getting into that habit was the single biggest shift.

- **Sleepable vs. non-sleepable hooks constrain everything downstream.**
  `bpf_d_path()` only works from sleepable LSM hooks. That one fact is why
  `file_permission` can only see a leaf filename, and why the prefix
  filter cannot use an LPM trie. A single "can I sleep here?" cascades
  through the whole design. I did not appreciate this until I had written
  three of the five hooks and had to restructure.

- **A time-limited trust grant is a window an adversary can plan around.**
  The temporary whitelist lasts 10–45 seconds, and while it is active the
  kernel bypasses the process entirely. That makes it a target: behave
  benignly long enough to earn the whitelist, then go full blast inside the
  window. The tripwire counter is the answer to that. Every event under a
  dynamic whitelist atomically increments the entry, and once it reaches the
  threshold the entry is evicted and the process is back under full
  monitoring. So a process that does nothing loses its whitelist to the
  timer, and a process that does too much loses it to the counter. "Allowed"
  is a state the process has to keep earning, not a place it can sit for the
  length of a timer. The general principle: time-based expiry assumes the
  adversary waits; activity-based expiry assumes they don't.

- **PID recycling is a real attack surface.** The cleanup in both
  `bprm_creds_for_exec` and `sched_process_exit` exists because a
  stale whitelist entry might survive the process it was granted
  to. Or even worse: a permanent whitelist entry could inadvertently
  be hijacked by an attacker, should process cleanup fail for some
  reason.

- **Heuristics are the easy part; calibration is the hard part.** Four
  weighted rules took an afternoon. Knowing whether they are *correct*
  would take a labelled corpus, a measured false-positive and
  false-negative rate, and more time than the project had. That is the
  reason this is a proof-of-concept and not a detector, and it is the
  part I would most want to get right next time.

If I started over: a hash-based whitelist from commit one instead of path
prefixes, a heuristic test harness before the TUI, and blocking before the
dashboard. The TUI is the part a reader sees first and the part that would
matter least in a working tool.

---

## Contributing

**There is no contribution process. Issues and pull requests are not
monitored.** The author has no plans to review, merge, or respond to them.

You are welcome to fork the repository and take the code wherever you like
— that is the entire purpose of publishing it under an open license. Just
don't open a PR expecting a reply, and don't interpret this project's
existence as a claim that it is fit for any use.

---

## License

The Rust Userspace Code is dual-licensed under GPL-3.0-or-later and EUPL-1.2. The eBPF program in src/bpf/stasis_lsm.bpf.c is GPL-2.0-only, because the Linux kernel requires a GPLv2-compatible license string for LSM BPF programs and GPL-only helpers; EUPL-1.2's compatibility clause permits this combination.

---

## Acknowledgements

- [libbpf-rs](https://github.com/libbpf/libbpf-rs) and
  [libbpf-cargo](https://github.com/libbpf/libbpf-rs) for skeleton
  generation.
- The [vmlinux.h](https://github.com/libbpf/vmlinux.h) project.
- [ratatui](https://github.com/ratatui/ratatui) for the TUI.
- The Linux eBPF and LSM documentation.

---

*Stasis-LSM was written as a personal learning project. If any of the
mechanics — attaching eBPF LSM hooks from Rust, ring-buffer event plumbing,
or the sleepable-vs-non-sleepable path-resolution distinction — are useful to
you, the code is here to read. It is not here to be relied on.*
