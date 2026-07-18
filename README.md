# Illuminati

<div align="center">

![platform](https://img.shields.io/badge/platform-Android%20%7C%20Termux-brightgreen)
[
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
](https://www.apache.org/licenses/LICENSE-2.0)
![root](https://img.shields.io/badge/root-KernelSU%20%7C%20KOWSU%20%7C%20Magisk-lightgrey)
![lang](https://img.shields.io/badge/lang-C-00599C)

</div>

---

## What is this

`illuminati` is a small, root-friendly CLI tool that preloads apps, files, or
whole directories into the Android page cache, and — if you ask it to —
physically pins those pages into RAM with `mlock` so they survive memory
pressure instead of getting evicted the moment lmkd gets nervous.

Most "RAM booster" scripts floating around do one `dd if=... of=/dev/null`
and call it a day. This one doesn't:

- Resolves installed packages the *correct* way, including the Android 11+
  hashed `/data/app/~~hash==/pkg-hash==/` layout most quick scripts never
  account for.
- Preloads via a real hybrid pipeline (`posix_fadvise` → chunked
  `readahead()` → optional `mmap` + `mlock`), not a single blind `cat`.
- Checks live `/proc/meminfo` budget before pinning anything, so it can't
  OOM your device.
- Protects its own daemon process from `lmkd` with `oom_score_adj`, because
  `mlock` only protects the *pages* — not the process holding them.
- Watches memory pressure while resident and gives pins back automatically
  before it becomes the reason something else gets killed.

---

## Features

| Feature | Flag | Notes |
|---|---|---|
| Preload an installed package | `-a PKG` | apk + oat/vdex/art, repeatable |
| Preload a single file | `-f FILE` | repeatable |
| Preload a directory (recursive) | `-d DIR` | repeatable |
| Exclude glob patterns | `-x GLOB` | repeatable |
| Batch config file | `-c FILE` | see [Config format](#config-file-format) |
| Worker thread count | `-t N` | default `min(nproc,4)` |
| Pin into RAM | `-m` | needs root for full effect |
| mlock memory budget | `-p PCT` | percent of available RAM, default `50` |
| Stay resident (daemon) | `-D` | keeps `-m` pins alive after the shell exits |
| Daemon watchdog floor | `-w PCT` | auto-release pins under pressure, default `15` |
| Generate boot service | `-S PATH` | writes a ready `service.d` script |
| Stop the daemon | `-k` | reads the pidfile, sends `SIGTERM` |
| Verbose output | `-v` | disables the live progress line |

---

## Usage

```bash
illuminati [-a PKG]... [-f FILE]... [-d DIR]... [-x GLOB]... [opts]
illuminati -c CONFIG [opts]
illuminati -S SCRIPT [opts]      # write a boot service, don't run
illuminati -k                    # stop a running -D daemon
```

### Examples

```bash
# Preload two apps, pin into RAM, verbose
illuminati -a com.whatsapp -a com.spotify -m -v

# Preload a directory, exclude debug symbols, cap mlock budget at 60%
illuminati -d /data/app -t 4 -m -p 60 -x '*.dm'

# Preload + stay resident with a safer memory floor
illuminati -a com.whatsapp -m -D -w 20

# Batch config, backgrounded
illuminati -c /data/local/tmp/illuminati.conf -m -D

# Generate a KernelSU/Magisk boot service for this exact command
illuminati -a com.whatsapp -m -D -S /data/local/tmp/illuminati-boot.sh

# Stop it
illuminati -k
```

### Config file format

One directive per line — lets `-S`-generated boot scripts stay simple
instead of hardcoding a long argv:

```
# comments are fine
a com.whatsapp
d /data/app
x *.dex
m
```

---

## Boot persistence (KernelSU / KOWSU / Magisk)

Works identically under KernelSU, KOWSU, and Magisk — `/data/adb/service.d/`
is honored by all three. The generated script waits for
`sys.boot_completed` before launching, so it never races the package
manager.

Diagnostics land in `/data/local/tmp/illuminati.log`; the running daemon's
pid is tracked in `/data/local/tmp/illuminati.pid`.

---

## How it actually preloads a file

```
open()
  → posix_fadvise(SEQUENTIAL, WILLNEED)
  → readahead()            [64MB chunks, looped]
  → mmap(MAP_POPULATE) + mlock()   [only if -m, and only if the memory
                                     budget check clears it]
```

If `mlock` isn't requested (or fails — e.g. `RLIMIT_MEMLOCK` without root),
it falls back to a manual `read()` sweep so filesystems that ignore
`fadvise`/`readahead` (fuse, sdcardfs) still get warmed.

---

## Why the daemon exists

`mlock` only keeps pages resident for as long as the process holding the
mapping is alive — exit, and the pin is gone. `-D` forks into a resident
child (`setsid`, stdio redirected, `SIGTERM`-driven cleanup) so the pin
actually outlives the shell that launched it.

That process is also explicitly protected from Android's low-memory killer
via `oom_score_adj -1000` — `mlock` alone does **not** stop lmkd from
reaping the process itself, which is the part most "persistent" preload
scripts get wrong. A background watchdog thread checks `MemAvailable`
every 2 seconds and releases the most recent pins first if the system
gets critically low, so this tool gives memory back before it becomes the
reason something else gets killed.

---

## Disclaimer

This tool needs root for anything beyond basic page-cache warming
(`-m`, `-D`, `oom_score_adj`, and `/data/app` scanning all require it).
Preloading large amounts of RAM has real tradeoffs — test the mlock
budget (`-p`) and watchdog floor (`-w`) for your device before relying on
it in a boot service.

---

<div align="center">

Built by **@Koneko_dev**

</div>
