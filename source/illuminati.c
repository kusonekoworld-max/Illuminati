/*
 * Copyright 2026 kusonekoworld-max (@koneko_dev)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <stdatomic.h>
#include <getopt.h>
#include <time.h>
#include <stdarg.h>

#define PROG_NAME    "illuminati"
#define PROG_VERSION "1.0.0"
#define PIDFILE      "/data/local/tmp/illuminati.pid"
#define LOGFILE      "/data/local/tmp/illuminati.log"
#define MAX_EXCLUDE  32
#define MAX_TARGETS  32
#define DEFAULT_WATCHDOG_PCT 15

/* ---------- ioprio_set syscall number, per-arch (not in every libc) ----- */
#if defined(__aarch64__) || defined(__riscv)
  #define SYS_IOPRIO_SET 30
#elif defined(__x86_64__)
  #define SYS_IOPRIO_SET 251
#elif defined(__i386__)
  #define SYS_IOPRIO_SET 289
#elif defined(__arm__)
  #define SYS_IOPRIO_SET 314
#else
  #define SYS_IOPRIO_SET -1
#endif
#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_CLASS_BE    2
#define IOPRIO_PRIO(cl,dat) (((cl) << 13) | (dat))

#define READAHEAD_CHUNK   (64 * 1024 * 1024)  /* 64MB per readahead() call */
#define FALLBACK_BUFSZ    (1 * 1024 * 1024)
#define DEFAULT_MEM_BUDGET_PCT 50

/* ------------------------------ job model -------------------------------- */
typedef struct job_node {
    char path[PATH_MAX];
    struct job_node *next;
} job_node_t;

typedef struct {
    job_node_t *head, *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int finished;
} job_queue_t;

typedef struct {
    void  *addr;
    size_t len;
} pinned_map_t;

/* ------------------------------ global state ------------------------------ */
static job_queue_t g_queue;
static int  g_threads      = 0;
static int  g_do_mlock     = 0;
static int  g_verbose      = 0;
static int  g_mem_budget   = DEFAULT_MEM_BUDGET_PCT;
static atomic_long g_bytes_loaded = 0;
static atomic_long g_files_loaded = 0;
static atomic_long g_files_failed = 0;
static atomic_long g_bytes_pinned = 0;
static volatile sig_atomic_t g_stop_requested = 0;

static pinned_map_t *g_pinned = NULL;
static size_t g_pinned_count = 0, g_pinned_cap = 0;
static pthread_mutex_t g_pinned_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *g_exclude[MAX_EXCLUDE];
static int g_exclude_count = 0;
static int g_daemon_mode = 0;
static atomic_int g_workers_done = 0;
static volatile sig_atomic_t g_daemon_stop = 0;

static const char *g_target_pkgs[MAX_TARGETS];  static int g_target_pkg_count  = 0;
static const char *g_target_files[MAX_TARGETS]; static int g_target_file_count = 0;
static const char *g_target_dirs[MAX_TARGETS];  static int g_target_dir_count  = 0;
static int g_watchdog_pct = DEFAULT_WATCHDOG_PCT;

/* --------------------------------- helpers --------------------------------- */
static void sigint_handler(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

static void vlog(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* Read MemAvailable from /proc/meminfo in kB, -1 on failure. */
static long get_mem_available_kb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    long val = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemAvailable: %ld kB", &val) == 1) break;
    }
    fclose(f);
    return val;
}

/* Read MemTotal from /proc/meminfo in kB, -1 on failure. */
static long get_mem_total_kb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    long val = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %ld kB", &val) == 1) break;
    }
    fclose(f);
    return val;
}

/* Tell lmkd/the kernel OOM killer to leave this process alone. On stock
 * Android, a resident daemon holding mlock'd pages can still get reaped
 * by lmkd under memory pressure — mlock alone does NOT protect the
 * process itself, only its pages while it's alive. Most quick preload
 * scripts miss this entirely and wonder why their "persistent" pin
 * disappears after a while. Root-only; silently best-effort otherwise. */
static void set_oom_score_adj(int value) {
    FILE *f = fopen("/proc/self/oom_score_adj", "w");
    if (!f) {
        fprintf(stderr, "%s: couldn't adjust oom_score_adj (%s) — daemon may still get "
                         "reaped under memory pressure without root\n", PROG_NAME, strerror(errno));
        return;
    }
    fprintf(f, "%d", value);
    fclose(f);
}

/* Best-effort I/O + CPU priority bump (full effect needs root). */
static void tune_self_priority(void) {
    setpriority(PRIO_PROCESS, 0, -5);
#if SYS_IOPRIO_SET != -1
    long prio = IOPRIO_PRIO(IOPRIO_CLASS_BE, 0); /* best-effort class, highest data prio */
    syscall(SYS_IOPRIO_SET, IOPRIO_WHO_PROCESS, 0, prio);
#endif
}

/* ------------------------------- job queue --------------------------------- */
static void queue_init(job_queue_t *q) {
    q->head = q->tail = NULL;
    q->finished = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_push(job_queue_t *q, const char *path) {
    job_node_t *n = malloc(sizeof(job_node_t));
    if (!n) return;
    snprintf(n->path, sizeof(n->path), "%s", path);
    n->next = NULL;

    pthread_mutex_lock(&q->lock);
    if (q->tail) q->tail->next = n; else q->head = n;
    q->tail = n;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

static int queue_pop(job_queue_t *q, char *out, size_t outsz) {
    pthread_mutex_lock(&q->lock);
    while (!q->head && !q->finished)
        pthread_cond_wait(&q->cond, &q->lock);

    if (!q->head) {
        pthread_mutex_unlock(&q->lock);
        return 0; /* queue closed and drained */
    }
    job_node_t *n = q->head;
    q->head = n->next;
    if (!q->head) q->tail = NULL;
    pthread_mutex_unlock(&q->lock);

    snprintf(out, outsz, "%s", n->path);
    free(n);
    return 1;
}

static void queue_mark_done(job_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    q->finished = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

/* ------------------------------ pin registry -------------------------------- */
static void register_pinned(void *addr, size_t len) {
    pthread_mutex_lock(&g_pinned_lock);
    if (g_pinned_count == g_pinned_cap) {
        g_pinned_cap = g_pinned_cap ? g_pinned_cap * 2 : 64;
        g_pinned = realloc(g_pinned, g_pinned_cap * sizeof(pinned_map_t));
    }
    g_pinned[g_pinned_count].addr = addr;
    g_pinned[g_pinned_count].len  = len;
    g_pinned_count++;
    pthread_mutex_unlock(&g_pinned_lock);
}

/* ---------------------------- hybrid preload core ----------------------------- */
static int preload_single_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        vlog("[skip] %s (%s)\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) {
        close(fd);
        return -1;
    }
    size_t size = (size_t)st.st_size;

    /* Stage 1: tell the kernel the access pattern up front. */
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED);

    /* Stage 2: manual chunked readahead. Large files fired in one shot
     * often get silently truncated by the kernel, so this loops in
     * predictable, verbose-loggable chunks. */
    off_t off = 0;
    while ((size_t)off < size) {
        size_t chunk = size - off;
        if (chunk > READAHEAD_CHUNK) chunk = READAHEAD_CHUNK;
        syscall(SYS_readahead, fd, off, chunk);
        off += chunk;
    }

    /* Stage 3 (optional): mmap + mlock to physically pin pages in RAM,
     * gated by a live memory budget check to avoid triggering the OOM
     * killer. */
    if (g_do_mlock) {
        long avail_kb = get_mem_available_kb();
        long already_pinned_kb = atomic_load(&g_bytes_pinned) / 1024;
        long budget_kb = (avail_kb > 0)
            ? (avail_kb + already_pinned_kb) * g_mem_budget / 100
            : -1;

        if (budget_kb < 0 || already_pinned_kb + (long)(size / 1024) <= budget_kb) {
            void *addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
            if (addr != MAP_FAILED) {
                if (mlock(addr, size) == 0) {
                    register_pinned(addr, size);
                    atomic_fetch_add(&g_bytes_pinned, (long)size);
                } else {
                    /* mlock failed (RLIMIT_MEMLOCK / non-root) — the
                     * mapping still warmed the page cache, so drop it. */
                    munmap(addr, size);
                    vlog("[mlock failed] %s: %s\n", path, strerror(errno));
                }
            }
        } else {
            vlog("[budget exceeded] skipping mlock for %s (%.1fMB)\n", path, size / 1048576.0);
        }
    } else {
        /* No mlock requested: fall back to a manual read loop for
         * filesystems that ignore fadvise/readahead (fuse/sdcardfs). */
        char *buf = malloc(FALLBACK_BUFSZ);
        if (buf) {
            ssize_t r;
            while ((r = read(fd, buf, FALLBACK_BUFSZ)) > 0) { /* just warm the page cache */ }
            free(buf);
        }
    }

    close(fd);
    atomic_fetch_add(&g_bytes_loaded, (long)size);
    atomic_fetch_add(&g_files_loaded, 1);
    vlog("[ok] %s (%.2fMB)\n", path, size / 1048576.0);
    return 0;
}

/* ------------------------------ live progress readout ------------------------------ */
/* Only runs on an interactive tty and when -v isn't already spamming
 * per-file lines — redraws a single line in place every 150ms.
 *
 * Deliberately NOT using ANSI erase-line ("\033[K") here: several
 * minimal PTYs (busybox sh, some Termux terminal configs) don't
 * interpret it cleanly and leave stale fragments behind. Plain
 * space-padding over a fixed width plus a bare '\r' is uglier but
 * works everywhere. */
#define PROGRESS_WIDTH 78

static void *stats_printer_thread(void *arg) {
    (void)arg;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    while (!atomic_load(&g_workers_done)) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;

        if (elapsed < 0.2) {
            /* too soon to bother — most sub-200ms runs finish before this
             * would even be useful, so skip straight to the next check
             * instead of flashing a half-drawn line. */
            struct timespec req = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };
            nanosleep(&req, NULL);
            continue;
        }
        if (elapsed <= 0) elapsed = 0.001;

        long files = atomic_load(&g_files_loaded);
        double mb  = atomic_load(&g_bytes_loaded) / 1048576.0;
        double pin = atomic_load(&g_bytes_pinned) / 1048576.0;

        char line[160];
        snprintf(line, sizeof(line),
                 "[illuminati] files:%-5ld loaded:%8.2fMB pinned:%8.2fMB  %6.1fMB/s",
                 files, mb, pin, mb / elapsed);
        printf("\r%-*s", PROGRESS_WIDTH, line);
        fflush(stdout);

        struct timespec req = { .tv_sec = 0, .tv_nsec = 150 * 1000 * 1000 };
        nanosleep(&req, NULL);
    }
    /* final overwrite: blank the line, drop the cursor to a fresh line
     * so "== done ==" from main() always starts clean. Only needed if
     * we actually printed something above. */
    struct timespec now2;
    clock_gettime(CLOCK_MONOTONIC, &now2);
    double total = (now2.tv_sec - t0.tv_sec) + (now2.tv_nsec - t0.tv_nsec) / 1e9;
    if (total >= 0.2) {
        printf("\r%-*s\r\n", PROGRESS_WIDTH, "");
        fflush(stdout);
    }
    return NULL;
}

/* -------------------------------- worker thread -------------------------------- */
static void *worker_thread(void *arg) {
    (void)arg;
    char path[PATH_MAX];
    while (!g_stop_requested && queue_pop(&g_queue, path, sizeof(path))) {
        if (preload_single_file(path) != 0)
            atomic_fetch_add(&g_files_failed, 1);
    }
    return NULL;
}

/* -------------------------------- exclude filter ---------------------------------- */
/* Glob match (fnmatch) against both the full path and just the basename,
 * so a simple pattern like "dex-ext-glob" or an oat-dir style glob work. */
static int should_exclude(const char *path) {
    if (g_exclude_count == 0) return 0;

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    for (int i = 0; i < g_exclude_count; i++) {
        if (fnmatch(g_exclude[i], path, 0) == 0) return 1;
        if (fnmatch(g_exclude[i], base, 0) == 0) return 1;
    }
    return 0;
}

/* ------------------------------ directory walking -------------------------------- */
static void scan_dir_recursive(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_dir_recursive(full);
        } else if (S_ISREG(st.st_mode)) {
            if (should_exclude(full)) {
                vlog("[excluded] %s\n", full);
                continue;
            }
            queue_push(&g_queue, full);
        }
    }
    closedir(d);
}

/* --------------------------- package -> file resolver ---------------------------- */
/* Enqueue apk + any oat/vdex/art found under one app directory. */
static void enqueue_app_dir(const char *appdir) {
    scan_dir_recursive(appdir); /* already picks up base.apk, split_N.apk, and everything under oat/ */
}

static int resolve_via_pm(const char *pkg) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "pm path %s 2>/dev/null", pkg);

    FILE *p = popen(cmd, "r");
    if (!p) return 0;

    char line[PATH_MAX];
    int found = 0;
    while (fgets(line, sizeof(line), p)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        char *apkpath = colon + 1;
        apkpath[strcspn(apkpath, "\r\n")] = 0;
        if (strlen(apkpath) == 0) continue;

        if (should_exclude(apkpath)) {
            vlog("[excluded] %s\n", apkpath);
            found = 1; /* still counts as "resolved", just filtered */
            continue;
        }
        queue_push(&g_queue, apkpath);
        found = 1;

        /* derive the apk's parent dir and sweep its sibling oat/ tree */
        char dircopy[PATH_MAX];
        snprintf(dircopy, sizeof(dircopy), "%s", apkpath);
        char *slash = strrchr(dircopy, '/');
        if (slash) {
            *slash = 0;
            char oatdir[PATH_MAX];
            snprintf(oatdir, sizeof(oatdir), "%s/oat", dircopy);
            struct stat st;
            if (stat(oatdir, &st) == 0 && S_ISDIR(st.st_mode))
                scan_dir_recursive(oatdir);
        }
    }
    pclose(p);
    return found;
}

/* Fallback with no `pm`: sweep /data/app manually, including the
 * Android 11+ hashed layout "/data/app/~~hash==/pkg-hash==/" that most
 * quick preload scripts never account for. */
static int resolve_via_scan(const char *pkg) {
    const char *root = "/data/app";
    DIR *d = opendir(root);
    if (!d) return 0;

    int found = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        char lvl1[PATH_MAX];
        snprintf(lvl1, sizeof(lvl1), "%s/%s", root, e->d_name);
        struct stat st;
        if (lstat(lvl1, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        if (strstr(e->d_name, pkg)) {
            /* legacy layout: /data/app/pkg-idx/ holds the apk directly */
            enqueue_app_dir(lvl1);
            found = 1;
            continue;
        }

        if (e->d_name[0] == '~') {
            /* hashed layout: descend one more level to find the folder
             * whose name contains the package name */
            DIR *d2 = opendir(lvl1);
            if (!d2) continue;
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL) {
                if (!strcmp(e2->d_name, ".") || !strcmp(e2->d_name, "..")) continue;
                if (strstr(e2->d_name, pkg)) {
                    char lvl2[PATH_MAX];
                    snprintf(lvl2, sizeof(lvl2), "%s/%s", lvl1, e2->d_name);
                    enqueue_app_dir(lvl2);
                    found = 1;
                }
            }
            closedir(d2);
        }
    }
    closedir(d);
    return found;
}

static void resolve_package(const char *pkg) {
    if (resolve_via_pm(pkg)) return;
    vlog("`pm path` returned nothing, falling back to manual /data/app scan...\n");
    if (!resolve_via_scan(pkg))
        fprintf(stderr, "%s: package '%s' not found (try running as root)\n", PROG_NAME, pkg);
}

/* -------------------------------- daemon mode -------------------------------------- */
/* SIGTERM handler for the resident child: just flips a flag, all real
 * cleanup (munlock/munmap) happens back in main()'s loop — signal
 * handlers should do as little as possible. */
static void sigterm_handler(int sig) {
    (void)sig;
    g_daemon_stop = 1;
}

static void release_all_pins(void) {
    pthread_mutex_lock(&g_pinned_lock);
    for (size_t i = 0; i < g_pinned_count; i++) {
        munlock(g_pinned[i].addr, g_pinned[i].len);
        munmap(g_pinned[i].addr, g_pinned[i].len);
    }
    pthread_mutex_unlock(&g_pinned_lock);
}

/* Background safety net for daemon mode: if system memory gets critically
 * low, being the reason lmkd starts killing foreground apps is worse than
 * losing some of our own pins. Evicts the most-recently-pinned mappings
 * first (LIFO — simplest fair approximation without per-pin usage stats)
 * until pressure clears or nothing's left to give back. */
static void *watchdog_thread(void *arg) {
    (void)arg;
    long total_kb = get_mem_total_kb();

    while (!g_daemon_stop) {
        struct timespec req = { .tv_sec = 2, .tv_nsec = 0 };
        nanosleep(&req, NULL);
        if (g_daemon_stop) break;

        long avail_kb = get_mem_available_kb();
        if (avail_kb < 0 || total_kb <= 0) continue;

        long pct = (avail_kb * 100) / total_kb;
        if (pct >= g_watchdog_pct) continue;

        pthread_mutex_lock(&g_pinned_lock);
        if (g_pinned_count > 0) {
            pinned_map_t victim = g_pinned[g_pinned_count - 1];
            g_pinned_count--;
            pthread_mutex_unlock(&g_pinned_lock);

            munlock(victim.addr, victim.len);
            munmap(victim.addr, victim.len);
            atomic_fetch_sub(&g_bytes_pinned, (long)victim.len);

            FILE *lf = fopen(LOGFILE, "a");
            if (lf) {
                fprintf(lf, "[watchdog] MemAvailable at %ld%% (< %d%% floor) — released %.1fMB pin\n",
                        pct, g_watchdog_pct, victim.len / 1048576.0);
                fclose(lf);
            }
        } else {
            pthread_mutex_unlock(&g_pinned_lock);
        }
    }
    return NULL;
}

/* Fork into background, keep the mlock'd mappings alive in the child
 * until SIGTERM (or `illuminati -k`). This is what makes -m pins actually
 * survive after the invoking shell session ends. */
static void daemonize_and_wait(void) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed: %s\n", PROG_NAME, strerror(errno));
        return;
    }
    if (pid > 0) {
        FILE *pf = fopen(PIDFILE, "w");
        if (pf) { fprintf(pf, "%d\n", pid); fclose(pf); }
        printf("daemonized as pid %d (%.0fMB pinned) — stop with: %s -k\n",
               pid, atomic_load(&g_bytes_pinned) / 1048576.0, PROG_NAME);
        exit(0);
    }

    /* child: detach from the controlling terminal */
    setsid();
    if (!freopen("/dev/null", "r", stdin))  { /* best effort */ }
    if (!freopen("/dev/null", "w", stdout)) { /* best effort */ }
    if (!freopen(LOGFILE, "a", stderr))     { /* best effort — diagnostics just get lost */ }
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    set_oom_score_adj(-1000); /* survive lmkd/OOM sweeps while resident, root-only */
    fprintf(stderr, "[illuminati] daemon started, watchdog floor=%d%%\n", g_watchdog_pct);

    pthread_t watchdog_tid;
    pthread_create(&watchdog_tid, NULL, watchdog_thread, NULL);

    while (!g_daemon_stop) {
        struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&req, NULL);
    }
    pthread_join(watchdog_tid, NULL);
    release_all_pins();
    unlink(PIDFILE);
    fprintf(stderr, "[illuminati] daemon stopped, pins released\n");
    exit(0);
}

static int kill_daemon(void) {
    FILE *pf = fopen(PIDFILE, "r");
    if (!pf) {
        fprintf(stderr, "%s: no daemon running (no pidfile at %s)\n", PROG_NAME, PIDFILE);
        return 1;
    }
    int pid = 0;
    if (fscanf(pf, "%d", &pid) != 1 || pid <= 0) {
        fclose(pf);
        fprintf(stderr, "%s: pidfile is corrupt\n", PROG_NAME);
        return 1;
    }
    fclose(pf);

    if (kill(pid, SIGTERM) != 0) {
        fprintf(stderr, "%s: couldn't signal pid %d: %s\n", PROG_NAME, pid, strerror(errno));
        return 1;
    }
    printf("sent SIGTERM to daemon pid %d\n", pid);
    return 0;
}

/* ------------------------------ batch config file ----------------------------------- */
/* Simple line format, one directive per line:
 *   a com.whatsapp        preload a package
 *   f /sdcard/game.apk    preload a file
 *   d /data/app           preload a directory
 *   x *.dex               exclude glob
 *   m                     enable mlock (same as -m)
 * Blank lines and lines starting with # are ignored. Lets one config
 * back a Magisk service.d boot script instead of hardcoding args. */
static void load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: can't open config '%s': %s\n", PROG_NAME, path, strerror(errno));
        return;
    }

    char line[PATH_MAX + 4];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        char kind = *p++;
        while (*p == ' ' || *p == '\t') p++;

        switch (kind) {
            case 'a':
                if (*p && g_target_pkg_count < MAX_TARGETS)
                    g_target_pkgs[g_target_pkg_count++] = strdup(p);
                break;
            case 'f':
                if (*p && g_target_file_count < MAX_TARGETS)
                    g_target_files[g_target_file_count++] = strdup(p);
                break;
            case 'd':
                if (*p && g_target_dir_count < MAX_TARGETS)
                    g_target_dirs[g_target_dir_count++] = strdup(p);
                break;
            case 'x':
                if (*p && g_exclude_count < MAX_EXCLUDE)
                    g_exclude[g_exclude_count++] = strdup(p);
                break;
            case 'm':
                g_do_mlock = 1;
                break;
            default:
                fprintf(stderr, "%s: config '%s': unknown directive '%c', skipping line\n",
                        PROG_NAME, path, kind);
        }
    }
    fclose(f);
}

/* --------------------------- Magisk boot service generator -------------------------- */
/* Rebuilds the current argv (minus -S/its value) into a single string,
 * good enough for simple args without embedded spaces/quotes — which
 * covers package names and typical file paths. */
static void rebuild_args_string(int argc, char **argv, char *out, size_t outsz) {
    out[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-S", 2)) {
            if (strlen(argv[i]) == 2) i++; /* also skip the separate value token */
            continue;
        }
        size_t used = strlen(out);
        if (used + strlen(argv[i]) + 2 >= outsz) break;
        strcat(out, argv[i]);
        strcat(out, " ");
    }
}

static int generate_service_script(const char *outpath, int argc, char **argv) {
    char selfpath[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", selfpath, sizeof(selfpath) - 1);
    if (n <= 0) snprintf(selfpath, sizeof(selfpath), "%s", argv[0]);

    char args[2048];
    rebuild_args_string(argc, argv, args, sizeof(args));

    FILE *f = fopen(outpath, "w");
    if (!f) {
        fprintf(stderr, "%s: can't write '%s': %s\n", PROG_NAME, outpath, strerror(errno));
        return 1;
    }
    fprintf(f,
        "#!/system/bin/sh\n"
        "# Auto-generated by %s -S — Magisk late_start service script.\n"
        "# Drop this into /data/adb/service.d/ so it runs once per boot,\n"
        "# well after the filesystem and package manager are ready.\n\n"
        "while [ \"$(getprop sys.boot_completed)\" != \"1\" ]; do sleep 1; done\n"
        "sleep 5\n"
        "%s %s&\n",
        PROG_NAME, selfpath, args);
    fclose(f);
    chmod(outpath, 0755);

    printf("wrote boot service script: %s\n", outpath);
    printf("install it with:\n  cp %s /data/adb/service.d/\n", outpath);
    return 0;
}

/* ------------------------------------ CLI / main ------------------------------------ */
/* toybox/AOSP-applet style help output */
static void print_usage(void) {
    fprintf(stderr,
"%s %s - android page-cache preload utility\n"
"usage: %s [-a PKG]... [-f FILE]... [-d DIR]... [-x GLOB]... [opts]\n"
"       %s -c CONFIG [opts]\n"
"       %s -S SCRIPT [opts]   (write a Magisk boot service, don't run)\n"
"       %s -k                 (stop a running -D daemon)\n"
"\n"
"Preload files, APKs, or installed packages into the page cache, and\n"
"optionally pin them into RAM so they survive cache pressure. -a/-f/-d/-x\n"
"are all repeatable — pass as many as you want in one run.\n"
"\n"
"By : @Koneko_dev (TELEGRAM) | kusonekoworld-max (GITHUB).\n"
"\n"
"-a PKG	preload an installed package (apk + oat/vdex/art)\n"
"-d DIR	preload a directory recursively\n"
"-f FILE	preload a single file\n"
"-x GLOB	exclude paths matching glob\n"
"-c FILE	load a batch config (see below) instead of -a/-f/-d/-x\n"
"-t N	worker thread count (default: min(nproc,4))\n"
"-m	pin loaded pages into RAM with mlock (root recommended)\n"
"-p PCT	memory budget percent allowed for mlock (default 50)\n"
"-D	stay resident in the background so -m pins persist\n"
"-w PCT	daemon watchdog: auto-release pins if MemAvailable falls\n"
"	below this percent of total RAM (default 15, -D only)\n"
"-S PATH	write a Magisk service.d boot script that reruns this\n"
"	exact command at every boot, then exit without preloading\n"
"-k	stop a running -D daemon\n"
"-v	verbose output (disables the live progress line)\n"
"-h	show this help message and exit\n"
"\n"
"config file format (-c), one directive per line:\n"
"  a com.whatsapp\n"
"  d /data/app\n"
"  x *.dex\n"
"  m\n"
"\n"
"examples:\n"
"  %s -a com.whatsapp -a com.spotify -m -v\n"
"  %s -d /data/app -t 4 -m -p 60 -x '*.dm'\n"
"  %s -a com.whatsapp -m -D -w 20   # preload + stay resident, safer floor\n"
"  %s -c /data/local/tmp/illuminati.conf -m -D\n"
"  %s -a com.whatsapp -m -D -S /data/local/tmp/illuminati-boot.sh\n"
"  %s -k                            # stop the daemon\n",
        PROG_NAME, PROG_VERSION, PROG_NAME, PROG_NAME, PROG_NAME, PROG_NAME,
        PROG_NAME, PROG_NAME, PROG_NAME, PROG_NAME, PROG_NAME, PROG_NAME);
}

int main(int argc, char **argv) {
    int opt;
    const char *service_out = NULL;

    while ((opt = getopt(argc, argv, "a:f:d:t:mp:x:c:w:S:Dkvh")) != -1) {
        switch (opt) {
            case 'a':
                if (g_target_pkg_count < MAX_TARGETS) g_target_pkgs[g_target_pkg_count++] = optarg;
                else fprintf(stderr, "%s: too many -a targets, ignoring '%s'\n", PROG_NAME, optarg);
                break;
            case 'f':
                if (g_target_file_count < MAX_TARGETS) g_target_files[g_target_file_count++] = optarg;
                else fprintf(stderr, "%s: too many -f targets, ignoring '%s'\n", PROG_NAME, optarg);
                break;
            case 'd':
                if (g_target_dir_count < MAX_TARGETS) g_target_dirs[g_target_dir_count++] = optarg;
                else fprintf(stderr, "%s: too many -d targets, ignoring '%s'\n", PROG_NAME, optarg);
                break;
            case 't': g_threads   = atoi(optarg); break;
            case 'm': g_do_mlock  = 1; break;
            case 'p': g_mem_budget = atoi(optarg); break;
            case 'x':
                if (g_exclude_count < MAX_EXCLUDE) g_exclude[g_exclude_count++] = optarg;
                else fprintf(stderr, "%s: too many -x patterns, ignoring '%s'\n", PROG_NAME, optarg);
                break;
            case 'c': load_config(optarg); break;
            case 'w': g_watchdog_pct = atoi(optarg); break;
            case 'S': service_out = optarg; break;
            case 'D': g_daemon_mode = 1; break;
            case 'k': return kill_daemon();
            case 'v': g_verbose   = 1; break;
            case 'h': print_usage(); return 0;
            default:  print_usage(); return 1;
        }
    }

    if (g_target_pkg_count == 0 && g_target_file_count == 0 && g_target_dir_count == 0) {
        print_usage();
        return 1;
    }

    if (service_out) {
        return generate_service_script(service_out, argc, argv);
    }

    if (g_daemon_mode && !g_do_mlock) {
        fprintf(stderr, "%s: -D without -m has nothing to keep pinned, enabling -m\n", PROG_NAME);
        g_do_mlock = 1;
    }
    if (g_watchdog_pct < 1) g_watchdog_pct = 1;
    if (g_watchdog_pct > 90) g_watchdog_pct = 90;

    if (g_threads <= 0) {
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        g_threads = (nproc > 4) ? 4 : (int)nproc;
        if (g_threads < 1) g_threads = 1;
    }

    signal(SIGINT, sigint_handler);
    tune_self_priority();
    queue_init(&g_queue);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    pthread_t *pool = malloc(sizeof(pthread_t) * g_threads);
    for (int i = 0; i < g_threads; i++)
        pthread_create(&pool[i], NULL, worker_thread, NULL);

    pthread_t progress_tid;
    int has_progress = (!g_verbose && isatty(STDOUT_FILENO));
    if (has_progress)
        pthread_create(&progress_tid, NULL, stats_printer_thread, NULL);

    /* fill the queue while workers are already draining it */
    for (int i = 0; i < g_target_pkg_count; i++)  resolve_package(g_target_pkgs[i]);
    for (int i = 0; i < g_target_file_count; i++) queue_push(&g_queue, g_target_files[i]);
    for (int i = 0; i < g_target_dir_count; i++)  scan_dir_recursive(g_target_dirs[i]);

    queue_mark_done(&g_queue);
    for (int i = 0; i < g_threads; i++)
        pthread_join(pool[i], NULL);
    free(pool);

    atomic_store(&g_workers_done, 1);
    if (has_progress) pthread_join(progress_tid, NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (elapsed <= 0) elapsed = 0.001;

    long files_ok  = atomic_load(&g_files_loaded);
    long files_bad = atomic_load(&g_files_failed);
    double mb       = atomic_load(&g_bytes_loaded) / 1048576.0;
    double mb_pin   = atomic_load(&g_bytes_pinned) / 1048576.0;

    printf("== done ==\n");
    printf("files ok      : %ld\n", files_ok);
    if (files_bad) printf("files failed  : %ld\n", files_bad);
    printf("total read    : %.2f MB\n", mb);
    if (g_do_mlock) printf("pinned in RAM : %.2f MB\n", mb_pin);
    printf("elapsed       : %.2f s (%.1f MB/s)\n", elapsed, mb / elapsed);

    if (g_daemon_mode && files_ok > 0) {
        daemonize_and_wait(); /* forks + exits the parent, doesn't return here */
    }

    /* intentionally not munmap/munlock'd on normal (non -D) exit — those
     * pins only last as long as this process does, which is why -D exists
     * for anyone who wants the pin to survive after the shell exits. */
    return files_ok > 0 ? 0 : 1;
}
