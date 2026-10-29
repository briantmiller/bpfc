/*
 * bpfcd - keeps bpfc programs from /etc/bpfc/interfaces.d attached to interfaces.
 *
 * Layout: <config_dir>/<interface>/{ingress,egress}/<priority>.bpfc
 *
 * - On start, every file is compiled and attached with bpfc.
 * - SIGHUP rescans: new or changed files (mtime moved and SHA-256 differs) are
 *   (re)installed with an atomic replace, deleted files are detached.
 * - A netlink monitor installs programs when a configured interface appears,
 *   forgets them when it disappears, and checks TC changes on managed
 *   interfaces so that removed/replaced programs are reinstalled or logged
 *   (on_external_change in bpfc.conf).
 * - The current view is written to <state_dir>/state for bpfcctl.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define MAX_CAPTURE (1024 * 1024)      /* bpfc output kept per run (verifier logs can be long) */
#define VERIFY_DELAY_MS 200            /* debounce for TC change bursts */

static struct config cfg;
static char conf_path[PATH_MAX] = DEFAULT_CONF_PATH;
static struct daemon_info dinfo;
static struct slot *slots;
static int nslots, cap_slots;
static int state_dirty;
static int sigfd = -1, nlfd = -1, tfd = -1, pidfd = -1;
static int verify_pending;

/* ======================= sd_notify (no libsystemd needed) ======================= */

static void sd_notify_msg(const char *msg) {
    const char *path = getenv("NOTIFY_SOCKET");
    if (!path || !*path) return;
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    size_t len = strlen(path);
    if (len >= sizeof(sa.sun_path)) return;
    memcpy(sa.sun_path, path, len);
    if (sa.sun_path[0] == '@') sa.sun_path[0] = '\0'; /* abstract namespace */
    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return;
    sendto(s, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&sa,
           offsetof(struct sockaddr_un, sun_path) + len);
    close(s);
}

/* ======================= slot table ======================= */

static struct slot *slot_find(const char *iface, int dir, int prio) {
    for (int i = 0; i < nslots; i++)
        if (slots[i].dir == dir && slots[i].prio == prio && !strcmp(slots[i].iface, iface))
            return &slots[i];
    return NULL;
}

static struct slot *slot_add(const char *iface, int dir, int prio) {
    if (nslots == cap_slots) {
        int nc = cap_slots ? cap_slots * 2 : 32;
        struct slot *n = realloc(slots, nc * sizeof(*slots));
        if (!n) return NULL;
        slots = n;
        cap_slots = nc;
    }
    struct slot *s = &slots[nslots++];
    memset(s, 0, sizeof(*s));
    snprintf(s->iface, sizeof(s->iface), "%s", iface);
    s->dir = dir;
    s->prio = prio;
    s->status = ST_PENDING;
    return s;
}

static void slot_remove_at(int i) {
    slots[i] = slots[--nslots];
}

static int slot_cmp(const void *a, const void *b) {
    const struct slot *x = a, *y = b;
    int c = strcmp(x->iface, y->iface);
    if (c) return c;
    if (x->dir != y->dir) return x->dir - y->dir;
    return x->prio - y->prio;
}

static void set_status(struct slot *s, int st, const char *err) {
    if (s->status != st) s->changed_at = time(NULL);
    s->status = st;
    snprintf(s->error, sizeof(s->error), "%s", err ? err : "");
    state_dirty = 1;
}

static void filter_name(const struct slot *s, char *out, size_t len) {
    snprintf(out, len, FILTER_NAME_PREFIX "%s/%s/%d", s->iface, dir_name(s->dir), s->prio);
}

static void write_state(void) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cfg.state_dir, STATE_FILE_NAME);
    qsort(slots, nslots, sizeof(*slots), slot_cmp);
    dinfo.on_external_change = cfg.on_external_change;
    snprintf(dinfo.config_dir, sizeof(dinfo.config_dir), "%s", cfg.config_dir);
    int rc = state_write(path, &dinfo, slots, nslots);
    if (rc < 0) logmsg(LOG_LVL_ERR, "cannot write %s: %s", path, strerror(-rc));
    state_dirty = 0;
}

/* ======================= running bpfc ======================= */

struct run_result { int exit_code; int timed_out; char *out; size_t outlen; };

/* Runs argv with stdout+stderr captured. exit_code is -1 if it did not exit normally. */
static int run_capture(char *const argv[], struct run_result *r) {
    memset(r, 0, sizeof(*r));
    r->exit_code = -1;
    int p[2];
    if (pipe2(p, O_CLOEXEC) < 0) return -errno;
    pid_t pid = fork();
    if (pid < 0) { int e = -errno; close(p[0]); close(p[1]); return e; }
    if (pid == 0) {
        /* The daemon blocks signals for its signalfd; the child must not inherit that. */
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, 0);
        dup2(p[1], 1);
        dup2(p[1], 2);
        /* bpfc writes output.bpf when compiling without -i; keep it out of the way. */
        if (chdir(cfg.state_dir) < 0) { /* not fatal */ }
        execv(argv[0], argv);
        fprintf(stderr, "cannot execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(p[1]);

    size_t cap = 8192;
    r->out = malloc(cap);
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
        long left = cfg.compile_timeout * 1000L - elapsed;
        if (left <= 0) { r->timed_out = 1; kill(pid, SIGKILL); break; }
        struct pollfd pfd = {.fd = p[0], .events = POLLIN};
        int pr = poll(&pfd, 1, (int)left);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) continue;
        char buf[8192];
        ssize_t n = read(p[0], buf, sizeof(buf));
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        if (r->out && r->outlen < MAX_CAPTURE) {
            size_t take = (size_t)n;
            if (r->outlen + take > MAX_CAPTURE) take = MAX_CAPTURE - r->outlen;
            if (r->outlen + take + 1 > cap) {
                while (r->outlen + take + 1 > cap) cap *= 2;
                char *nb = realloc(r->out, cap);
                if (!nb) { free(r->out); r->out = NULL; continue; }
                r->out = nb;
            }
            memcpy(r->out + r->outlen, buf, take);
            r->outlen += take;
        }
    }
    close(p[0]);
    if (r->out) r->out[r->outlen] = '\0';
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) ;
    if (WIFEXITED(st)) r->exit_code = WEXITSTATUS(st);
    return 0;
}

/* Picks the most useful single line from bpfc output for the status table. */
static void summarize_failure(const struct run_result *r, char *out, size_t len) {
    if (r->timed_out) { snprintf(out, len, "bpfc timed out after %ds", cfg.compile_timeout); return; }
    if (!r->out || !r->outlen) { snprintf(out, len, "bpfc exited with status %d", r->exit_code); return; }
    if (strstr(r->out, "VERIFIER REJECTION")) {
        /* The verifier's own reason is the last non-empty line before the closing dashes. */
        /* The verifier's reason is the last line of its log that is not a statistics line. */
        const char *start = strstr(r->out, "VERIFIER REJECTION");
        const char *end = strstr(start, "\n------------------------------------------");
        while (end && end > start) {
            const char *p = end;
            while (p > start && (p[-1] == '\n' || p[-1] == ' ')) p--;
            const char *ls = p;
            while (ls > start && ls[-1] != '\n') ls--;
            if (p <= ls || ls <= start) break;
            if (!strncmp(ls, "processed ", 10) || !strncmp(ls, "verification time", 17) ||
                !strncmp(ls, "stack depth", 11)) {
                end = ls - 1;
                continue;
            }
            snprintf(out, len, "verifier rejected program: %.*s", (int)(p - ls), ls);
            return;
        }
        snprintf(out, len, "verifier rejected program");
        return;
    }
    /* Otherwise the first line that looks like an error, else the last line. */
    const char *best = NULL, *last = NULL;
    for (const char *ln = r->out; *ln;) {
        const char *nl = strchr(ln, '\n');
        size_t l = nl ? (size_t)(nl - ln) : strlen(ln);
        if (l) {
            last = ln;
            if (!best && (!strncmp(ln, "Error", 5) || strstr(ln, "error") || strstr(ln, "Invalid") ||
                          strstr(ln, "Fatal")))
                best = ln;
        }
        if (!nl) break;
        ln = nl + 1;
    }
    const char *pick = best ? best : last;
    if (!pick) { snprintf(out, len, "bpfc exited with status %d", r->exit_code); return; }
    const char *nl = strchr(pick, '\n');
    snprintf(out, len, "%.*s", (int)(nl ? nl - pick : (long)strlen(pick)), pick);
}

static void save_error_log(const struct slot *s, const struct run_result *r, const char *summary) {
    char path[PATH_MAX + 64];
    error_log_path(path, sizeof(path), cfg.state_dir, s->iface, s->dir, s->prio);
    FILE *f = fopen(path, "w");
    if (!f) { logmsg(LOG_LVL_WARN, "cannot write %s: %s", path, strerror(errno)); return; }
    time_t now = time(NULL);
    fprintf(f, "# bpfc failure for %s %s priority %d\n# file: %s\n# time: %s# reason: %s\n\n",
            s->iface, dir_name(s->dir), s->prio, s->path, ctime(&now), summary);
    if (r && r->out) fwrite(r->out, 1, r->outlen, f);
    if (r && r->outlen >= MAX_CAPTURE) fprintf(f, "\n[output truncated at %d bytes]\n", MAX_CAPTURE);
    fclose(f);
}

static void clear_error_log(const struct slot *s) {
    char path[PATH_MAX + 64];
    error_log_path(path, sizeof(path), cfg.state_dir, s->iface, s->dir, s->prio);
    unlink(path);
}

/* bpfc -D: removes whatever sits at this slot's priority. */
static int bpfc_delete(const struct slot *s) {
    char prio[16];
    snprintf(prio, sizeof(prio), "%d", s->prio);
    char *argv[] = {cfg.bpfc_path, "-i", (char *)s->iface, "-d", (char *)dir_name(s->dir),
                    "-p", prio, "-D", NULL};
    struct run_result r;
    int rc = run_capture(argv, &r);
    if (rc < 0 || r.exit_code != 0) {
        char why[256];
        if (rc < 0) snprintf(why, sizeof(why), "%s", strerror(-rc));
        else summarize_failure(&r, why, sizeof(why));
        logmsg(LOG_LVL_ERR, "%s %s prio %d: removing program failed: %s",
               s->iface, dir_name(s->dir), s->prio, why);
        free(r.out);
        return -1;
    }
    free(r.out);
    return 0;
}

/* ======================= installing a slot ======================= */

static int parse_info_line(const char *out, struct slot *s) {
    const char *p = out ? strstr(out, "BPFC_INFO ") : NULL;
    if (!p) return -1;
    unsigned id = 0, insns = 0;
    char tag[17] = {0};
    const char *q;
    if ((q = strstr(p, " id="))) id = (unsigned)strtoul(q + 4, NULL, 10);
    if ((q = strstr(p, " tag="))) sscanf(q + 5, "%16[0-9a-f]", tag);
    if ((q = strstr(p, " insns="))) insns = (unsigned)strtoul(q + 7, NULL, 10);
    if (!id) return -1;
    s->prog_id = id;
    s->insns = insns;
    snprintf(s->tag, sizeof(s->tag), "%s", tag);
    return 0;
}

/* Warns before bpfcd takes over a priority that holds a filter it did not install. */
static void warn_if_foreign(const struct slot *s, int ifindex) {
    struct tc_filter *f = NULL;
    int n = tc_dump_filters(ifindex, s->dir, &f);
    char mine[300];
    filter_name(s, mine, sizeof(mine));
    for (int i = 0; i < n; i++) {
        if (f[i].prio != s->prio) continue;
        if (!strcmp(f[i].name, mine)) break;
        char extra[64] = "";
        if (f[i].prog_id) snprintf(extra, sizeof(extra), " (prog id %u)", f[i].prog_id);
        logmsg(LOG_LVL_WARN, "%s %s prio %d: replacing a %s filter%s not installed by bpfcd",
               s->iface, dir_name(s->dir), s->prio, f[i].kind, extra);
        break;
    }
    free(f);
}

static void install_slot(struct slot *s, const char *why) {
    int ifindex = (int)if_nametoindex(s->iface);
    if (!ifindex) {
        if (s->status != ST_PENDING)
            logmsg(LOG_LVL_INFO, "%s %s prio %d: interface not present, waiting for it",
                   s->iface, dir_name(s->dir), s->prio);
        s->ifindex = 0;
        s->prog_id = 0;
        s->tag[0] = '\0';
        set_status(s, ST_PENDING, NULL);
        s->dirty = 0;
        return;
    }
    if (s->prog_id == 0 || s->ifindex != ifindex) warn_if_foreign(s, ifindex);

    char prio[16], name[300];
    snprintf(prio, sizeof(prio), "%d", s->prio);
    filter_name(s, name, sizeof(name));
    char *argv[16];
    int a = 0;
    argv[a++] = cfg.bpfc_path;
    argv[a++] = "-i"; argv[a++] = s->iface;
    argv[a++] = "-d"; argv[a++] = (char *)dir_name(s->dir);
    argv[a++] = "-p"; argv[a++] = prio;
    argv[a++] = "-n"; argv[a++] = name;
    argv[a++] = "-I";
    if (cfg.map_dir[0]) { argv[a++] = "-m"; argv[a++] = cfg.map_dir; }
    argv[a++] = "-f"; argv[a++] = s->path;
    argv[a] = NULL;

    struct run_result r;
    int rc = run_capture(argv, &r);
    struct slot probe = *s;
    if (rc == 0 && r.exit_code == 0 && parse_info_line(r.out, &probe) == 0) {
        s->prog_id = probe.prog_id;
        s->insns = probe.insns;
        snprintf(s->tag, sizeof(s->tag), "%s", probe.tag);
        s->ifindex = ifindex;
        s->installed_at = time(NULL);
        s->dirty = 0;
        set_status(s, ST_INSTALLED, NULL);
        clear_error_log(s);
        logmsg(LOG_LVL_INFO, "%s %s prio %d: installed %s (%s; prog id %u, tag %s, %u insns)",
               s->iface, dir_name(s->dir), s->prio, s->path, why, s->prog_id, s->tag, s->insns);
        free(r.out);
        return;
    }

    char summary[512];
    if (rc < 0) snprintf(summary, sizeof(summary), "cannot run %s: %s", cfg.bpfc_path, strerror(-rc));
    else if (r.exit_code == 0) snprintf(summary, sizeof(summary), "bpfc did not report a program id (is %s too old?)", cfg.bpfc_path);
    else summarize_failure(&r, summary, sizeof(summary));
    save_error_log(s, rc < 0 ? NULL : &r, summary);
    free(r.out);

    /* Never leave an older program running in place of one that failed (see bpfcd(8)). */
    bpfc_delete(s);
    s->prog_id = 0;
    s->tag[0] = '\0';
    s->insns = 0;
    s->ifindex = ifindex; /* remember where we tried, so link up/down does not retry */
    s->dirty = 0;
    set_status(s, ST_FAILED, summary);
    logmsg(LOG_LVL_ERR, "%s %s prio %d: %s failed: %s (details: bpfcctl show %s %s %d)",
           s->iface, dir_name(s->dir), s->prio, s->path, summary, s->iface, dir_name(s->dir), s->prio);
}

static void uninstall_slot(struct slot *s, const char *why) {
    /* Only our own program is removed; a filter someone else put in its place is left alone. */
    if (s->ifindex && if_nametoindex(s->iface) == (unsigned)s->ifindex && s->status == ST_INSTALLED) {
        if (bpfc_delete(s) == 0)
            logmsg(LOG_LVL_INFO, "%s %s prio %d: removed (%s)", s->iface, dir_name(s->dir), s->prio, why);
    }
    clear_error_log(s);
}

/* ======================= scanning the config dir ======================= */

/* Accepts "<1-65535>.bpfc" without leading zeros, so each priority has exactly one name. */
static int parse_prio_name(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot || strcmp(dot, ".bpfc") || dot == name || name[0] == '0') return -1;
    int v = 0;
    for (const char *p = name; p < dot; p++) {
        if (!isdigit((unsigned char)*p)) return -1;
        v = v * 10 + (*p - '0');
        if (v > 65535) return -1;
    }
    return v >= 1 ? v : -1;
}

/* Programs can drop or redirect any traffic, so world-writable sources are refused. */
static int file_trusted(const char *path, const struct stat *st) {
    if (st->st_mode & S_IWOTH) {
        logmsg(LOG_LVL_ERR, "%s: ignored, file is world-writable", path);
        return 0;
    }
    if (st->st_uid != 0 && geteuid() == 0)
        logmsg(LOG_LVL_WARN, "%s: not owned by root", path);
    return 1;
}

static void scan_file(const char *iface, int dir, const char *dirpath, const char *fname) {
    int prio = parse_prio_name(fname);
    if (prio < 0) {
        const char *dot = strrchr(fname, '.');
        if (dot && !strcmp(dot, ".bpfc"))
            logmsg(LOG_LVL_WARN, "%s/%s: ignored, name must be <priority>.bpfc with priority 1-65535 "
                   "and no leading zeros", dirpath, fname);
        return;
    }
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dirpath, fname) >= sizeof(path)) return;
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        logmsg(LOG_LVL_WARN, "%s: ignored, not a regular file", path);
        return;
    }
    if (!file_trusted(path, &st)) return;

    int64_t mtime = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
    struct slot *s = slot_find(iface, dir, prio);
    if (!s) {
        s = slot_add(iface, dir, prio);
        if (!s) { logmsg(LOG_LVL_ERR, "out of memory"); return; }
        s->dirty = 1;
        s->is_new = 1;
        s->changed_at = time(NULL);
    }
    s->seen = 1;
    snprintf(s->path, sizeof(s->path), "%s", path);

    /* Per bpfcd(8): only hash when the mtime moved; reload only when the hash differs too. */
    if (s->dirty || s->mtime_ns != mtime || !s->sha256[0]) {
        char hex[65];
        int rc = sha256_file(path, hex);
        if (rc < 0) {
            logmsg(LOG_LVL_ERR, "%s: cannot read: %s", path, strerror(-rc));
            s->seen = 0; /* treat as absent rather than install something stale */
            return;
        }
        if (strcmp(hex, s->sha256)) {
            if (s->sha256[0]) s->dirty = 1;
            snprintf(s->sha256, sizeof(s->sha256), "%s", hex);
        }
        s->mtime_ns = mtime;
        state_dirty = 1;
    }
}

static void scan_dir(void) {
    for (int i = 0; i < nslots; i++) slots[i].seen = 0;

    DIR *top = opendir(cfg.config_dir);
    if (!top) {
        if (errno == ENOENT)
            logmsg(LOG_LVL_WARN, "%s does not exist; no programs configured", cfg.config_dir);
        else
            logmsg(LOG_LVL_ERR, "cannot open %s: %s", cfg.config_dir, strerror(errno));
        return;
    }
    struct dirent *de;
    while ((de = readdir(top))) {
        if (de->d_name[0] == '.') continue;
        char ifdir[PATH_MAX];
        if ((size_t)snprintf(ifdir, sizeof(ifdir), "%s/%s", cfg.config_dir, de->d_name) >= sizeof(ifdir)) continue;
        struct stat st;
        if (stat(ifdir, &st) < 0 || !S_ISDIR(st.st_mode)) continue;
        if (!valid_ifname(de->d_name)) {
            logmsg(LOG_LVL_WARN, "%s: ignored, not a valid interface name", ifdir);
            continue;
        }
        for (int dir = DIR_INGRESS; dir <= DIR_EGRESS; dir++) {
            char ddir[PATH_MAX];
            if ((size_t)snprintf(ddir, sizeof(ddir), "%s/%s", ifdir, dir_name(dir)) >= sizeof(ddir)) continue;
            DIR *d = opendir(ddir);
            if (!d) {
                if (errno != ENOENT) logmsg(LOG_LVL_WARN, "cannot open %s: %s", ddir, strerror(errno));
                continue;
            }
            struct dirent *fe;
            while ((fe = readdir(d))) {
                if (fe->d_name[0] == '.') continue;
                scan_file(de->d_name, dir, ddir, fe->d_name);
            }
            closedir(d);
        }
    }
    closedir(top);
}

/* ======================= reconcile / verify ======================= */

/* Makes the kernel match the slot table. A reload also retries slots in any non-installed state. */
static void apply(int is_reload) {
    /* Deleted files first, so their priorities are free before anything new lands. */
    for (int i = 0; i < nslots;) {
        if (!slots[i].seen) {
            logmsg(LOG_LVL_INFO, "%s %s prio %d: %s was removed from the configuration",
                   slots[i].iface, dir_name(slots[i].dir), slots[i].prio, slots[i].path);
            uninstall_slot(&slots[i], "file deleted");
            slot_remove_at(i);
            state_dirty = 1;
            continue;
        }
        i++;
    }
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        int was_new = s->is_new;
        s->is_new = 0;
        if (s->dirty) {
            install_slot(s, was_new ? "new file" : "file changed");
        } else if (is_reload && s->status != ST_INSTALLED) {
            s->reinstall_count = 0;
            install_slot(s, "reload retry");
        }
    }
}

static void verify_all(void);

static void full_reload(void) {
    scan_dir();
    apply(1);
    verify_all();
    dinfo.last_reload = time(NULL);
    dinfo.reload_count++;
    state_dirty = 1;
}

/* Rate limit for automatic reinstalls, so bpfcd never fights another tool forever. */
static int reinstall_allowed(struct slot *s) {
    if (cfg.reinstall_limit == 0) return 1;
    time_t now = time(NULL);
    if (now - s->reinstall_window >= 60) {
        s->reinstall_window = now;
        s->reinstall_count = 0;
    }
    return ++s->reinstall_count <= cfg.reinstall_limit;
}

static void verify_iface_dir(int ifindex, int dir) {
    struct tc_filter *f = NULL;
    int n = tc_dump_filters(ifindex, dir, &f);
    if (n < 0) {
        logmsg(LOG_LVL_WARN, "cannot list filters on ifindex %d %s: %s", ifindex, dir_name(dir), strerror(-n));
        return;
    }
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (s->ifindex != ifindex || s->dir != dir || s->status != ST_INSTALLED) continue;
        const struct tc_filter *hit = NULL;
        for (int j = 0; j < n; j++)
            if (f[j].prio == s->prio) { hit = &f[j]; break; }
        if (hit && hit->prog_id == s->prog_id) continue;

        int removed = !hit;
        char what[256];
        if (removed)
            snprintf(what, sizeof(what), "program (id %u) was removed by something other than bpfcd", s->prog_id);
        else
            snprintf(what, sizeof(what), "program (id %u) was replaced by a %s filter%s not installed by bpfcd",
                     s->prog_id, hit->kind, hit->prog_id ? " with another program" : "");

        if (cfg.on_external_change == EXT_LOG) {
            logmsg(LOG_LVL_WARN, "%s %s prio %d: %s; on_external_change=log, leaving it",
                   s->iface, dir_name(s->dir), s->prio, what);
            set_status(s, removed ? ST_REMOVED_EXT : ST_REPLACED_EXT, what);
            if (removed) { s->prog_id = 0; s->tag[0] = '\0'; }
            continue;
        }
        if (!reinstall_allowed(s)) {
            char msg[512];
            snprintf(msg, sizeof(msg), "%s; reinstalled %d times within a minute, giving up until reload",
                     what, cfg.reinstall_limit);
            logmsg(LOG_LVL_ERR, "%s %s prio %d: %s", s->iface, dir_name(s->dir), s->prio, msg);
            set_status(s, ST_DISABLED, msg);
            continue;
        }
        logmsg(LOG_LVL_WARN, "%s %s prio %d: %s; reinstalling", s->iface, dir_name(s->dir), s->prio, what);
        install_slot(s, "external change");
    }
    free(f);
}

static void verify_all(void) {
    /* Each (ifindex, dir) pair is dumped once. */
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (s->status != ST_INSTALLED || !s->ifindex) continue;
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (slots[j].status == ST_INSTALLED && slots[j].ifindex == s->ifindex && slots[j].dir == s->dir) { dup = 1; break; }
        if (dup) continue;
        if (if_nametoindex(s->iface) != (unsigned)s->ifindex) continue; /* link event will handle it */
        verify_iface_dir(s->ifindex, s->dir);
    }
}

static void schedule_verify(void) {
    if (verify_pending) return;
    struct itimerspec its = {.it_value = {.tv_sec = 0, .tv_nsec = VERIFY_DELAY_MS * 1000000L}};
    timerfd_settime(tfd, 0, &its, NULL);
    verify_pending = 1;
}

/* ======================= startup adoption ======================= */

/*
 * After a daemon restart the programs are usually still attached. A slot is
 * adopted (not reinstalled) when the previous state says it was installed
 * from a file with the same hash and the kernel still has that exact program
 * at that priority. Slots from the old state whose files are gone are removed
 * if bpfcd's program is still attached.
 */
static void adopt_previous_state(void) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cfg.state_dir, STATE_FILE_NAME);
    struct daemon_info old_di;
    struct slot *old = NULL;
    int n = state_read(path, &old_di, &old);
    if (n <= 0) { free(old); return; }
    int adopted = 0;
    for (int i = 0; i < n; i++) {
        struct slot *o = &old[i];
        if (o->status != ST_INSTALLED || !o->prog_id) continue;
        int ifindex = (int)if_nametoindex(o->iface);
        if (!ifindex || ifindex != o->ifindex) continue;
        struct tc_filter *f = NULL;
        int nf = tc_dump_filters(ifindex, o->dir, &f);
        int present = 0;
        for (int j = 0; j < nf; j++)
            if (f[j].prio == o->prio && f[j].prog_id == o->prog_id) { present = 1; break; }
        free(f);
        if (!present) continue;

        struct slot *s = slot_find(o->iface, o->dir, o->prio);
        if (s && s->seen && !strcmp(s->sha256, o->sha256)) {
            s->prog_id = o->prog_id;
            snprintf(s->tag, sizeof(s->tag), "%s", o->tag);
            s->insns = o->insns;
            s->ifindex = ifindex;
            s->installed_at = o->installed_at;
            s->changed_at = o->changed_at;
            s->dirty = 0;
            s->status = ST_INSTALLED;
            adopted++;
        } else if (!s || !s->seen) {
            logmsg(LOG_LVL_INFO, "%s %s prio %d: %s was removed while bpfcd was stopped",
                   o->iface, dir_name(o->dir), o->prio, o->path);
            if (bpfc_delete(o) == 0)
                logmsg(LOG_LVL_INFO, "%s %s prio %d: removed", o->iface, dir_name(o->dir), o->prio);
        } else if (s) {
            /* Changed while stopped: an atomic replace takes care of it. */
            s->prog_id = o->prog_id;
            s->ifindex = ifindex;
        }
    }
    if (adopted) logmsg(LOG_LVL_INFO, "adopted %d program(s) still attached from the previous run", adopted);
    free(old);
}

/* ======================= netlink monitor ======================= */

static int open_monitor(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (s < 0) return -errno;
    int sz = 4 * 1024 * 1024;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0)
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK | RTMGRP_TC};
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(s); return e; }
    return s;
}

static int iface_is_managed(const char *name) {
    for (int i = 0; i < nslots; i++)
        if (!strcmp(slots[i].iface, name)) return 1;
    return 0;
}

static void on_link_new(int ifindex, const char *name) {
    /* A managed slot's device was renamed away from its configured name. */
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (s->ifindex == ifindex && strcmp(s->iface, name)) {
            logmsg(LOG_LVL_WARN, "%s was renamed to %s; removing %s prio %d from it",
                   s->iface, name, dir_name(s->dir), s->prio);
            if (s->status == ST_INSTALLED) {
                struct slot tmp = *s;
                snprintf(tmp.iface, sizeof(tmp.iface), "%s", name);
                bpfc_delete(&tmp);
            }
            s->ifindex = 0;
            s->prog_id = 0;
            s->tag[0] = '\0';
            set_status(s, ST_PENDING, NULL);
        }
    }
    if (!iface_is_managed(name)) return;
    int did = 0;
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (strcmp(s->iface, name) || s->ifindex == ifindex) continue;
        if (!did) logmsg(LOG_LVL_INFO, "interface %s appeared (ifindex %d), installing its programs", name, ifindex);
        did = 1;
        s->reinstall_count = 0;
        install_slot(s, "interface appeared");
    }
}

static void on_link_del(int ifindex, const char *name) {
    int did = 0;
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (s->ifindex != ifindex) continue;
        if (!did) logmsg(LOG_LVL_INFO, "interface %s (ifindex %d) was removed", name, ifindex);
        did = 1;
        s->ifindex = 0;
        s->prog_id = 0;
        s->tag[0] = '\0';
        set_status(s, ST_PENDING, NULL);
    }
}

static int ifindex_is_managed(int ifindex) {
    for (int i = 0; i < nslots; i++)
        if (slots[i].ifindex == ifindex && slots[i].status == ST_INSTALLED) return 1;
    return 0;
}

static void handle_netlink(void) {
    char buf[65536];
    for (;;) {
        ssize_t len = recv(nlfd, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == ENOBUFS) {
                /* Events were lost: re-derive everything from the kernel. */
                logmsg(LOG_LVL_WARN, "netlink monitor overflowed; resynchronizing");
                for (int i = 0; i < nslots; i++) {
                    struct slot *s = &slots[i];
                    int idx = (int)if_nametoindex(s->iface);
                    if (!idx && s->ifindex) on_link_del(s->ifindex, s->iface);
                    else if (idx && idx != s->ifindex) on_link_new(idx, s->iface);
                }
                schedule_verify();
                continue;
            }
            logmsg(LOG_LVL_ERR, "netlink monitor: %s", strerror(errno));
            return;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
            switch (h->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK: {
                struct ifinfomsg *ifi = NLMSG_DATA(h);
                char name[IFNAMSIZ] = {0};
                int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
                for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
                    if (a->rta_type == IFLA_IFNAME)
                        snprintf(name, sizeof(name), "%s", (char *)RTA_DATA(a));
                if (!name[0]) break;
                if (h->nlmsg_type == RTM_DELLINK) on_link_del(ifi->ifi_index, name);
                else on_link_new(ifi->ifi_index, name);
                break;
            }
            case RTM_NEWTFILTER:
            case RTM_DELTFILTER:
            case RTM_NEWQDISC:
            case RTM_DELQDISC: {
                struct tcmsg *t = NLMSG_DATA(h);
                if (ifindex_is_managed(t->tcm_ifindex)) schedule_verify();
                break;
            }
            default:
                break;
            }
        }
    }
}

/* ======================= lifecycle ======================= */

static int acquire_pidfile(void) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cfg.state_dir, PID_FILE_NAME);
    pidfd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (pidfd < 0) { logmsg(LOG_LVL_ERR, "cannot open %s: %s", path, strerror(errno)); return -1; }
    if (flock(pidfd, LOCK_EX | LOCK_NB) < 0) {
        logmsg(LOG_LVL_ERR, "another bpfcd is already running (%s is locked)", path);
        return -1;
    }
    return 0;
}

/* Called after daemonizing, so the recorded pid is the long-lived process. The
 * flock taken above belongs to the open file and survives the fork. */
static void write_pidfile(void) {
    char pid[32];
    int n = snprintf(pid, sizeof(pid), "%d\n", (int)getpid());
    if (ftruncate(pidfd, 0) < 0 || pwrite(pidfd, pid, n, 0) != n)
        logmsg(LOG_LVL_WARN, "cannot write the pid file: %s", strerror(errno));
}

static void release_pidfile(void) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cfg.state_dir, PID_FILE_NAME);
    if (pidfd >= 0) { unlink(path); close(pidfd); pidfd = -1; }
}

static void shutdown_daemon(void) {
    if (cfg.remove_on_stop) {
        logmsg(LOG_LVL_INFO, "remove_on_stop=yes: removing managed programs");
        for (int i = 0; i < nslots; i++) {
            uninstall_slot(&slots[i], "bpfcd stopping");
            slots[i].prog_id = 0;
            slots[i].tag[0] = '\0';
            set_status(&slots[i], ST_PENDING, "bpfcd stopped (remove_on_stop)");
        }
    }
    dinfo.pid = 0;
    write_state();
    release_pidfile();
}

static void count_states(int counts[ST__COUNT]) {
    memset(counts, 0, sizeof(int) * ST__COUNT);
    for (int i = 0; i < nslots; i++)
        if (slots[i].status >= 0 && slots[i].status < ST__COUNT) counts[slots[i].status]++;
}

static void notify_status(const char *prefix) {
    int c[ST__COUNT];
    count_states(c);
    char msg[256];
    snprintf(msg, sizeof(msg), "%sSTATUS=%d installed, %d waiting for interface, %d failed, %d external change",
             prefix, c[ST_INSTALLED], c[ST_PENDING], c[ST_FAILED] + c[ST_DISABLED],
             c[ST_REMOVED_EXT] + c[ST_REPLACED_EXT]);
    sd_notify_msg(msg);
    int failed = c[ST_FAILED] + c[ST_DISABLED];
    logmsg(failed ? LOG_LVL_WARN : LOG_LVL_INFO,
           "%d program(s) installed, %d waiting for interface, %d failed",
           c[ST_INSTALLED], c[ST_PENDING], failed);
}

static int reload_config_file(void) {
    struct config nc;
    config_defaults(&nc);
    char err[512] = "";
    if (config_load(conf_path, &nc, err, sizeof(err)) < 0 ||
        config_apply_env(&nc, err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "%s; keeping the previous settings", err);
        return -1;
    }
    if (strcmp(nc.state_dir, cfg.state_dir)) {
        logmsg(LOG_LVL_WARN, "state_dir changes take effect after a restart");
        snprintf(nc.state_dir, sizeof(nc.state_dir), "%s", cfg.state_dir);
    }
    if (strcmp(nc.map_dir, cfg.map_dir))
        logmsg(LOG_LVL_INFO, "map_dir changed; it applies to programs installed from now on");
    cfg = nc;
    log_set_level(cfg.log_level);
    return 0;
}

static int check_only(void) {
    /* -t: validate bpfc.conf and the directory layout without touching the kernel. */
    scan_dir();
    qsort(slots, nslots, sizeof(*slots), slot_cmp);
    printf("config:   %s\nprograms: %s\n", conf_path, cfg.config_dir);
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (!s->seen) continue;
        printf("  %-15s %-7s prio %-5d sha256 %.12s  %s%s\n", s->iface, dir_name(s->dir), s->prio,
               s->sha256, s->path, if_nametoindex(s->iface) ? "" : "  (interface not present)");
    }
    if (!nslots) printf("  (no programs found)\n");
    return 0;
}

static void usage(const char *argv0) {
    printf("Usage: %s [options]\n"
           "  -c, --config <file>  configuration file (default %s)\n"
           "  -b, --background     daemonize and log to syslog (non-systemd systems)\n"
           "  -D, --debug          log debug messages\n"
           "  -t, --test           check the configuration and list programs, then exit\n"
           "  -V, --version        print version\n"
           "  -h, --help           this help\n"
           "Signals: SIGHUP rescans %s and bpfc.conf; SIGTERM/SIGINT stop.\n",
           argv0, DEFAULT_CONF_PATH, DEFAULT_CONFIG_DIR);
}

int main(int argc, char **argv) {
    int background = 0, debug = 0, test = 0;
    static const struct option longopts[] = {
        {"config", required_argument, 0, 'c'}, {"background", no_argument, 0, 'b'},
        {"debug", no_argument, 0, 'D'}, {"test", no_argument, 0, 't'},
        {"version", no_argument, 0, 'V'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    /*
     * Block the signals bpfcd reads through its signalfd before anything else,
     * so a SIGTERM that arrives during start-up is handled as a clean stop
     * rather than killing the process. As PID 1 in a container, bpfcd also
     * takes SIGCHLD to reap orphaned processes re-parented to it.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    int is_init = getpid() == 1;
    if (is_init) sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int o;
    while ((o = getopt_long(argc, argv, "c:bDtVh", longopts, NULL)) != -1) {
        switch (o) {
        case 'c': snprintf(conf_path, sizeof(conf_path), "%s", optarg); break;
        case 'b': background = 1; break;
        case 'D': debug = 1; break;
        case 't': test = 1; break;
        case 'V': printf("bpfcd %s\n", BPFC_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }

    log_init("bpfcd", LOG_TO_STDERR, LOG_LVL_INFO);
    config_defaults(&cfg);
    char err[512] = "";
    if (config_load(conf_path, &cfg, err, sizeof(err)) < 0 ||
        config_apply_env(&cfg, err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "%s", err);
        return 1;
    }
    if (debug) cfg.log_level = LOG_LVL_DEBUG;
    log_set_level(cfg.log_level);
    if (test) return check_only();

    if (geteuid() != 0) logmsg(LOG_LVL_WARN, "not running as root; attaching programs will likely fail");
    if (access(cfg.bpfc_path, X_OK) < 0) {
        logmsg(LOG_LVL_ERR, "bpfc not executable at %s: %s", cfg.bpfc_path, strerror(errno));
        return 1;
    }

    char errdir[PATH_MAX + 32];
    snprintf(errdir, sizeof(errdir), "%s/%s", cfg.state_dir, ERROR_DIR_NAME);
    int rc = mkdir_p(errdir, 0755);
    if (rc < 0) { logmsg(LOG_LVL_ERR, "cannot create %s: %s", errdir, strerror(-rc)); return 1; }
    /* Locked before daemonizing so a duplicate start fails on the terminal, not just in syslog. */
    if (acquire_pidfile() < 0) return 1;
    if (background) {
        if (daemon(0, 0) < 0) { logmsg(LOG_LVL_ERR, "daemon(): %s", strerror(errno)); return 1; }
        log_init("bpfcd", LOG_TO_SYSLOG, cfg.log_level);
    }
    write_pidfile();

    signal(SIGPIPE, SIG_IGN);
    sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    /* The monitor is opened before the first scan so no interface event is missed. */
    nlfd = open_monitor();
    if (sigfd < 0 || tfd < 0 || nlfd < 0) {
        logmsg(LOG_LVL_ERR, "setup failed: %s", strerror(nlfd < 0 ? -nlfd : errno));
        release_pidfile();
        return 1;
    }

    memset(&dinfo, 0, sizeof(dinfo));
    dinfo.pid = (int)getpid();
    dinfo.started = time(NULL);
    snprintf(dinfo.version, sizeof(dinfo.version), "%s", BPFC_VERSION);

    logmsg(LOG_LVL_INFO, "bpfcd %s starting%s; programs from %s, external changes: %s",
           BPFC_VERSION, is_init ? " as PID 1" : "", cfg.config_dir,
           cfg.on_external_change == EXT_LOG ? "log" : "reinstall");
    scan_dir();
    adopt_previous_state();
    apply(0);
    verify_all();
    dinfo.last_reload = time(NULL);
    write_state();
    notify_status("READY=1\n");

    int running = 1;
    while (running) {
        struct pollfd pfd[3] = {
            {.fd = sigfd, .events = POLLIN}, {.fd = nlfd, .events = POLLIN}, {.fd = tfd, .events = POLLIN}};
        if (poll(pfd, 3, -1) < 0) {
            if (errno == EINTR) continue;
            logmsg(LOG_LVL_ERR, "poll: %s", strerror(errno));
            break;
        }
        if (pfd[1].revents & POLLIN) handle_netlink();
        if (pfd[2].revents & POLLIN) {
            uint64_t exp;
            if (read(tfd, &exp, sizeof(exp)) < 0) { /* spurious */ }
            verify_pending = 0;
            verify_all();
        }
        if (pfd[0].revents & POLLIN) {
            struct signalfd_siginfo si;
            while (read(sigfd, &si, sizeof(si)) == sizeof(si)) {
                if (si.ssi_signo == SIGCHLD) {
                    /* Only orphans can be waiting here: bpfc runs are reaped by run_capture()
                     * before it returns, and nothing else is forked from the main loop. */
                    while (waitpid(-1, NULL, WNOHANG) > 0)
                        ;
                } else if (si.ssi_signo == SIGHUP) {
                    logmsg(LOG_LVL_INFO, "SIGHUP: reloading %s and %s", conf_path, cfg.config_dir);
                    sd_notify_msg("STATUS=reloading");
                    reload_config_file();
                    full_reload();
                    write_state();
                    notify_status("");
                } else {
                    logmsg(LOG_LVL_INFO, "received %s, stopping", strsignal((int)si.ssi_signo));
                    sd_notify_msg("STOPPING=1");
                    running = 0;
                }
            }
        }
        if (state_dirty) write_state();
    }
    shutdown_daemon();
    return 0;
}
