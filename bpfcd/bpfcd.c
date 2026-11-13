/*
 * bpfcd - keeps bpfc programs from /etc/bpfc/interfaces.d attached to interfaces.
 *
 * Layout: <config_dir>/<interface>/{ingress,egress}/<priority>.bpfc
 *         <config_dir>/%all%/...      every interface
 *         <config_dir>/%<kind>%/...   every interface of that kind (veth, gre,
 *                                     vxlan, ...; nic = no kind, lo = loopback)
 *   Per direction and priority the most specific file wins: <interface>, then
 *   %<kind>%, then %all%. An empty file there means nothing at that priority.
 *
 * - On start, every file is compiled and attached with bpfc.
 * - SIGHUP rescans: new or changed files (mtime moved and SHA-256 differs) are
 *   (re)installed with an atomic replace, deleted files are detached.
 * - A netlink monitor installs programs when a configured interface appears,
 *   forgets them when it disappears, and checks TC changes on managed
 *   interfaces so that removed/replaced programs are reinstalled or logged
 *   (on_external_change in bpfc.conf).
 * - The current view is written to <state_dir>/state for bpfcctl.
 * - Programs come from two trees with the same layout: config_dir
 *   (/etc/bpfc/interfaces.d, edited by hand) and rest_dir
 *   (/var/lib/bpfc/interfaces.d, written through the REST socket). A file in
 *   rest_dir overrides the file at the same place in config_dir.
 * - With rest_socket set, an HTTP server on that unix socket shows the status
 *   and reads, writes and deletes rest_dir files; see the REST API section.
 * - With -n <name>, all of this happens inside network namespace <name>,
 *   configured from /etc/bpfc/netns/<name>/; see netns.c for how the
 *   namespace is found and the NETNS section below for following it.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"
#include "netns.h"
#include "json.h"
#include "http.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define VERIFY_DELAY_MS 200            /* debounce for TC change bursts */
#define NETNS_CHECK_MS  1000           /* how often the namespace (and its symlinks) is re-checked */

static struct config cfg;
static char conf_path[PATH_MAX + 16] = DEFAULT_CONF_PATH;   /* the file read, for messages */
static const char *conf_override;                           /* -c */
static const char *netns_arg;                               /* -n */
static struct daemon_info dinfo;
static struct slot *slots;
static int nslots, cap_slots;
static int state_dirty;
static int sigfd = -1, nlfd = -1, tfd = -1, pidfd = -1;
static int verify_pending;

/* -n: the namespace bpfcd started in, and the one it manages (cur.fd < 0 while waiting). */
static int host_nsfd = -1, host_rtnl = -1, nstfd = -1;
static struct netns_loc cur = {.fd = -1};
static char ns_wait_reason[512];

/* Programs may only be touched while inside the managed namespace. */
static int ns_active(void) { return !cfg.netns[0] || cur.fd >= 0; }

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

static char rest_serving[REST_SOCKET_MAX + 1];      /* REST socket being served (REST API section) */

/* The daemon record of the state file, from the current settings. */
static void fill_dinfo(void) {
    dinfo.on_external_change = cfg.on_external_change;
    snprintf(dinfo.config_dir, sizeof(dinfo.config_dir), "%s", cfg.config_dir);
    snprintf(dinfo.bpfc_path, sizeof(dinfo.bpfc_path), "%s", cfg.bpfc_path);
    snprintf(dinfo.netns, sizeof(dinfo.netns), "%s", cfg.netns);
    if (cfg.netns[0]) {
        snprintf(dinfo.netns_status, sizeof(dinfo.netns_status), "%s", cur.fd >= 0 ? "active" : "waiting");
        snprintf(dinfo.netns_target, sizeof(dinfo.netns_target), "%s", cur.fd >= 0 ? cur.desc : ns_wait_reason);
        dinfo.netns_dev = cur.dev;
        dinfo.netns_ino = cur.ino;
    }
    snprintf(dinfo.rest_dir, sizeof(dinfo.rest_dir), "%s", cfg.rest_dir);
    snprintf(dinfo.rest_socket, sizeof(dinfo.rest_socket), "%s", rest_serving);
}

static void write_state(void) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cfg.state_dir, STATE_FILE_NAME);
    qsort(slots, nslots, sizeof(*slots), slot_cmp);
    fill_dinfo();
    int rc = state_write(path, &dinfo, slots, nslots);
    if (rc < 0) logmsg(LOG_LVL_ERR, "cannot write %s: %s", path, strerror(-rc));
    state_dirty = 0;
}

/* ======================= running bpfc ======================= */

/* run_capture() and struct run_result are in common.c. */

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
    if (s->dir == DIR_XDP) { argv[5] = "-D"; argv[6] = NULL; } /* one program per interface */
    struct run_result r;
    int rc = run_capture(argv, &r, cfg.compile_timeout, cfg.state_dir);
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
    /* XDP programs have no filter name: compare the kernel program name bpfc
     * derives from it ("bpfcd:eth0/xdp/0" -> "eth0_xdp_0") */
    if (s->dir == DIR_XDP) kernel_prog_name(mine, mine, sizeof(mine));
    for (int i = 0; i < n; i++) {
        if (f[i].prio != s->prio) continue;
        if (!strcmp(f[i].name, mine)) break;
        char extra[64] = "";
        if (f[i].prog_id) snprintf(extra, sizeof(extra), " (prog id %u)", f[i].prog_id);
        logmsg(LOG_LVL_WARN, s->dir == DIR_XDP ? "%s %s prio %d: replacing an %s program%s not installed by bpfcd"
                                               : "%s %s prio %d: replacing a %s filter%s not installed by bpfcd",
               s->iface, dir_name(s->dir), s->prio, f[i].kind, extra);
        break;
    }
    free(f);
}

static void install_slot(struct slot *s, const char *why) {
    /* Waiting for the namespace: the current one is the host's, never touch it. */
    int ifindex = ns_active() ? (int)if_nametoindex(s->iface) : 0;
    if (!ifindex) {
        if (s->status != ST_PENDING && ns_active())
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
    if (s->dir != DIR_XDP) { argv[a++] = "-p"; argv[a++] = prio; }
    argv[a++] = "-n"; argv[a++] = name;
    argv[a++] = "-I";
    if (cfg.map_dir[0]) { argv[a++] = "-m"; argv[a++] = cfg.map_dir; }
    argv[a++] = "-f"; argv[a++] = s->path;
    argv[a] = NULL;

    struct run_result r;
    int rc = run_capture(argv, &r, cfg.compile_timeout, cfg.state_dir);
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

/* XDP: is our program still the one attached? (bpfc -D -d xdp removes whichever is.) */
static int xdp_still_ours(const struct slot *s) {
    struct tc_filter *f = NULL;
    int n = tc_dump_filters(s->ifindex, DIR_XDP, &f);
    int ours = n > 0 && f[0].prog_id == s->prog_id;
    free(f);
    return ours;
}

static void uninstall_slot(struct slot *s, const char *why) {
    /* Only our own program is removed; a filter someone else put in its place is left alone. */
    if (ns_active() && s->ifindex && if_nametoindex(s->iface) == (unsigned)s->ifindex && s->status == ST_INSTALLED &&
        (s->dir != DIR_XDP || xdp_still_ours(s))) {
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

/*
 * Sources are the files in the config dir, one per (scope, direction,
 * priority). A scope is an interface name, "%all%" or "%<kind>%". Slots are
 * what gets installed, one per (interface, direction, priority): for each
 * existing interface the most specific source wins, per direction and
 * priority -- <interface>/, then %<kind>%/, then %all%/ (Ethernet-header
 * devices only). An empty file at a more specific level means "nothing at
 * this priority on this interface" (status excluded).
 */
enum { LAYER_CONFIG = 0, LAYER_REST = 1 };

struct source {
    char scope[IFNAMSIZ + 24];
    int dir, prio;
    char path[PATH_MAX];
    int layer;                  /* LAYER_REST: from rest_dir */
    char overrides[PATH_MAX];   /* the config_dir file a rest_dir file stands in for, if any */
    int64_t mtime_ns;
    char sha256[65];
    int has_includes;
    int empty;
    int seen;
};
static struct source *sources;
static int nsources, cap_sources;

static struct link_info *links;
static int nlinks;

static struct source *source_find(const char *scope, int dir, int prio) {
    for (int i = 0; i < nsources; i++)
        if (sources[i].dir == dir && sources[i].prio == prio && !strcmp(sources[i].scope, scope))
            return &sources[i];
    return NULL;
}

/* No commands: only whitespace, ';' and # comments. */
static int file_is_empty(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int c, in_comment = 0, empty = 1;
    while ((c = fgetc(f)) != EOF) {
        if (in_comment) { if (c == '\n') in_comment = 0; continue; }
        if (c == '#') { in_comment = 1; continue; }
        if (!isspace(c) && c != ';') { empty = 0; break; }
    }
    fclose(f);
    return empty;
}

static void scan_file(const char *scope, int dir, const char *dirpath, const char *fname, int layer) {
    int prio = dir == DIR_XDP ? 0 : parse_prio_name(fname);
    if (prio < 0) {
        const char *dot = strrchr(fname, '.');
        if (dot && !strcmp(dot, ".bpfc"))
            logmsg(LOG_LVL_WARN, "%s/%s: ignored, name must be <priority>.bpfc with priority 1-65535 "
                   "and no leading zeros", dirpath, fname);
        return;
    }
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dirpath, fname) >= sizeof(path)) return;
    /* rest_dir is scanned first: its file wins over this one. */
    struct source *rsrc = layer == LAYER_CONFIG ? source_find(scope, dir, prio) : NULL;
    if (rsrc && rsrc->seen && rsrc->layer == LAYER_REST) {
        snprintf(rsrc->overrides, sizeof(rsrc->overrides), "%s", path);
        return;
    }
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        logmsg(LOG_LVL_WARN, "%s: ignored, not a regular file", path);
        return;
    }
    if (!file_trusted(path, &st)) return;

    int64_t mtime = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
    struct source *src = source_find(scope, dir, prio);
    if (!src) {
        if (nsources == cap_sources) {
            int nc = cap_sources ? cap_sources * 2 : 32;
            struct source *n = realloc(sources, nc * sizeof(*sources));
            if (!n) { logmsg(LOG_LVL_ERR, "out of memory"); return; }
            sources = n;
            cap_sources = nc;
        }
        src = &sources[nsources++];
        memset(src, 0, sizeof(*src));
        snprintf(src->scope, sizeof(src->scope), "%s", scope);
        src->dir = dir;
        src->prio = prio;
    }
    /* A file that moved between the trees is hashed again even with the same mtime. */
    int moved = strcmp(src->path, path) != 0;
    snprintf(src->path, sizeof(src->path), "%s", path);
    src->layer = layer;
    src->overrides[0] = '\0';

    /* Per bpfcd(8): only hash when the mtime moved; reload only when the hash differs too.
     * A program with includes is always re-hashed: an included file may have changed. */
    if (moved || src->mtime_ns != mtime || !src->sha256[0] || src->has_includes) {
        src->empty = file_is_empty(path);
        char hex[65];
        int rc;
        if (src->empty) {
            snprintf(hex, sizeof(hex), "%s", "empty");
            src->has_includes = 0;
            rc = 0;
        } else {
            rc = sha256_program(cfg.bpfc_path, path, cfg.compile_timeout, hex, &src->has_includes);
        }
        if (rc < 0) {
            logmsg(LOG_LVL_ERR, "%s: cannot read: %s", path, strerror(-rc));
            return; /* not seen: treated as absent rather than installing something stale */
        }
        snprintf(src->sha256, sizeof(src->sha256), "%s", hex);
        src->mtime_ns = mtime;
    }
    src->seen = 1;
}

static const struct link_info *link_by_name(const char *name) {
    for (int i = 0; i < nlinks; i++)
        if (!strcmp(links[i].name, name)) return &links[i];
    return NULL;
}

/* The slot for iface/dir/prio comes from src: create it or note a change of file. */
static void desire(const char *iface, const struct source *src, int from_template) {
    struct slot *s = slot_find(iface, src->dir, src->prio);
    if (!s) {
        s = slot_add(iface, src->dir, src->prio);
        if (!s) { logmsg(LOG_LVL_ERR, "out of memory"); return; }
        s->dirty = 1;
        s->is_new = 1;
        s->changed_at = time(NULL);
    } else if (strcmp(s->path, src->path) || strcmp(s->sha256, src->sha256)) {
        s->dirty = 1;
    }
    s->seen = 1;
    s->from_template = from_template;
    s->excluded = src->empty;
    s->has_includes = src->has_includes;
    s->mtime_ns = src->mtime_ns;
    snprintf(s->path, sizeof(s->path), "%s", src->path);
    if (strcmp(s->sha256, src->sha256)) state_dirty = 1;
    snprintf(s->sha256, sizeof(s->sha256), "%s", src->sha256);
}

/* Rebuilds the slot set from the sources and the current interfaces. */
static void expand(void) {
    for (int i = 0; i < nslots; i++) slots[i].seen = 0;
    for (int i = 0; i < nsources; i++)
        if (sources[i].scope[0] != '%') desire(sources[i].scope, &sources[i], 0);
    for (int l = 0; l < nlinks; l++) {
        const struct link_info *li = &links[l];
        char kscope[sizeof(li->kind) + 2];
        snprintf(kscope, sizeof(kscope), "%%%s%%", li->kind);
        for (int i = 0; i < nsources; i++) {
            const struct source *t = &sources[i];
            /* each (dir, prio) once: from the kind's entry, or from %all% when the kind has none */
            if (!strcmp(t->scope, kscope)) {
                if (!source_find(li->name, t->dir, t->prio)) desire(li->name, t, 1);
            } else if (!strcmp(t->scope, "%all%")) {
                /* every interface: on devices without an Ethernet header bpfc
                 * puts the IP header at offset 0 ($L3OFF) */
                if (!source_find(li->name, t->dir, t->prio) && !source_find(kscope, t->dir, t->prio))
                    desire(li->name, t, 1);
            }
        }
    }
}

/* Reads one program tree (config_dir or rest_dir). Returns -errno if it cannot be opened. */
static int scan_tree(const char *root, int layer) {
    DIR *top = opendir(root);
    if (!top) {
        int e = errno;
        if (e != ENOENT) logmsg(LOG_LVL_ERR, "cannot open %s: %s", root, strerror(e));
        return -e;
    }
    struct dirent *de;
    while ((de = readdir(top))) {
        if (de->d_name[0] == '.') continue;
        char ifdir[PATH_MAX];
        if ((size_t)snprintf(ifdir, sizeof(ifdir), "%s/%s", root, de->d_name) >= sizeof(ifdir)) continue;
        struct stat st;
        if (stat(ifdir, &st) < 0 || !S_ISDIR(st.st_mode)) continue;
        if (de->d_name[0] == '%' ? !valid_template_name(de->d_name) : !valid_ifname(de->d_name)) {
            logmsg(LOG_LVL_WARN, "%s: ignored, not a valid interface name, %%all%% or %%<kind>%%", ifdir);
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
                if (fe->d_name[0] == '.') continue;   /* also the REST API's temporary files */
                scan_file(de->d_name, dir, ddir, fe->d_name, layer);
            }
            closedir(d);
        }
        /* <if>/xdp.bpfc: the interface's XDP program */
        char xpath[PATH_MAX];
        struct stat xst;
        if ((size_t)snprintf(xpath, sizeof(xpath), "%s/xdp.bpfc", ifdir) < sizeof(xpath) && lstat(xpath, &xst) == 0)
            scan_file(de->d_name, DIR_XDP, ifdir, "xdp.bpfc", layer);
    }
    closedir(top);
    return 0;
}

static void scan_dir(void) {
    for (int i = 0; i < nsources; i++) sources[i].seen = 0;
    /* rest_dir first: its files override config_dir's (scan_file). It may well not exist. */
    int have_rest = scan_tree(cfg.rest_dir, LAYER_REST) == 0;
    if (scan_tree(cfg.config_dir, LAYER_CONFIG) == -ENOENT && !have_rest)
        logmsg(LOG_LVL_WARN, "%s does not exist; no programs configured", cfg.config_dir);
    for (int i = 0; i < nsources;) {
        if (!sources[i].seen) { sources[i] = sources[--nsources]; continue; }
        i++;
    }
    expand();
}

/* Re-reads the interface list (start-up, and after the monitor lost events). */
static void load_links(void) {
    if (!ns_active()) {   /* no namespace: no interfaces, so templates expand to nothing */
        free(links);
        links = NULL;
        nlinks = 0;
        return;
    }
    struct link_info *l = NULL;
    int n = link_dump(&l);
    if (n < 0) { logmsg(LOG_LVL_ERR, "cannot list interfaces: %s", strerror(-n)); return; }
    free(links);
    links = l;
    nlinks = n;
}

/* ======================= reconcile / verify ======================= */

/* What a retry of a non-installed slot is logged as. */
static const char *retry_reason = "reload retry";

/* Makes the kernel match the slot table. A reload also retries slots in any non-installed state. */
static void apply(int is_reload) {
    /* Deleted files first, so their priorities are free before anything new lands. */
    for (int i = 0; i < nslots;) {
        if (!slots[i].seen) {
            if (slots[i].from_template && !link_by_name(slots[i].iface))
                logmsg(LOG_LVL_DEBUG, "%s %s prio %d: interface gone, dropping %s",
                       slots[i].iface, dir_name(slots[i].dir), slots[i].prio, slots[i].path);
            else
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
        if (s->excluded) {
            /* An empty file at a more specific level: nothing at this priority here. */
            if (s->status != ST_EXCLUDED) {
                uninstall_slot(s, "excluded");
                s->prog_id = 0;
                s->tag[0] = '\0';
                s->insns = 0;
                s->ifindex = 0;
                logmsg(LOG_LVL_INFO, "%s %s prio %d: excluded by the empty file %s",
                       s->iface, dir_name(s->dir), s->prio, s->path);
                set_status(s, ST_EXCLUDED, NULL);
            }
            s->dirty = 0;
            continue;
        }
        if (s->dirty) {
            install_slot(s, was_new ? "new file" : "file changed");
        } else if (s->status == ST_EXCLUDED || (is_reload && s->status != ST_INSTALLED)) {
            s->reinstall_count = 0;
            install_slot(s, retry_reason);
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
            snprintf(what, sizeof(what), s->dir == DIR_XDP ? "program (id %u) was replaced by an %s program%s not installed by bpfcd"
                                                            : "program (id %u) was replaced by a %s filter%s not installed by bpfcd",
                     s->prog_id, hit->kind, hit->prog_id && s->dir != DIR_XDP ? " with another program" : "");

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
    if (!ns_active()) return;
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
    /* Programs recorded for another namespace are not ours to adopt or remove here. */
    if (cfg.netns[0] && (old_di.netns_ino != cur.ino || old_di.netns_dev != cur.dev)) {
        logmsg(LOG_LVL_INFO, "previous state is for a different namespace; installing afresh");
        free(old);
        return;
    }
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

static void link_upsert(const struct link_info *li) {
    for (int i = 0; i < nlinks; i++) {
        if (links[i].index != li->index) continue;
        /* keep a known kind if this message did not carry one */
        char kind[sizeof(li->kind)];
        snprintf(kind, sizeof(kind), "%s", links[i].kind);
        links[i] = *li;
        if (!li->has_kind && strcmp(kind, "nic") && strcmp(kind, "lo")) snprintf(links[i].kind, sizeof(kind), "%s", kind);
        return;
    }
    struct link_info *n = realloc(links, (nlinks + 1) * sizeof(*links));
    if (!n) { logmsg(LOG_LVL_ERR, "out of memory"); return; }
    links = n;
    links[nlinks++] = *li;
}

static void link_forget(int ifindex) {
    for (int i = 0; i < nlinks; i++)
        if (links[i].index == ifindex) { links[i] = links[--nlinks]; return; }
}

static void on_link_new(const struct link_info *li) {
    int ifindex = li->index;
    const char *name = li->name;
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
    const struct link_info *old = NULL;
    for (int i = 0; i < nlinks; i++) if (links[i].index == ifindex) old = &links[i];
    int changed = !old || strcmp(old->name, name) || old->type != li->type;
    link_upsert(li);
    if (changed) {
        /* %all% / %<kind>% programs for a new (or renamed) interface */
        expand();
        apply(0);
    }
    int did = 0;
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (strcmp(s->iface, name) || s->ifindex == ifindex || s->excluded) continue;
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
    link_forget(ifindex);
    expand();      /* drops this interface's %all% / %<kind>% slots */
    apply(0);
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
                    if (!s->ifindex || if_nametoindex(s->iface) == (unsigned)s->ifindex) continue;
                    s->ifindex = 0;     /* gone or renamed while events were lost */
                    s->prog_id = 0;
                    s->tag[0] = '\0';
                    set_status(s, ST_PENDING, NULL);
                }
                load_links();
                expand();
                apply(0);
                for (int i = 0; i < nslots; i++) {
                    struct slot *s = &slots[i];
                    if (s->excluded || s->status == ST_INSTALLED) continue;
                    if (if_nametoindex(s->iface)) install_slot(s, "interface appeared");
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
                struct link_info li;
                if (link_parse(h, &li) < 0) break;
                if (h->nlmsg_type == RTM_DELLINK) on_link_del(li.index, li.name);
                else {
                    on_link_new(&li);
                    /* an XDP program attached or removed by someone else shows up here */
                    if (ifindex_is_managed(li.index)) schedule_verify();
                }
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

/* ======================= NETNS: entering and following a namespace ======================= */

/*
 * With -n, bpfcd lives inside its namespace while it exists: setns() makes
 * if_nametoindex(), the TC netlink requests and every bpfc it runs act there.
 * Sockets stay with the namespace they were created in, so the event monitor
 * is reopened on every switch, and host_rtnl (created before the first
 * setns) keeps looking at the host side of a netns_veth.
 *
 * Every NETNS_CHECK_MS the namespace is checked again (netns_changed):
 *   - it disappeared (path gone, veth deleted, or nothing but bpfcd left in
 *     it): log, keep the programs as they are, and drop bpfcd's own
 *     reference so the namespace can be freed; wait for it to come back.
 *   - the path or veth now leads to a different namespace: remove bpfcd's
 *     programs from the old one, then install everything in the new one.
 */
static void ns_set_waiting(const char *why) {
    if (strcmp(ns_wait_reason, why)) {
        logmsg(LOG_LVL_INFO, "netns %s: waiting: %s", cfg.netns, why);
        snprintf(ns_wait_reason, sizeof(ns_wait_reason), "%s", why);
        state_dirty = 1;
    }
}

static void ns_forget_programs(int remove) {
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (remove) uninstall_slot(s, "namespace changed");
        if (s->status == ST_INSTALLED || s->status == ST_REMOVED_EXT || s->status == ST_REPLACED_EXT ||
            s->status == ST_DISABLED || s->status == ST_FAILED) {
            s->ifindex = 0;
            s->prog_id = 0;
            s->tag[0] = '\0';
            s->insns = 0;
            set_status(s, ST_PENDING, NULL);
        }
    }
}

/* Leaves the managed namespace: back to the host one, holding no reference to it. */
static void ns_leave(int remove_programs, const char *why) {
    if (cur.fd < 0) return;
    ns_forget_programs(remove_programs);
    if (nlfd >= 0) { close(nlfd); nlfd = -1; }
    if (setns(host_nsfd, CLONE_NEWNET) < 0)
        logmsg(LOG_LVL_ERR, "cannot return to the host namespace: %s", strerror(errno));
    netns_loc_close(&cur);
    ns_wait_reason[0] = '\0';
    ns_set_waiting(why);
    load_links();
    scan_dir();          /* template slots for the namespace's interfaces go away */
    apply(0);
    state_dirty = 1;
}

/* Enters a located namespace and installs everything there. */
static int ns_enter(struct netns_loc *loc, int at_start) {
    if (setns(loc->fd, CLONE_NEWNET) < 0) {
        int e = errno;
        char why[600];
        snprintf(why, sizeof(why), "%s: cannot enter: %s", loc->desc, strerror(e));
        netns_loc_close(loc);
        ns_set_waiting(why);
        return -e;
    }
    cur = *loc;
    loc->fd = -1;
    ns_wait_reason[0] = '\0';
    logmsg(LOG_LVL_INFO, "netns %s: managing %s", cfg.netns, cur.desc);
    if (nlfd >= 0) close(nlfd);
    nlfd = open_monitor();
    if (nlfd < 0) logmsg(LOG_LVL_ERR, "netns %s: event monitor: %s", cfg.netns, strerror(-nlfd));
    load_links();
    scan_dir();
    if (at_start) adopt_previous_state();
    retry_reason = "namespace found";
    apply(1);           /* every slot not adopted is pending: install them all */
    retry_reason = "reload retry";
    verify_all();
    state_dirty = 1;
    return 0;
}

static void ns_check(int at_start) {
    if (cur.fd >= 0 && !netns_changed(&cfg, host_rtnl, &cur)) return;
    struct netns_loc loc;
    int rc = netns_locate(&cfg, host_rtnl, &loc);
    if (cur.fd >= 0) {
        if (rc == 0 && loc.dev == cur.dev && loc.ino == cur.ino) {
            /* same namespace, found through another witness */
            snprintf(cur.witness, sizeof(cur.witness), "%s", loc.witness);
            snprintf(cur.desc, sizeof(cur.desc), "%s", loc.desc);
            cur.veth_ifindex = loc.veth_ifindex;
            cur.veth_nsid = loc.veth_nsid;
            netns_loc_close(&loc);
            state_dirty = 1;
            return;
        }
        if (rc == 0) {
            logmsg(LOG_LVL_WARN, "netns %s: now %s, a different namespace; moving the programs there",
                   cfg.netns, loc.desc);
            ns_leave(1, "switching namespace");
        } else {
            logmsg(LOG_LVL_WARN, "netns %s: the namespace is gone (%s); its programs are left as they "
                   "are, bpfcd waits for it to return", cfg.netns, loc.desc);
            ns_leave(0, loc.desc);
            return;
        }
    }
    if (rc < 0) {
        if (rc != -ENOENT && strcmp(ns_wait_reason, loc.desc))
            logmsg(LOG_LVL_ERR, "netns %s: %s", cfg.netns, loc.desc);
        ns_set_waiting(loc.desc);
        return;
    }
    ns_enter(&loc, at_start);
}

static void ns_start_timer(void) {
    struct itimerspec its = {
        .it_interval = {.tv_sec = NETNS_CHECK_MS / 1000, .tv_nsec = (NETNS_CHECK_MS % 1000) * 1000000L},
        .it_value = {.tv_sec = NETNS_CHECK_MS / 1000, .tv_nsec = (NETNS_CHECK_MS % 1000) * 1000000L}};
    timerfd_settime(nstfd, 0, &its, NULL);
}

/* ======================= REST API ======================= */

/*
 * With rest_socket set, bpfcd serves HTTP on that unix socket (http.c). Anyone
 * who can connect may read and change programs: access is the socket's owner
 * and mode (rest_socket_owner, rest_socket_mode). Resources:
 *
 *   GET    /                                   daemon, summary and every program (as bpfcctl status)
 *   GET    /interfaces                         every interface and scope with programs or files
 *   GET    /interfaces/<if>                    one interface (or %all%, %<kind>%): details, programs, files
 *   GET    /interfaces/<if>/<ingress|egress>   its programs and files in one direction
 *   GET    /interfaces/<if>/<dir>/<prio>       the program file, as a JSON array of lines
 *   POST   (same; PUT is the same)             write the file in rest_dir and install it
 *   DELETE (same)                              remove the rest_dir file
 *   .../interfaces/<if>/xdp                    the XDP program file (no priority)
 *
 * A write is checked first (bpfc -T, on one interface the file applies to)
 * and only then replaces the file. If installing it still fails anywhere,
 * the previous file is put back and reinstalled, and the reply is 422.
 * ?dry-run (or ?dry-run=true) checks on every interface the file would apply
 * to and changes nothing. Writes rescan both trees, like a reload.
 */

static struct http_server *rest_srv;
static char rest_owner_cur[sizeof(cfg.rest_owner)];
static int rest_mode_cur;
static dev_t rest_sock_dev;
static ino_t rest_sock_ino;

static void rest_handle(const struct http_request *req, struct http_response *resp);

static void rest_stop(void) {
    if (!rest_srv) return;
    http_server_free(rest_srv);
    rest_srv = NULL;
    /* Only our own socket: another bpfcd may have taken the path over. */
    struct stat st;
    if (lstat(rest_serving, &st) == 0 && st.st_dev == rest_sock_dev && st.st_ino == rest_sock_ino)
        unlink(rest_serving);
    logmsg(LOG_LVL_INFO, "rest: no longer serving %s", rest_serving);
    rest_serving[0] = '\0';
    state_dirty = 1;
}

static void rest_start(void) {
    if (!cfg.rest_socket[0]) return;
    uid_t uid;
    gid_t gid;
    char err[600];
    snprintf(rest_owner_cur, sizeof(rest_owner_cur), "%s", cfg.rest_owner);
    rest_mode_cur = cfg.rest_mode;
    if (rest_owner_resolve(cfg.rest_owner, &uid, &gid, err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "rest: %s; not serving %s", err, cfg.rest_socket);
        return;
    }
    int fd = http_listen(cfg.rest_socket, uid, gid, (unsigned)cfg.rest_mode, err, sizeof(err));
    if (fd < 0) { logmsg(LOG_LVL_ERR, "rest: %s; the REST API is off", err); return; }
    rest_srv = http_server_new(fd, rest_handle);
    if (!rest_srv) { close(fd); unlink(cfg.rest_socket); logmsg(LOG_LVL_ERR, "rest: out of memory"); return; }
    struct stat st;
    if (stat(cfg.rest_socket, &st) == 0) { rest_sock_dev = st.st_dev; rest_sock_ino = st.st_ino; }
    snprintf(rest_serving, sizeof(rest_serving), "%s", cfg.rest_socket);
    int rc = mkdir_p(cfg.rest_dir, 0755);
    if (rc < 0) logmsg(LOG_LVL_WARN, "rest: cannot create %s: %s", cfg.rest_dir, strerror(-rc));
    logmsg(LOG_LVL_INFO, "rest: serving %s (owner %s, mode %04o); programs written to %s",
           rest_serving, cfg.rest_owner, cfg.rest_mode, cfg.rest_dir);
    state_dirty = 1;
}

/* After a reload: (re)open the socket when its settings changed, or when it could not be opened before. */
static void rest_reconfigure(void) {
    if (!strcmp(cfg.rest_socket, rest_serving) && !strcmp(cfg.rest_owner, rest_owner_cur) &&
        cfg.rest_mode == rest_mode_cur && (rest_srv || !cfg.rest_socket[0]))
        return;
    /* A new owner that does not resolve keeps the socket that works. */
    uid_t u;
    gid_t g;
    char err[600];
    if (rest_srv && cfg.rest_socket[0] && rest_owner_resolve(cfg.rest_owner, &u, &g, err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "rest: %s; still serving %s as before", err, rest_serving);
        snprintf(rest_owner_cur, sizeof(rest_owner_cur), "%s", cfg.rest_owner);   /* log it once */
        rest_mode_cur = cfg.rest_mode;
        return;
    }
    rest_stop();
    rest_start();
}

/* ---- helpers ---- */

static const struct json_status_ctx *rest_ctx(void) {
    static struct json_status_ctx c;
    c.config_dir = cfg.config_dir;
    c.rest_dir = cfg.rest_dir;
    return &c;
}

/* <scope>/<dir>/<prio>.bpfc, or <scope>/xdp.bpfc */
static void prog_rel(char *out, size_t n, const char *scope, int dir, int prio) {
    if (dir == DIR_XDP) snprintf(out, n, "%s/xdp.bpfc", scope);
    else snprintf(out, n, "%s/%s/%d.bpfc", scope, dir_name(dir), prio);
}

static int is_regular(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Reads a whole file (at most max bytes). Returns 0, -EFBIG, or -errno. */
static int read_file(const char *path, char **out, size_t *len, size_t max) {
    *out = NULL;
    *len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    size_t cap = 4096, n = 0;
    char *b = malloc(cap + 1);
    if (!b) { close(fd); return -ENOMEM; }
    for (;;) {
        if (n == cap) {
            if (cap >= max) { free(b); close(fd); return -EFBIG; }
            cap *= 2;
            char *nb = realloc(b, cap + 1);
            if (!nb) { free(b); close(fd); return -ENOMEM; }
            b = nb;
        }
        ssize_t r = read(fd, b + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; int e = -errno; free(b); close(fd); return e; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (n > max) { free(b); return -EFBIG; }
    b[n] = '\0';
    *out = b;
    *len = n;
    return 0;
}

/* Writes data to path atomically (temporary file in the same directory, then rename), mode 0644. */
static int write_file_atomic(const char *path, const char *data, size_t len) {
    char tmp[PATH_MAX + 64];
    const char *slash = strrchr(path, '/');
    if (!slash) return -EINVAL;
    snprintf(tmp, sizeof(tmp), "%.*s/.%s.rest-%d.tmp", (int)(slash - path), path, slash + 1, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return -errno;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; int e = -errno; close(fd); unlink(tmp); return e; }
        off += (size_t)w;
    }
    if (fchmod(fd, 0644) < 0 || fsync(fd) < 0) { int e = -errno; close(fd); unlink(tmp); return e; }
    if (close(fd) < 0) { int e = -errno; unlink(tmp); return e; }
    if (rename(tmp, path) < 0) { int e = -errno; unlink(tmp); return e; }
    return 0;
}

/* Removes <rest_dir>/<scope>/<dir> and <rest_dir>/<scope> once they are empty. */
static void prune_rest_dirs(const char *scope, int dir) {
    char p[PATH_MAX + 64];
    if (dir != DIR_XDP) {
        snprintf(p, sizeof(p), "%s/%s/%s", cfg.rest_dir, scope, dir_name(dir));
        rmdir(p);
    }
    snprintf(p, sizeof(p), "%s/%s", cfg.rest_dir, scope);
    rmdir(p);
}

/* Is slot s (one interface) driven by files of scope at dir/prio? An interface scope is its own name. */
static int slot_in_scope(const struct slot *s, const char *scope) {
    if (scope[0] != '%') return !strcmp(s->iface, scope);
    char sc[IFNAMSIZ + 40];
    json_file_scope(s->path, s->dir, sc, sizeof(sc));
    return !strcmp(sc, scope);
}

static void json_source(struct jbuf *b, const struct source *src) {
    jb_obj(b);
    jb_kstr(b, "direction", dir_name(src->dir));
    if (src->dir == DIR_XDP) jb_knull(b, "priority");
    else jb_kint(b, "priority", src->prio);
    jb_kstr(b, "file", src->path);
    jb_kstr(b, "source", src->layer == LAYER_REST ? "rest" : "config");
    jb_kbool(b, "empty", src->empty);
    jb_kstr(b, "overrides", src->overrides[0] ? src->overrides : NULL);
    jb_obj_end(b);
}

static int source_cmp(const void *a, const void *b) {
    const struct source *x = *(const struct source *const *)a, *y = *(const struct source *const *)b;
    if (x->dir != y->dir) return x->dir - y->dir;
    return x->prio - y->prio;
}

/* "files": the sources of one scope (and direction, unless dir < 0), in order. */
static void json_sources_of(struct jbuf *b, const char *scope, int dir) {
    const struct source **list = malloc((nsources ? nsources : 1) * sizeof(*list));
    int n = 0;
    for (int i = 0; list && i < nsources; i++)
        if (!strcmp(sources[i].scope, scope) && (dir < 0 || sources[i].dir == dir)) list[n++] = &sources[i];
    if (list) qsort(list, n, sizeof(*list), source_cmp);
    jb_arr(b);
    for (int i = 0; i < n; i++) json_source(b, list[i]);
    jb_arr_end(b);
    free(list);
}

/* "programs": the slots of one scope (and direction, unless dir < 0; and priority, unless prio < 0). */
static void json_slots_of(struct jbuf *b, const char *scope, int dir, int prio) {
    jb_arr(b);
    for (int i = 0; i < nslots; i++) {
        const struct slot *s = &slots[i];
        if ((dir >= 0 && s->dir != dir) || (prio >= 0 && s->prio != prio) || !slot_in_scope(s, scope)) continue;
        json_slot(b, s, rest_ctx());
    }
    jb_arr_end(b);
}

/* Link details from the kernel: flags, MTU and MAC address (in the managed namespace). */
static void json_link_details(struct jbuf *b, const char *name) {
    const struct link_info *li = ns_active() ? link_by_name(name) : NULL;
    jb_kbool(b, "present", li != NULL);
    if (!li) {
        jb_knull(b, "ifindex");
        jb_knull(b, "kind");
        return;
    }
    jb_kint(b, "ifindex", li->index);
    jb_kstr(b, "kind", li->kind);
    jb_kint(b, "type", li->type);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        jb_kbool(b, "up", !!(ifr.ifr_flags & IFF_UP));
        jb_kbool(b, "running", !!(ifr.ifr_flags & IFF_RUNNING));
    }
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) jb_kint(b, "mtu", ifr.ifr_mtu);
    if (li->type == ARPHRD_ETHER_ && ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        const unsigned char *m = (const unsigned char *)ifr.ifr_hwaddr.sa_data;
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
        jb_kstr(b, "mac", mac);
    }
    close(fd);
}

/* ---- checking a program with bpfc -T ---- */

struct check {
    char iface[IFNAMSIZ];       /* empty: checked without an interface */
    int ok;
    unsigned insns, verified;
    char summary[512];
    char *out;
    size_t outlen;
};

static void run_check(const char *file, const char *iface, int dir, int prio, struct check *c) {
    memset(c, 0, sizeof(*c));
    if (iface) snprintf(c->iface, sizeof(c->iface), "%s", iface);
    char pr[16];
    snprintf(pr, sizeof(pr), "%d", prio);
    char *argv[16];
    int a = 0;
    argv[a++] = cfg.bpfc_path;
    argv[a++] = "-T";
    argv[a++] = "-I";
    argv[a++] = "-d"; argv[a++] = (char *)dir_name(dir);
    if (dir != DIR_XDP) { argv[a++] = "-p"; argv[a++] = pr; }
    if (iface) { argv[a++] = "-i"; argv[a++] = (char *)iface; }
    if (cfg.map_dir[0]) { argv[a++] = "-m"; argv[a++] = cfg.map_dir; }
    argv[a++] = "-f"; argv[a++] = (char *)file;
    argv[a] = NULL;
    struct run_result r;
    int rc = run_capture(argv, &r, cfg.compile_timeout, cfg.state_dir);
    c->ok = rc == 0 && r.exit_code == 0;
    if (rc == 0 && r.out) {
        const char *info = strstr(r.out, "BPFC_INFO ");
        const char *q;
        if (info && (q = strstr(info, " insns="))) c->insns = (unsigned)strtoul(q + 7, NULL, 10);
        if (info && (q = strstr(info, " verified="))) c->verified = (unsigned)strtoul(q + 10, NULL, 10);
        c->out = r.out;
        c->outlen = r.outlen;
    } else {
        free(r.out);
    }
    if (!c->ok) {
        if (rc < 0) snprintf(c->summary, sizeof(c->summary), "cannot run %s: %s", cfg.bpfc_path, strerror(-rc));
        else summarize_failure(&r, c->summary, sizeof(c->summary));
    }
}

/* bpfc's output without the BPFC_INFO line. */
static void json_check(struct jbuf *b, const struct check *c) {
    jb_obj(b);
    jb_kstr(b, "interface", c->iface[0] ? c->iface : NULL);
    jb_kbool(b, "ok", c->ok);
    if (c->insns) jb_kint(b, "insns", c->insns);
    if (c->verified) jb_kint(b, "verified_insns", c->verified);
    jb_kstr(b, "error", c->ok ? NULL : c->summary);
    jb_key(b, "output");
    jb_arr(b);
    const char *p = c->out, *end = c->out ? c->out + c->outlen : NULL;
    while (p && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t l = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (strncmp(p, "BPFC_INFO ", 10)) jb_strn(b, p, l);
        p += l + (nl ? 1 : 0);
    }
    jb_arr_end(b);
    jb_obj_end(b);
}

/*
 * Interfaces a file of scope at dir/prio would be installed on now: the
 * interface itself, or each interface of the kind (or every interface) that
 * has no more specific file at that priority. Returns how many (at most max).
 */
static int check_targets(const char *scope, int dir, int prio, char (*out)[IFNAMSIZ], int max) {
    if (!ns_active()) return 0;
    if (scope[0] != '%') {
        if (!link_by_name(scope) || max < 1) return 0;
        snprintf(out[0], IFNAMSIZ, "%s", scope);
        return 1;
    }
    int n = 0;
    for (int l = 0; l < nlinks && n < max; l++) {
        const struct link_info *li = &links[l];
        char kscope[sizeof(li->kind) + 2];
        snprintf(kscope, sizeof(kscope), "%%%s%%", li->kind);
        if (source_find(li->name, dir, prio)) continue;
        if (!strcmp(scope, "%all%")) {
            if (source_find(kscope, dir, prio)) continue;
        } else if (strcmp(scope, kscope)) {
            continue;
        }
        snprintf(out[n++], IFNAMSIZ, "%s", li->name);
    }
    return n;
}

/* ---- handlers ---- */

static void rest_get_root(struct http_response *resp) {
    fill_dinfo();
    qsort(slots, nslots, sizeof(*slots), slot_cmp);
    struct jbuf *b = &resp->body;
    jb_obj(b);
    jb_key(b, "bpfcd");
    json_daemon(b, &dinfo, 1);
    jb_key(b, "summary");
    json_summary(b, slots, nslots, 0);
    jb_key(b, "programs");
    jb_arr(b);
    for (int i = 0; i < nslots; i++) json_slot(b, &slots[i], rest_ctx());
    jb_arr_end(b);
    jb_obj_end(b);
}

static int name_cmp(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static void rest_get_interfaces(struct http_response *resp) {
    /* Interfaces that exist, and scopes that have files or programs. */
    typedef char name_t[IFNAMSIZ + 24];
    int cap = nlinks + nsources + nslots + 1, n = 0;
    name_t *names = calloc((size_t)cap, sizeof(name_t));
    if (!names) { http_error(resp, 500, "out of memory"); return; }
#define ADD_NAME(x) do { int _d = 0; for (int _j = 0; _j < n; _j++) if (!strcmp(names[_j], (x))) { _d = 1; break; } \
                         if (!_d) snprintf(names[n++], sizeof(name_t), "%s", (x)); } while (0)
    if (ns_active()) for (int i = 0; i < nlinks; i++) ADD_NAME(links[i].name);
    for (int i = 0; i < nsources; i++) ADD_NAME(sources[i].scope);
    for (int i = 0; i < nslots; i++) ADD_NAME(slots[i].iface);
#undef ADD_NAME
    qsort(names, (size_t)n, sizeof(name_t), name_cmp);
    struct jbuf *b = &resp->body;
    jb_obj(b);
    jb_key(b, "interfaces");
    jb_arr(b);
    for (int i = 0; i < n; i++) {
        int progs = 0, files = 0;
        for (int j = 0; j < nslots; j++) if (slot_in_scope(&slots[j], names[i])) progs++;
        for (int j = 0; j < nsources; j++) if (!strcmp(sources[j].scope, names[i])) files++;
        jb_obj(b);
        jb_kstr(b, "name", names[i]);
        jb_kbool(b, "template", names[i][0] == '%');
        if (names[i][0] != '%') {
            const struct link_info *li = ns_active() ? link_by_name(names[i]) : NULL;
            jb_kbool(b, "present", li != NULL);
            if (li) { jb_kint(b, "ifindex", li->index); jb_kstr(b, "kind", li->kind); }
            else { jb_knull(b, "ifindex"); jb_knull(b, "kind"); }
        }
        jb_kint(b, "programs", progs);
        jb_kint(b, "files", files);
        jb_obj_end(b);
    }
    jb_arr_end(b);
    jb_obj_end(b);
    free(names);
}

static void rest_get_interface(struct http_response *resp, const char *name, int dir) {
    struct jbuf *b = &resp->body;
    jb_obj(b);
    jb_kstr(b, "name", name);
    jb_kbool(b, "template", name[0] == '%');
    if (dir >= 0) jb_kstr(b, "direction", dir_name(dir));
    if (name[0] != '%') json_link_details(b, name);
    jb_key(b, "programs");
    json_slots_of(b, name, dir, -1);
    jb_key(b, "files");
    json_sources_of(b, name, dir);
    jb_obj_end(b);
}

static void rest_get_file(struct http_response *resp, const char *scope, int dir, int prio) {
    char rel[IFNAMSIZ + 64], rpath[PATH_MAX + 80], cpath[PATH_MAX + 80];
    prog_rel(rel, sizeof(rel), scope, dir, prio);
    snprintf(rpath, sizeof(rpath), "%s/%s", cfg.rest_dir, rel);
    snprintf(cpath, sizeof(cpath), "%s/%s", cfg.config_dir, rel);
    const char *path = is_regular(rpath) ? rpath : is_regular(cpath) ? cpath : NULL;
    if (!path) {
        const struct slot *s = scope[0] != '%' ? slot_find(scope, dir, prio) : NULL;
        if (s && s->path[0])
            http_error(resp, 404, "no file %s; the program at %s %s%s%.0d comes from %s", rel, scope,
                       dir_name(dir), dir == DIR_XDP ? "" : " ", dir == DIR_XDP ? 0 : prio, s->path);
        else
            http_error(resp, 404, "no file %s in %s or %s", rel, cfg.rest_dir, cfg.config_dir);
        return;
    }
    char *data;
    size_t len;
    int rc = read_file(path, &data, &len, 16 * 1024 * 1024);
    if (rc < 0) { http_error(resp, 500, "cannot read %s: %s", path, strerror(-rc)); return; }
    jb_lines(&resp->body, data, len);
    free(data);
    http_add_header(resp, "X-Bpfc-File", path);
    http_add_header(resp, "X-Bpfc-Source", path == rpath ? "rest" : "config");
}

static int query_flag(const char *query, const char *name) {
    char v[16];
    if (!http_query_get(query, name, v, sizeof(v))) return 0;
    return strcasecmp(v, "false") && strcmp(v, "0") && strcasecmp(v, "no");
}

static void rest_put_file(const struct http_request *req, struct http_response *resp,
                          const char *scope, int dir, int prio) {
    char **lines;
    int nl;
    char err[256];
    if (json_parse_lines(req->body, req->body_len, &lines, &nl, err, sizeof(err)) < 0) {
        http_error(resp, 400, "%s", err);
        return;
    }
    /* The program text: the lines, each ending in a newline. */
    size_t total = 0;
    for (int i = 0; i < nl; i++) total += strlen(lines[i]) + 1;
    char *text = malloc(total + 1);
    if (!text) { json_lines_free(lines, nl); http_error(resp, 500, "out of memory"); return; }
    size_t off = 0;
    for (int i = 0; i < nl; i++) {
        size_t l = strlen(lines[i]);
        memcpy(text + off, lines[i], l);
        text[off + l] = '\n';
        off += l + 1;
    }
    text[off] = '\0';
    json_lines_free(lines, nl);
    int dry = query_flag(req->query, "dry-run") || query_flag(req->query, "dry_run");

    char rel[IFNAMSIZ + 64], target[PATH_MAX + 80], cpath[PATH_MAX + 80], tmp[PATH_MAX + 128], dirpath[PATH_MAX + 80];
    prog_rel(rel, sizeof(rel), scope, dir, prio);
    snprintf(target, sizeof(target), "%s/%s", cfg.rest_dir, rel);
    snprintf(cpath, sizeof(cpath), "%s/%s", cfg.config_dir, rel);
    snprintf(dirpath, sizeof(dirpath), "%s", target);
    *strrchr(dirpath, '/') = '\0';
    snprintf(tmp, sizeof(tmp), "%s/.%s.rest-%d.check", dirpath, strrchr(target, '/') + 1, (int)getpid());
    int rc = mkdir_p(dirpath, 0755);
    /* The candidate sits next to the target, so relative includes resolve the same. */
    if (rc == 0) rc = write_file_atomic(tmp, text, off);
    if (rc < 0) {
        http_error(resp, 500, "cannot write %s: %s", tmp, strerror(-rc));
        free(text);
        return;
    }
    int empty = file_is_empty(tmp);
    int overrides = is_regular(cpath);

    /* Check first: nothing changes for a program the kernel would refuse. */
    char (*targets)[IFNAMSIZ] = calloc((size_t)(nlinks ? nlinks : 1), IFNAMSIZ);
    int ntargets = targets ? check_targets(scope, dir, prio, targets, nlinks) : 0;
    int nchecks = empty ? 0 : dry ? (ntargets ? ntargets : 1) : 1;
    struct check *checks = calloc((size_t)(nchecks ? nchecks : 1), sizeof(*checks));
    int failed = -1;
    for (int i = 0; checks && i < nchecks; i++) {
        run_check(tmp, ntargets ? targets[i] : NULL, dir, prio, &checks[i]);
        if (!checks[i].ok && failed < 0) failed = i;
    }
    struct jbuf *b = &resp->body;
    if (!checks) { http_error(resp, 500, "out of memory"); goto out_tmp; }

    if (dry || failed >= 0) {
        resp->status = failed >= 0 ? 422 : 200;
        jb_obj(b);
        jb_kbool(b, "ok", failed < 0);
        if (dry) jb_kbool(b, "dry_run", 1);
        if (failed >= 0) {
            char msg[700];
            snprintf(msg, sizeof(msg), "the program was rejected%s%s: %s", checks[failed].iface[0] ? " on " : "",
                     checks[failed].iface, checks[failed].summary);
            jb_kstr(b, "error", msg);
            if (!dry) jb_kbool(b, "changed", 0);
        }
        jb_kstr(b, "file", target);
        jb_kstr(b, "overrides", overrides ? cpath : NULL);
        jb_kbool(b, "empty", empty);
        if (!ntargets && !dry) jb_kstr(b, "note", "no interface uses this file now; checked without one");
        if (dry && !empty) {
            jb_key(b, "applies_to");
            jb_arr(b);
            for (int i = 0; i < ntargets; i++) jb_str(b, targets[i]);
            jb_arr_end(b);
        }
        jb_key(b, "checks");
        jb_arr(b);
        for (int i = 0; i < nchecks; i++) json_check(b, &checks[i]);
        jb_arr_end(b);
        jb_obj_end(b);
        goto out_tmp;
    }

    /* Commit: keep the old file for a rollback, then swap the checked one in. */
    char *old = NULL;
    size_t oldlen = 0;
    int had_old = read_file(target, &old, &oldlen, 16 * 1024 * 1024) == 0;
    int changed = !had_old || oldlen != off || memcmp(old, text, off);
    if (rename(tmp, target) < 0) {
        http_error(resp, 500, "cannot write %s: %s", target, strerror(errno));
        free(old);
        goto out_tmp;
    }
    scan_dir();
    apply(0);
    schedule_verify();
    state_dirty = 1;

    /* Did it install everywhere it applies? */
    int nfail = 0;
    for (int i = 0; i < nslots; i++) if (!strcmp(slots[i].path, target) && slots[i].status == ST_FAILED) nfail++;
    if (nfail) {
        /* The reply lists the failures first: their logs are gone once the rollback reinstalls. */
        char (*fifs)[IFNAMSIZ] = calloc((size_t)nfail, IFNAMSIZ);
        int k = 0;
        const struct slot *f0 = NULL;
        for (int i = 0; i < nslots && !f0; i++)
            if (!strcmp(slots[i].path, target) && slots[i].status == ST_FAILED) f0 = &slots[i];
        char first[700];
        snprintf(first, sizeof(first), "installing failed on %s: %s", f0->iface, f0->error);
        resp->status = 422;
        jb_obj(b);
        jb_kbool(b, "ok", 0);
        jb_kstr(b, "error", first);
        jb_kstr(b, "file", target);
        jb_key(b, "failures");
        jb_arr(b);
        for (int i = 0; i < nslots; i++) {
            const struct slot *s = &slots[i];
            if (strcmp(s->path, target) || s->status != ST_FAILED) continue;
            if (fifs) snprintf(fifs[k++], IFNAMSIZ, "%s", s->iface);
            char lp[PATH_MAX + 64];
            error_log_path(lp, sizeof(lp), cfg.state_dir, s->iface, s->dir, s->prio);
            char *log = NULL;
            size_t loglen = 0;
            read_file(lp, &log, &loglen, MAX_CAPTURE + 4096);
            jb_obj(b);
            jb_kstr(b, "interface", s->iface);
            jb_kstr(b, "error", s->error);
            jb_key(b, "output");
            jb_lines(b, log ? log : "", loglen);
            jb_obj_end(b);
            free(log);
        }
        jb_arr_end(b);

        int rb = had_old ? write_file_atomic(target, old, oldlen) : (unlink(target) < 0 ? -errno : 0);
        if (!had_old) prune_rest_dirs(scope, dir);
        if (rb < 0) logmsg(LOG_LVL_ERR, "rest: cannot restore %s: %s", target, strerror(-rb));
        scan_dir();
        apply(0);
        schedule_verify();
        logmsg(LOG_LVL_WARN, "rest: %s: %s; %s", target, first,
               rb < 0 ? "restoring the previous file failed" : had_old ? "the previous file is back" : "removed it again");
        jb_kbool(b, "rolled_back", rb == 0);
        jb_kstr(b, "restored", rb == 0 ? (had_old ? "previous file" : "no file (there was none)") : NULL);
        jb_key(b, "programs");
        jb_arr(b);
        for (int i = 0; i < nslots; i++) {
            const struct slot *s = &slots[i];
            if (s->dir != dir || s->prio != prio) continue;
            for (int j = 0; fifs && j < k; j++) if (!strcmp(s->iface, fifs[j])) { json_slot(b, s, rest_ctx()); break; }
        }
        jb_arr_end(b);
        jb_obj_end(b);
        free(fifs);
        free(old);
        goto out;
    }

    resp->status = had_old ? 200 : 201;
    jb_obj(b);
    jb_kbool(b, "ok", 1);
    jb_kstr(b, "file", target);
    jb_kbool(b, "created", !had_old);
    jb_kbool(b, "changed", changed);
    jb_kstr(b, "overrides", overrides ? cpath : NULL);
    jb_kbool(b, "empty", empty);
    int nprogs = 0, npending = 0;
    for (int i = 0; i < nslots; i++)
        if (!strcmp(slots[i].path, target)) { nprogs++; if (slots[i].status == ST_PENDING) npending++; }
    if (!ns_active())
        jb_kstr(b, "note", "the network namespace is not there yet; the program is installed when it is");
    else if (!nprogs)
        jb_kstr(b, "note", "no interface uses this file now (none matches, or a more specific file wins); "
                           "it is installed when one does");
    else if (npending == nprogs)
        jb_kstr(b, "note", "the interface is not present; the program is installed when it appears");
    jb_key(b, "checks");
    jb_arr(b);
    for (int i = 0; i < nchecks; i++) json_check(b, &checks[i]);
    jb_arr_end(b);
    jb_key(b, "programs");
    jb_arr(b);
    for (int i = 0; i < nslots; i++) if (!strcmp(slots[i].path, target)) json_slot(b, &slots[i], rest_ctx());
    jb_arr_end(b);
    jb_obj_end(b);
    free(old);
    goto out;

out_tmp:
    unlink(tmp);
    if (!is_regular(target)) prune_rest_dirs(scope, dir);   /* directories made only for the check */
out:
    for (int i = 0; checks && i < nchecks; i++) free(checks[i].out);
    free(checks);
    free(targets);
    free(text);
}

static void rest_delete_file(struct http_response *resp, const char *scope, int dir, int prio) {
    char rel[IFNAMSIZ + 64], target[PATH_MAX + 80], cpath[PATH_MAX + 80];
    prog_rel(rel, sizeof(rel), scope, dir, prio);
    snprintf(target, sizeof(target), "%s/%s", cfg.rest_dir, rel);
    snprintf(cpath, sizeof(cpath), "%s/%s", cfg.config_dir, rel);
    struct stat st;
    if (lstat(target, &st) < 0) {
        if (is_regular(cpath))
            http_error(resp, 409, "%s is in config_dir; the REST API only removes files in %s", cpath, cfg.rest_dir);
        else
            http_error(resp, 404, "no file %s in %s", rel, cfg.rest_dir);
        return;
    }
    if (unlink(target) < 0) { http_error(resp, 500, "cannot remove %s: %s", target, strerror(errno)); return; }
    prune_rest_dirs(scope, dir);
    scan_dir();
    apply(0);
    schedule_verify();
    state_dirty = 1;
    struct jbuf *b = &resp->body;
    jb_obj(b);
    jb_kbool(b, "ok", 1);
    jb_kstr(b, "deleted", target);
    jb_kstr(b, "now_from", is_regular(cpath) ? cpath : NULL);
    jb_key(b, "programs");
    json_slots_of(b, scope, dir, prio);
    jb_obj_end(b);
}

/* ---- routing ---- */

#define REST_MAX_SEGS 5

static void rest_route(const struct http_request *req, struct http_response *resp) {
    char seg[REST_MAX_SEGS][IFNAMSIZ + 40];
    int ns = 0;
    for (const char *p = req->path; *p; ) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *e = strchr(p, '/');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (ns == REST_MAX_SEGS) { http_error(resp, 404, "no such resource"); return; }
        if (http_unescape(p, l, seg[ns], sizeof(seg[ns])) < 0) {
            http_error(resp, 400, "invalid path segment (too long, or an encoded '/' or NUL)");
            return;
        }
        ns++;
        p += l;
    }
    const char *m = req->method;
    int get = !strcmp(m, "GET") || !strcmp(m, "HEAD");
    if (ns == 0) {
        if (!get) { http_add_header(resp, "Allow", "GET, HEAD"); http_error(resp, 405, "/ is read-only"); return; }
        rest_get_root(resp);
        return;
    }
    if (strcmp(seg[0], "interfaces")) {
        http_error(resp, 404, "no such resource; try / or /interfaces");
        return;
    }
    if (ns == 1) {
        if (!get) { http_add_header(resp, "Allow", "GET, HEAD"); http_error(resp, 405, "read-only resource"); return; }
        rest_get_interfaces(resp);
        return;
    }
    const char *name = seg[1];
    if (!(name[0] == '%' ? valid_template_name(name) : valid_ifname(name))) {
        http_error(resp, 404, "'%s' is not a valid interface name, %%all%% or %%<kind>%%", name);
        return;
    }
    if (ns == 2) {
        if (!get) { http_add_header(resp, "Allow", "GET, HEAD"); http_error(resp, 405, "read-only resource"); return; }
        rest_get_interface(resp, name, -1);
        return;
    }
    int dir = dir_parse(seg[2]);
    if (dir < 0) { http_error(resp, 404, "'%s' is not ingress, egress or xdp", seg[2]); return; }
    int prio = 0;
    if (dir == DIR_XDP) {
        if (ns != 3) { http_error(resp, 404, "the XDP program has no priority: use /interfaces/%s/xdp", name); return; }
    } else if (ns == 3) {
        if (!get) { http_add_header(resp, "Allow", "GET, HEAD"); http_error(resp, 405, "read-only resource; add /<priority>"); return; }
        rest_get_interface(resp, name, dir);
        return;
    } else {
        if (ns > 4) { http_error(resp, 404, "no such resource"); return; }
        const char *p = seg[3];
        long v = 0;
        int okp = *p && *p != '0';
        for (; okp && *p; p++) {
            if (*p < '0' || *p > '9') okp = 0;
            else if ((v = v * 10 + (*p - '0')) > 65535) okp = 0;
        }
        if (!okp || v < 1) { http_error(resp, 404, "priority must be 1-65535 without leading zeros"); return; }
        prio = (int)v;
    }
    if (get) rest_get_file(resp, name, dir, prio);
    else if (!strcmp(m, "POST") || !strcmp(m, "PUT")) rest_put_file(req, resp, name, dir, prio);
    else if (!strcmp(m, "DELETE")) rest_delete_file(resp, name, dir, prio);
    else {
        http_add_header(resp, "Allow", "GET, HEAD, POST, PUT, DELETE");
        http_error(resp, 405, "method %s not allowed here", m);
    }
}

static void rest_handle(const struct http_request *req, struct http_response *resp) {
    rest_route(req, resp);
    int mutating = strcmp(req->method, "GET") && strcmp(req->method, "HEAD");
    logmsg(mutating ? LOG_LVL_INFO : LOG_LVL_DEBUG, "rest: %s %s%s%s from uid %d pid %d: %d", req->method,
           req->path, req->query ? "?" : "", req->query ? req->query : "", (int)req->peer_uid,
           (int)req->peer_pid, resp->status);
    if (state_dirty) write_state();
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
    rest_stop();
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
    char err[512] = "";
    if (config_resolve(netns_arg, conf_override, &nc, conf_path, sizeof(conf_path), err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "%s; keeping the previous settings", err);
        return -1;
    }
    int ns_moved = strcmp(nc.netns_path, cfg.netns_path) || strcmp(nc.netns_veth, cfg.netns_veth);
    if (strcmp(nc.state_dir, cfg.state_dir)) {
        logmsg(LOG_LVL_WARN, "state_dir changes take effect after a restart");
        snprintf(nc.state_dir, sizeof(nc.state_dir), "%s", cfg.state_dir);
    }
    if (strcmp(nc.map_dir, cfg.map_dir))
        logmsg(LOG_LVL_INFO, "map_dir changed; it applies to programs installed from now on");
    if (cfg.netns[0] && strcmp(nc.map_dir, cfg.map_dir)) {
        int rc = mkdir_p(nc.map_dir, 0700);
        if (rc < 0) logmsg(LOG_LVL_WARN, "cannot create map directory %s: %s", nc.map_dir, strerror(-rc));
    }
    if (strcmp(nc.rest_dir, cfg.rest_dir))
        logmsg(LOG_LVL_INFO, "rest_dir changed to %s; programs in %s no longer apply", nc.rest_dir, cfg.rest_dir);
    cfg = nc;
    log_set_level(cfg.log_level);
    rest_reconfigure();
    if (ns_moved && cfg.netns[0]) {
        logmsg(LOG_LVL_INFO, "netns %s: netns_path/netns_veth changed; looking for the namespace again", cfg.netns);
        ns_check(0);
    }
    return 0;
}

static int check_only(void) {
    /* -t: validate bpfc.conf and the directory layout without touching the kernel. */
    load_links();
    scan_dir();
    qsort(slots, nslots, sizeof(*slots), slot_cmp);
    printf("config:   %s\nprograms: %s\n          %s (REST, overrides the above)\n", conf_path, cfg.config_dir,
           cfg.rest_dir);
    if (cfg.rest_socket[0]) {
        uid_t u;
        gid_t g;
        char err[512];
        int rc = rest_owner_resolve(cfg.rest_owner, &u, &g, err, sizeof(err));
        printf("rest:     %s (owner %s = %u:%u, mode %04o)%s%s\n", cfg.rest_socket, cfg.rest_owner,
               rc == 0 ? (unsigned)u : 0, rc == 0 ? (unsigned)g : 0, cfg.rest_mode, rc < 0 ? "\n          error: " : "",
               rc < 0 ? err : "");
    } else {
        printf("rest:     off (no rest_socket)\n");
    }
    if (cfg.netns[0]) {
        printf("netns:    %s\nstate:    %s\nmaps:     %s\n", cfg.netns, cfg.state_dir, cfg.map_dir);
        struct netns_loc loc;
        int rc = netns_locate(&cfg, host_rtnl, &loc);
        printf("found:    %s%s\n", rc == 0 ? "" : "no: ", loc.desc);
        if (rc == 0) {
            if (setns(loc.fd, CLONE_NEWNET) < 0)
                printf("          (cannot enter it to check interfaces: %s)\n", strerror(errno));
            netns_loc_close(&loc);
        } else {
            printf("          (interfaces below are checked in the current namespace)\n");
        }
    }
    for (int i = 0; i < nslots; i++) {
        struct slot *s = &slots[i];
        if (!s->seen) continue;
        printf("  %-15s %-7s prio %-5d sha256 %.12s  %s%s\n", s->iface, dir_name(s->dir), s->prio,
               s->sha256, s->path, s->excluded ? "  (excluded: empty file)" :
               if_nametoindex(s->iface) ? "" : "  (interface not present)");
    }
    if (!nslots) printf("  (no programs found)\n");
    return 0;
}

static void usage(const char *argv0) {
    printf("Usage: %s [options]\n"
           "  -n, --netns <name>   manage network namespace <name>, configured from\n"
           "                       %s/netns/<name>/ (see bpfcd(8), NETWORK NAMESPACES)\n"
           "  -c, --config <file>  configuration file (default %s)\n"
           "  -b, --background     daemonize and log to syslog (non-systemd systems)\n"
           "  -D, --debug          log debug messages\n"
           "  -t, --test           check the configuration and list programs, then exit\n"
           "  -V, --version        print version\n"
           "  -h, --help           this help\n"
           "Signals: SIGHUP rescans %s and bpfc.conf; SIGTERM/SIGINT stop.\n",
           argv0, DEFAULT_CONF_ROOT, DEFAULT_CONF_PATH, DEFAULT_CONFIG_DIR);
}

int main(int argc, char **argv) {
    int background = 0, debug = 0, test = 0;
    static const struct option longopts[] = {
        {"config", required_argument, 0, 'c'}, {"background", no_argument, 0, 'b'},
        {"netns", required_argument, 0, 'n'},
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
    while ((o = getopt_long(argc, argv, "c:n:bDtVh", longopts, NULL)) != -1) {
        switch (o) {
        case 'c': conf_override = optarg; break;
        case 'n': netns_arg = optarg; break;
        case 'b': background = 1; break;
        case 'D': debug = 1; break;
        case 't': test = 1; break;
        case 'V': printf("bpfcd %s\n", BPFC_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }

    log_init("bpfcd", LOG_TO_STDERR, LOG_LVL_INFO);
    char err[512] = "";
    if (config_resolve(netns_arg, conf_override, &cfg, conf_path, sizeof(conf_path), err, sizeof(err)) < 0) {
        logmsg(LOG_LVL_ERR, "%s", err);
        return 1;
    }
    if (debug) cfg.log_level = LOG_LVL_DEBUG;
    log_set_level(cfg.log_level);
    if (cfg.netns[0]) {
        /* Taken before entering any namespace: the way back, and the host side of netns_veth. */
        host_nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        host_rtnl = netns_host_socket();
        if (host_nsfd < 0 || host_rtnl < 0) {
            logmsg(LOG_LVL_ERR, "cannot open the current network namespace: %s",
                   strerror(host_nsfd < 0 ? errno : -host_rtnl));
            return 1;
        }
    }
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
    /* bpfc does not create its map directory; a namespace's default one is new. */
    if (cfg.netns[0] && cfg.map_dir[0] && (rc = mkdir_p(cfg.map_dir, 0700)) < 0)
        logmsg(LOG_LVL_WARN, "cannot create map directory %s: %s (programs using maps will fail)",
               cfg.map_dir, strerror(-rc));
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
    /* The monitor is opened before the first scan so no interface event is missed.
     * In a namespace it is opened on entering it (ns_enter). */
    if (!cfg.netns[0]) nlfd = open_monitor();
    else nstfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (sigfd < 0 || tfd < 0 || (cfg.netns[0] ? nstfd < 0 : nlfd < 0)) {
        logmsg(LOG_LVL_ERR, "setup failed: %s", strerror(nlfd < 0 ? -nlfd : errno));
        release_pidfile();
        return 1;
    }

    memset(&dinfo, 0, sizeof(dinfo));
    dinfo.pid = (int)getpid();
    dinfo.started = time(NULL);
    snprintf(dinfo.version, sizeof(dinfo.version), "%s", BPFC_VERSION);

    logmsg(LOG_LVL_INFO, "bpfcd %s starting%s%s%s; programs from %s, external changes: %s",
           BPFC_VERSION, is_init ? " as PID 1" : "", cfg.netns[0] ? " for network namespace " : "",
           cfg.netns, cfg.config_dir, cfg.on_external_change == EXT_LOG ? "log" : "reinstall");
    if (cfg.netns[0]) {
        ns_set_waiting("not looked for yet");
        scan_dir();          /* the programs show as pending until the namespace is found */
        apply(0);
        ns_check(1);
        ns_start_timer();
    } else {
        load_links();
        scan_dir();
        adopt_previous_state();
        apply(0);
        verify_all();
    }
    dinfo.last_reload = time(NULL);
    rest_start();
    write_state();
    notify_status("READY=1\n");

    int running = 1;
    while (running) {
        struct pollfd pfd[4 + HTTP_MAX_POLLFDS] = {
            {.fd = sigfd, .events = POLLIN}, {.fd = nlfd, .events = POLLIN}, {.fd = tfd, .events = POLLIN},
            {.fd = nstfd, .events = POLLIN}};   /* negative fds (no monitor, no namespace) are skipped */
        struct http_server *polled = rest_srv;
        int nh = polled ? http_pollfds(polled, pfd + 4, HTTP_MAX_POLLFDS) : 0;
        if (poll(pfd, 4 + nh, polled ? http_timeout_ms(polled) : -1) < 0) {
            if (errno == EINTR) continue;
            logmsg(LOG_LVL_ERR, "poll: %s", strerror(errno));
            break;
        }
        /* REST first: a reload below may replace the server these pollfds belong to. */
        if (polled) http_process(polled, pfd + 4, nh);
        if (pfd[1].revents & POLLIN) handle_netlink();
        if (pfd[2].revents & POLLIN) {
            uint64_t exp;
            if (read(tfd, &exp, sizeof(exp)) < 0) { /* spurious */ }
            verify_pending = 0;
            verify_all();
        }
        if (pfd[3].revents & POLLIN) {
            uint64_t exp;
            if (read(nstfd, &exp, sizeof(exp)) < 0) { /* spurious */ }
            ns_check(0);
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
                    if (cfg.netns[0]) ns_check(0);   /* a reload also looks for a missing namespace */
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
