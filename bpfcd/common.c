/*
 * Shared code for bpfcd (daemon) and bpfcctl (status tool).
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>

/* ======================= small helpers ======================= */

const char *dir_name(int dir) { return dir == DIR_EGRESS ? "egress" : "ingress"; }

int dir_parse(const char *s) {
    if (!strcmp(s, "ingress")) return DIR_INGRESS;
    if (!strcmp(s, "egress")) return DIR_EGRESS;
    return -1;
}

static const char *const status_names[ST__COUNT] = {
    [ST_INSTALLED] = "installed",
    [ST_PENDING] = "pending-iface",
    [ST_FAILED] = "failed",
    [ST_REMOVED_EXT] = "removed-externally",
    [ST_REPLACED_EXT] = "replaced-externally",
    [ST_DISABLED] = "reinstall-limit",
};

const char *status_name(int st) {
    return (st >= 0 && st < ST__COUNT) ? status_names[st] : "unknown";
}

int status_parse(const char *s) {
    for (int i = 0; i < ST__COUNT; i++)
        if (!strcmp(s, status_names[i])) return i;
    return -1;
}

int mkdir_p(const char *path, int mode) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -errno;
        *p = '/';
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -errno;
    return 0;
}

int valid_ifname(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n >= IFNAMSIZ) return 0;
    if (!strcmp(s, ".") || !strcmp(s, "..")) return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c <= ' ' || c == '/' || c == ':' || c >= 0x7f) return 0;
    }
    return 1;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

/* ======================= logging ======================= */

static enum log_target log_target_cur = LOG_TO_STDERR;
static int log_max = LOG_LVL_INFO;
static int log_journal = 0;

void log_init(const char *ident, enum log_target target, int max_level) {
    log_target_cur = target;
    log_max = max_level;
    /* systemd sets JOURNAL_STREAM when stderr is connected to the journal. */
    log_journal = getenv("JOURNAL_STREAM") != NULL;
    if (target == LOG_TO_SYSLOG) openlog(ident, LOG_PID, LOG_DAEMON);
}

void log_set_level(int max_level) { log_max = max_level; }

int log_level_parse(const char *s) {
    if (!strcmp(s, "error")) return LOG_LVL_ERR;
    if (!strcmp(s, "warning") || !strcmp(s, "warn")) return LOG_LVL_WARN;
    if (!strcmp(s, "info")) return LOG_LVL_INFO;
    if (!strcmp(s, "debug")) return LOG_LVL_DEBUG;
    return -1;
}

void logmsg(int level, const char *fmt, ...) {
    if (level > log_max) return;
    va_list ap;
    va_start(ap, fmt);
    if (log_target_cur == LOG_TO_SYSLOG) {
        vsyslog(level, fmt, ap);
    } else {
        if (log_journal) {
            fprintf(stderr, "<%d>", level);
        } else {
            const char *tag = level <= LOG_LVL_ERR ? "error: " : level == LOG_LVL_WARN ? "warning: "
                            : level == LOG_LVL_DEBUG ? "debug: " : "";
            fputs(tag, stderr);
        }
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
}

/* ======================= configuration ======================= */

void config_defaults(struct config *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->bpfc_path, sizeof(c->bpfc_path), "%s", DEFAULT_BPFC_PATH);
    snprintf(c->config_dir, sizeof(c->config_dir), "%s", DEFAULT_CONFIG_DIR);
    snprintf(c->state_dir, sizeof(c->state_dir), "%s", DEFAULT_STATE_DIR);
    c->on_external_change = EXT_REINSTALL;
    c->remove_on_stop = 0;
    c->reinstall_limit = 5;
    c->compile_timeout = 30;
    c->log_level = LOG_LVL_INFO;
}

static int parse_bool(const char *v, int *out) {
    if (!strcasecmp(v, "yes") || !strcasecmp(v, "true") || !strcmp(v, "1") || !strcasecmp(v, "on")) {
        *out = 1; return 0;
    }
    if (!strcasecmp(v, "no") || !strcasecmp(v, "false") || !strcmp(v, "0") || !strcasecmp(v, "off")) {
        *out = 0; return 0;
    }
    return -1;
}

static int parse_int(const char *v, int lo, int hi, int *out) {
    char *end;
    errno = 0;
    long n = strtol(v, &end, 10);
    if (errno || *end || end == v || n < lo || n > hi) return -1;
    *out = (int)n;
    return 0;
}

int config_load(const char *path, struct config *c, char *err, size_t errlen) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        return -1;
    }
    char line[PATH_MAX + 128];
    int lineno = 0, rc = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *s = trim(line);
        if (!*s) continue;
        char *eq = strchr(s, '=');
        if (!eq) {
            snprintf(err, errlen, "%s:%d: expected 'key = value'", path, lineno);
            rc = -1; break;
        }
        *eq = '\0';
        char *k = trim(s), *v = trim(eq + 1);
        int bad = 0;
        if (!strcmp(k, "bpfc_path")) snprintf(c->bpfc_path, sizeof(c->bpfc_path), "%s", v);
        else if (!strcmp(k, "config_dir")) snprintf(c->config_dir, sizeof(c->config_dir), "%s", v);
        else if (!strcmp(k, "state_dir")) snprintf(c->state_dir, sizeof(c->state_dir), "%s", v);
        else if (!strcmp(k, "map_dir")) snprintf(c->map_dir, sizeof(c->map_dir), "%s", v);
        else if (!strcmp(k, "on_external_change")) {
            if (!strcmp(v, "reinstall")) c->on_external_change = EXT_REINSTALL;
            else if (!strcmp(v, "log")) c->on_external_change = EXT_LOG;
            else bad = 1;
        } else if (!strcmp(k, "remove_on_stop")) bad = parse_bool(v, &c->remove_on_stop) < 0;
        else if (!strcmp(k, "reinstall_limit")) bad = parse_int(v, 0, 1000, &c->reinstall_limit) < 0;
        else if (!strcmp(k, "compile_timeout")) bad = parse_int(v, 1, 3600, &c->compile_timeout) < 0;
        else if (!strcmp(k, "log_level")) {
            int l = log_level_parse(v);
            if (l < 0) bad = 1; else c->log_level = l;
        } else {
            snprintf(err, errlen, "%s:%d: unknown setting '%s'", path, lineno, k);
            rc = -1; break;
        }
        if (bad) {
            snprintf(err, errlen, "%s:%d: invalid value '%s' for %s", path, lineno, v, k);
            rc = -1; break;
        }
    }
    fclose(f);
    if (rc == 0 && c->bpfc_path[0] != '/') {
        snprintf(err, errlen, "%s: bpfc_path must be an absolute path", path);
        rc = -1;
    }
    return rc;
}

/* ======================= SHA-256 (FIPS 180-4) ======================= */

struct sha256_ctx { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t blen; };

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 | (uint32_t)p[i*4+2] << 8 | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e,6) ^ ROR(e,11) ^ ROR(e,25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a,2) ^ ROR(a,13) ^ ROR(a,22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(struct sha256_ctx *c) {
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0; c->blen = 0;
}

static void sha256_update(struct sha256_ctx *c, const uint8_t *p, size_t n) {
    c->len += n;
    while (n) {
        size_t take = 64 - c->blen < n ? 64 - c->blen : n;
        memcpy(c->buf + c->blen, p, take);
        c->blen += take; p += take; n -= take;
        if (c->blen == 64) { sha256_block(c, c->buf); c->blen = 0; }
    }
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->blen != 56) sha256_update(c, &pad, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4] = c->h[i] >> 24; out[i*4+1] = c->h[i] >> 16;
        out[i*4+2] = c->h[i] >> 8; out[i*4+3] = c->h[i];
    }
}

int sha256_file(const char *path, char out_hex[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    struct sha256_ctx c;
    sha256_init(&c);
    uint8_t buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            int e = -errno; close(fd); return e;
        }
        sha256_update(&c, buf, (size_t)n);
    }
    close(fd);
    uint8_t d[32];
    sha256_final(&c, d);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i * 2, "%02x", d[i]);
    out_hex[64] = '\0';
    return 0;
}

/* ======================= state file ======================= */

/*
 * Format, one record per line, values percent-encoded:
 *   # comment
 *   daemon pid=.. started=.. last_reload=.. reload_count=.. version=.. config_dir=.. on_external_change=..
 *   slot iface=.. dir=.. prio=.. path=.. mtime_ns=.. sha256=.. status=.. ifindex=..
 *        prog_id=.. tag=.. insns=.. installed_at=.. changed_at=.. error=..
 * Unknown keys are ignored so newer daemons stay readable by older tools.
 */

static void put_enc(FILE *f, const char *key, const char *val) {
    fprintf(f, " %s=", key);
    if (!*val) { fputc('-', f); return; }
    for (const unsigned char *p = (const unsigned char *)val; *p; p++) {
        if (*p <= ' ' || *p == '%' || *p == '=' || *p >= 0x7f || (*p == '-' && p == (const unsigned char *)val && !p[1]))
            fprintf(f, "%%%02X", *p);
        else
            fputc(*p, f);
    }
}

static void decode_into(char *dst, size_t dstlen, const char *src) {
    size_t o = 0;
    if (!strcmp(src, "-")) { dst[0] = '\0'; return; }
    for (const char *p = src; *p && o + 1 < dstlen; p++) {
        if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
            char hx[3] = {p[1], p[2], 0};
            dst[o++] = (char)strtol(hx, NULL, 16);
            p += 2;
        } else {
            dst[o++] = *p;
        }
    }
    dst[o] = '\0';
}

int state_write(const char *path, const struct daemon_info *di,
                const struct slot *slots, int nslots) {
    char tmp[PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -errno;
    FILE *f = fdopen(fd, "w");
    if (!f) { int e = -errno; close(fd); return e; }
    char num[64];

    fprintf(f, "# bpfcd state v1 -- written by bpfcd, read by bpfcctl; do not edit\n");
    fprintf(f, "daemon");
    snprintf(num, sizeof(num), "%d", di->pid); put_enc(f, "pid", num);
    snprintf(num, sizeof(num), "%lld", (long long)di->started); put_enc(f, "started", num);
    snprintf(num, sizeof(num), "%lld", (long long)di->last_reload); put_enc(f, "last_reload", num);
    snprintf(num, sizeof(num), "%u", di->reload_count); put_enc(f, "reload_count", num);
    put_enc(f, "version", di->version);
    put_enc(f, "config_dir", di->config_dir);
    put_enc(f, "on_external_change", di->on_external_change == EXT_LOG ? "log" : "reinstall");
    fputc('\n', f);

    for (int i = 0; i < nslots; i++) {
        const struct slot *s = &slots[i];
        fprintf(f, "slot");
        put_enc(f, "iface", s->iface);
        put_enc(f, "dir", dir_name(s->dir));
        snprintf(num, sizeof(num), "%d", s->prio); put_enc(f, "prio", num);
        put_enc(f, "path", s->path);
        snprintf(num, sizeof(num), "%lld", (long long)s->mtime_ns); put_enc(f, "mtime_ns", num);
        put_enc(f, "sha256", s->sha256);
        put_enc(f, "status", status_name(s->status));
        snprintf(num, sizeof(num), "%d", s->ifindex); put_enc(f, "ifindex", num);
        snprintf(num, sizeof(num), "%u", s->prog_id); put_enc(f, "prog_id", num);
        put_enc(f, "tag", s->tag);
        snprintf(num, sizeof(num), "%u", s->insns); put_enc(f, "insns", num);
        snprintf(num, sizeof(num), "%lld", (long long)s->installed_at); put_enc(f, "installed_at", num);
        snprintf(num, sizeof(num), "%lld", (long long)s->changed_at); put_enc(f, "changed_at", num);
        put_enc(f, "error", s->error);
        fputc('\n', f);
    }
    if (fflush(f) != 0 || fsync(fd) != 0) { int e = -errno; fclose(f); unlink(tmp); return e; }
    if (fclose(f) != 0) { int e = -errno; unlink(tmp); return e; }
    if (rename(tmp, path) < 0) { int e = -errno; unlink(tmp); return e; }
    return 0;
}

int state_read(const char *path, struct daemon_info *di, struct slot **slots_out) {
    FILE *f = fopen(path, "r");
    if (!f) return -errno;
    memset(di, 0, sizeof(*di));
    struct slot *slots = NULL;
    int n = 0, cap = 0;
    char *line = NULL;
    size_t llen = 0;
    char val[PATH_MAX];

    while (getline(&line, &llen, f) > 0) {
        char *save = NULL;
        char *rec = strtok_r(line, " \n", &save);
        if (!rec || rec[0] == '#') continue;
        int is_slot = !strcmp(rec, "slot");
        if (!is_slot && strcmp(rec, "daemon")) continue;
        struct slot *s = NULL;
        if (is_slot) {
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                struct slot *ns = realloc(slots, cap * sizeof(*slots));
                if (!ns) { free(slots); free(line); fclose(f); return -ENOMEM; }
                slots = ns;
            }
            s = &slots[n++];
            memset(s, 0, sizeof(*s));
            s->status = -1;
        }
        for (char *kv; (kv = strtok_r(NULL, " \n", &save));) {
            char *eq = strchr(kv, '=');
            if (!eq) continue;
            *eq = '\0';
            const char *k = kv;
            decode_into(val, sizeof(val), eq + 1);
            if (!is_slot) {
                if (!strcmp(k, "pid")) di->pid = atoi(val);
                else if (!strcmp(k, "started")) di->started = (time_t)atoll(val);
                else if (!strcmp(k, "last_reload")) di->last_reload = (time_t)atoll(val);
                else if (!strcmp(k, "reload_count")) di->reload_count = (unsigned)strtoul(val, NULL, 10);
                else if (!strcmp(k, "version")) snprintf(di->version, sizeof(di->version), "%s", val);
                else if (!strcmp(k, "config_dir")) snprintf(di->config_dir, sizeof(di->config_dir), "%s", val);
                else if (!strcmp(k, "on_external_change")) di->on_external_change = strcmp(val, "log") ? EXT_REINSTALL : EXT_LOG;
                continue;
            }
            if (!strcmp(k, "iface")) snprintf(s->iface, sizeof(s->iface), "%s", val);
            else if (!strcmp(k, "dir")) s->dir = dir_parse(val) == DIR_EGRESS ? DIR_EGRESS : DIR_INGRESS;
            else if (!strcmp(k, "prio")) s->prio = atoi(val);
            else if (!strcmp(k, "path")) snprintf(s->path, sizeof(s->path), "%s", val);
            else if (!strcmp(k, "mtime_ns")) s->mtime_ns = atoll(val);
            else if (!strcmp(k, "sha256")) snprintf(s->sha256, sizeof(s->sha256), "%s", val);
            else if (!strcmp(k, "status")) s->status = status_parse(val);
            else if (!strcmp(k, "ifindex")) s->ifindex = atoi(val);
            else if (!strcmp(k, "prog_id")) s->prog_id = (uint32_t)strtoul(val, NULL, 10);
            else if (!strcmp(k, "tag")) snprintf(s->tag, sizeof(s->tag), "%s", val);
            else if (!strcmp(k, "insns")) s->insns = (uint32_t)strtoul(val, NULL, 10);
            else if (!strcmp(k, "installed_at")) s->installed_at = (time_t)atoll(val);
            else if (!strcmp(k, "changed_at")) s->changed_at = (time_t)atoll(val);
            else if (!strcmp(k, "error")) snprintf(s->error, sizeof(s->error), "%s", val);
        }
        /* Drop records missing their identity rather than guessing. */
        if (s && (!s->iface[0] || s->prio <= 0 || s->status < 0)) n--;
    }
    free(line);
    fclose(f);
    *slots_out = slots;
    return n;
}

void error_log_path(char *out, size_t outlen, const char *state_dir,
                    const char *iface, int dir, int prio) {
    snprintf(out, outlen, "%s/%s/%s.%s.%d.log", state_dir, ERROR_DIR_NAME, iface, dir_name(dir), prio);
}

/* ======================= TC filter dump ======================= */

int tc_dump_filters(int ifindex, int dir, struct tc_filter **out) {
    *out = NULL;
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return -errno;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(s); return e; }

    struct { struct nlmsghdr n; struct tcmsg t; } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_type = RTM_GETTFILTER;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = (uint32_t)time(NULL);
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, dir == DIR_EGRESS ? TC_H_MIN_EGRESS : TC_H_MIN_INGRESS);
    if (sendto(s, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = -errno; close(s); return e;
    }

    struct tc_filter *v = NULL;
    int n = 0, cap = 0, rc = 0, done = 0;
    char *buf = malloc(65536);
    if (!buf) { close(s); return -ENOMEM; }
    while (!done) {
        ssize_t len = recv(s, buf, 65536, 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            rc = -errno; break;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != req.n.nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if (h->nlmsg_type == NLMSG_ERROR) {
                int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                /* No clsact qdisc: nothing attached. */
                if (e != -EINVAL && e != -ENOENT) rc = e;
                done = 1; break;
            }
            if (h->nlmsg_type != RTM_NEWTFILTER) continue;
            struct tcmsg *tm = NLMSG_DATA(h);
            if (tm->tcm_handle == 0) continue; /* per-priority chain header */
            if (n == cap) {
                cap = cap ? cap * 2 : 8;
                struct tc_filter *nv = realloc(v, cap * sizeof(*v));
                if (!nv) { rc = -ENOMEM; done = 1; break; }
                v = nv;
            }
            struct tc_filter *f = &v[n++];
            memset(f, 0, sizeof(*f));
            f->prio = TC_H_MAJ(tm->tcm_info) >> 16;
            f->proto = ntohs(TC_H_MIN(tm->tcm_info));
            f->handle = tm->tcm_handle;
            int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*tm));
            for (struct rtattr *a = (struct rtattr *)((char *)tm + NLMSG_ALIGN(sizeof(*tm)));
                 RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
                if (a->rta_type == TCA_KIND) {
                    snprintf(f->kind, sizeof(f->kind), "%s", (char *)RTA_DATA(a));
                } else if (a->rta_type == TCA_OPTIONS) {
                    int olen = RTA_PAYLOAD(a);
                    for (struct rtattr *o = RTA_DATA(a); RTA_OK(o, olen); o = RTA_NEXT(o, olen)) {
                        if (o->rta_type == TCA_BPF_ID && RTA_PAYLOAD(o) >= 4)
                            memcpy(&f->prog_id, RTA_DATA(o), 4);
                        else if (o->rta_type == TCA_BPF_NAME)
                            snprintf(f->name, sizeof(f->name), "%.*s", (int)RTA_PAYLOAD(o), (char *)RTA_DATA(o));
                    }
                }
            }
            /* Only a bpf classifier's options are interpreted above. */
            if (strcmp(f->kind, "bpf")) { f->prog_id = 0; f->name[0] = '\0'; }
        }
    }
    free(buf);
    close(s);
    if (rc < 0) { free(v); return rc; }
    *out = v;
    return n;
}

/* ======================= bpf program info ======================= */

#ifndef BPF_PROG_GET_FD_BY_ID
#define BPF_PROG_GET_FD_BY_ID 13
#endif
#ifndef BPF_OBJ_GET_INFO_BY_FD
#define BPF_OBJ_GET_INFO_BY_FD 15
#endif

static int sys_bpf(int cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int prog_get_details(uint32_t id, int want_insns, struct prog_details *out) {
    memset(out, 0, sizeof(*out));
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = id;
    int fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr);
    if (fd < 0) return -errno;

    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0) { int e = -errno; close(fd); return e; }

    out->id = info.id;
    for (int i = 0; i < 8; i++) sprintf(out->tag + i * 2, "%02x", info.tag[i]);
    snprintf(out->name, sizeof(out->name), "%.16s", info.name);
    out->xlated_len = info.xlated_prog_len;
    out->jited_len = info.jited_prog_len;
    out->load_time_ns = info.load_time;

    if (want_insns && info.xlated_prog_len) {
        uint32_t len = info.xlated_prog_len;
        void *insns = calloc(1, len);
        if (!insns) { close(fd); return -ENOMEM; }
        memset(&info, 0, sizeof(info));
        info.xlated_prog_len = len;
        info.xlated_prog_insns = (unsigned long)insns;
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (unsigned long)&info;
        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0) {
            /* Usually kernel.kptr_restrict / sysctl hardening; info is still useful. */
            free(insns);
        } else {
            out->xlated = insns;
            out->xlated_len = info.xlated_prog_len < len ? info.xlated_prog_len : len;
        }
    }
    close(fd);
    return 0;
}
