/*
 * acl.c - access lists as bpfcctl and bpfcd see them (see acl.h).
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "acl.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int sys_bpf(int cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* ------------------------------------------------------------ meta table */

static void add(struct acl_table *t, const struct acl_rule *r) {
    if (t->n == t->cap) {
        int c = t->cap ? t->cap * 2 : 64;
        struct acl_rule *n = realloc(t->r, (size_t)c * sizeof(*n));
        if (!n) return;
        t->r = n;
        t->cap = c;
    }
    t->r[t->n++] = *r;
}

static int load_file(struct acl_table *t, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    char type[16] = "", name[96] = "", dir[8] = "", iface[64] = "";
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "acl ", 4)) {
            if (sscanf(line + 4, "%15s %95s %7s %63s", type, name, dir, iface) != 4) type[0] = 0;
            continue;
        }
        if (strncmp(line, "acl-rule ", 9) || !type[0]) continue;
        struct acl_rule r;
        memset(&r, 0, sizeof(r));
        char keyhex[24];
        int off = 0;
        if (sscanf(line + 9, "%95s %15s %23s %15s %d %n", r.acl, r.seq, keyhex, r.action, &r.log, &off) < 5 || !off)
            continue;
        r.key = strtoull(keyhex, NULL, 16);
        snprintf(r.text, sizeof(r.text), "%s", line + 9 + off);
        /* the list's type, direction and interface: from its acl line */
        if (!strcmp(r.acl, name)) {
            snprintf(r.type, sizeof(r.type), "%s", type);
            snprintf(r.dir, sizeof(r.dir), "%s", dir);
            snprintf(r.iface, sizeof(r.iface), "%s", iface);
        }
        add(t, &r);
    }
    fclose(f);
    return 0;
}

/* acl lines come before their acl-rule lines, but one file can hold
 * several lists (IPv4, IPv6, MAC): load_file keeps the last acl line, so
 * read the acl lines of a file first and match each rule to its list. */
static int load_file2(struct acl_table *t, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    struct { char type[16], name[96], dir[8], iface[64]; } lists[8];
    int nl = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, "acl ", 4) && nl < 8 &&
            sscanf(line + 4, "%15s %95s %7s %63s", lists[nl].type, lists[nl].name, lists[nl].dir, lists[nl].iface) == 4)
            nl++;
    fclose(f);
    int first = t->n;
    if (load_file(t, path) < 0) return -1;
    for (int i = first; i < t->n; i++)
        for (int k = 0; k < nl; k++)
            if (!strcmp(t->r[i].acl, lists[k].name)) {
                snprintf(t->r[i].type, sizeof(t->r[i].type), "%s", lists[k].type);
                snprintf(t->r[i].dir, sizeof(t->r[i].dir), "%s", lists[k].dir);
                snprintf(t->r[i].iface, sizeof(t->r[i].iface), "%s", lists[k].iface);
            }
    return 0;
}

int acl_table_load(struct acl_table *t, const char *state_dir) {
    memset(t, 0, sizeof(*t));
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/meta", state_dir);
    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? 0 : -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.' || strstr(de->d_name, ".tmp")) continue;
        char p[PATH_MAX + 256];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        load_file2(t, p);
    }
    closedir(d);
    return 0;
}

void acl_table_free(struct acl_table *t) {
    free(t->r);
    memset(t, 0, sizeof(*t));
}

const struct acl_rule *acl_table_find(const struct acl_table *t, uint64_t key) {
    for (int i = 0; i < t->n; i++) if (t->r[i].key == key) return &t->r[i];
    return NULL;
}

/* ------------------------------------------------------------------ maps */

int acl_map_open(const char *map_dir, const char *name) {
    char p[PATH_MAX + 64];
    snprintf(p, sizeof(p), "%s/%s", map_dir, name);
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.pathname = (unsigned long)p;
    return sys_bpf(BPF_OBJ_GET, &a);
}

int acl_map_get(int fd, uint64_t key, uint64_t *val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key = (unsigned long)&key;
    a.value = (unsigned long)val;
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, &a) < 0 ? -1 : 0;
}

int acl_map_del(int fd, uint64_t key) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = (uint32_t)fd;
    a.key = (unsigned long)&key;
    return sys_bpf(BPF_MAP_DELETE_ELEM, &a) < 0 ? -1 : 0;
}

static uint32_t fd_map_id(int fd) {
    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = (uint32_t)fd;
    a.info.info_len = sizeof(info);
    a.info.info = (unsigned long)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) < 0) return 0;
    return info.id;
}

uint32_t acl_pinned_map_id(const char *map_dir, const char *name) {
    int fd = acl_map_open(map_dir, name);
    if (fd < 0) return 0;
    uint32_t id = fd_map_id(fd);
    close(fd);
    return id;
}

/* --------------------------------------------------------- show / clear */

static const char *heading(const char *type) {
    if (!strcmp(type, "standard")) return "Standard IP access list";
    if (!strcmp(type, "extended")) return "Extended IP access list";
    if (!strcmp(type, "ipv6")) return "IPv6 access list";
    if (!strcmp(type, "mac")) return "Extended MAC access list";
    return "Access list";
}

static int seq_cmp(const char *a, const char *b) {
    int ia = !strcmp(a, "implicit") ? INT_MAX : atoi(a), ib = !strcmp(b, "implicit") ? INT_MAX : atoi(b);
    return ia < ib ? -1 : ia > ib;
}

static int rule_cmp(const void *x, const void *y) {
    const struct acl_rule *a = x, *b = y;
    int c = strcmp(a->acl, b->acl);
    if (c) return c;
    c = strcmp(a->type, b->type);
    if (c) return c;
    return seq_cmp(a->seq, b->seq);
}

int acl_show(FILE *out, const char *state_dir, const char *map_dir, const char *name, const char *iface, int bytes) {
    struct acl_table t;
    if (acl_table_load(&t, state_dir) < 0) { fprintf(stderr, "bpfcctl: %s/meta: %s\n", state_dir, strerror(errno)); return 1; }
    int pfd = acl_map_open(map_dir, "BPFC_ACL_P"), bfd = acl_map_open(map_dir, "BPFC_ACL_B");
    int counters = pfd >= 0;
    if (!counters && t.n)
        fprintf(stderr, "bpfcctl: no counters (%s/BPFC_ACL_P: %s)\n", map_dir,
                errno == EPERM || errno == EACCES ? "run as root" : strerror(errno));
    /* one line per entry and list, summed over the interfaces it is applied on */
    qsort(t.r, (size_t)t.n, sizeof(*t.r), rule_cmp);
    int shown = 0;
    for (int i = 0; i < t.n;) {
        int j = i;
        while (j < t.n && !strcmp(t.r[j].acl, t.r[i].acl) && !strcmp(t.r[j].type, t.r[i].type)) j++;
        if (name && strcmp(t.r[i].acl, name)) { i = j; continue; }
        int any = 0;
        for (int k = i; k < j; k++) if (!iface || !strcmp(t.r[k].iface, iface)) any = 1;
        if (!any) { i = j; continue; }
        fprintf(out, "%s %s\n", heading(t.r[i].type), t.r[i].acl);
        shown++;
        for (int k = i; k < j;) {
            int m = k;
            uint64_t pk = 0, by = 0;
            while (m < j && !seq_cmp(t.r[m].seq, t.r[k].seq)) {
                if (!iface || !strcmp(t.r[m].iface, iface)) {
                    uint64_t v;
                    if (counters && !acl_map_get(pfd, t.r[m].key, &v)) pk += v;
                    if (bfd >= 0 && !acl_map_get(bfd, t.r[m].key, &v)) by += v;
                }
                m++;
            }
            const struct acl_rule *r = &t.r[k];
            int implicit = !strcmp(r->seq, "implicit");
            if (implicit && !pk) { k = m; continue; }
            char cnt[96] = "";
            if (pk) {
                int o = snprintf(cnt, sizeof(cnt), " (%llu match%s", (unsigned long long)pk, pk == 1 ? "" : "es");
                if (bytes) o += snprintf(cnt + o, sizeof(cnt) - (size_t)o, ", %llu bytes", (unsigned long long)by);
                snprintf(cnt + o, sizeof(cnt) - (size_t)o, ")");
            }
            if (implicit) fprintf(out, "    (implicit) %s%s\n", r->text, cnt);
            else if (!strcmp(r->type, "ipv6") || !strcmp(r->type, "mac"))
                fprintf(out, "    %s%s sequence %s\n", r->text, cnt, r->seq);
            else fprintf(out, "    %s %s%s\n", r->seq, r->text, cnt);
            k = m;
        }
        i = j;
    }
    if (!shown) fprintf(out, name ? "no access list %s is installed\n" : "no access lists are installed\n", name);
    if (pfd >= 0) close(pfd);
    if (bfd >= 0) close(bfd);
    acl_table_free(&t);
    return name && !shown ? 1 : 0;
}

int acl_clear(const char *state_dir, const char *map_dir, const char *name) {
    struct acl_table t;
    if (acl_table_load(&t, state_dir) < 0) return -1;
    int pfd = acl_map_open(map_dir, "BPFC_ACL_P"), bfd = acl_map_open(map_dir, "BPFC_ACL_B");
    if (pfd < 0) { acl_table_free(&t); return -1; }
    int n = 0;
    for (int i = 0; i < t.n; i++) {
        if (name && strcmp(t.r[i].acl, name)) continue;
        acl_map_del(pfd, t.r[i].key);
        if (bfd >= 0) acl_map_del(bfd, t.r[i].key);
        n++;
    }
    close(pfd);
    if (bfd >= 0) close(bfd);
    acl_table_free(&t);
    return n;
}

/* ------------------------------------------------------------------- top */

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

struct toprow { const struct acl_rule *r; double pps, bps; uint64_t total; };

static int top_cmp(const void *x, const void *y) {
    const struct toprow *a = x, *b = y;
    if (a->pps != b->pps) return a->pps < b->pps ? 1 : -1;
    return a->total < b->total ? 1 : a->total > b->total ? -1 : 0;
}

static void human(char *b, size_t l, double v, const char *unit) {
    const char *p[] = {"", "k", "M", "G", "T"};
    int i = 0;
    while (v >= 1000 && i < 4) { v /= 1000; i++; }
    snprintf(b, l, i ? "%.1f%s%s" : "%.0f%s%s", v, p[i], unit);
}

int acl_top(FILE *out, const char *state_dir, const char *map_dir, double secs, int n) {
    struct acl_table t;
    if (acl_table_load(&t, state_dir) < 0) return 1;
    if (!t.n) { fprintf(out, "no access lists are installed\n"); acl_table_free(&t); return 0; }
    int pfd = acl_map_open(map_dir, "BPFC_ACL_P"), bfd = acl_map_open(map_dir, "BPFC_ACL_B");
    if (pfd < 0) {
        fprintf(stderr, "bpfcctl: %s/BPFC_ACL_P: %s\n", map_dir, errno == EPERM || errno == EACCES ? "run as root" : strerror(errno));
        acl_table_free(&t);
        return 1;
    }
    uint64_t *p0 = calloc((size_t)t.n, 8), *b0 = calloc((size_t)t.n, 8);
    struct toprow *rows = calloc((size_t)t.n, sizeof(*rows));
    if (!p0 || !b0 || !rows) { acl_table_free(&t); return 1; }
    for (int i = 0; i < t.n; i++) {
        acl_map_get(pfd, t.r[i].key, &p0[i]);
        if (bfd >= 0) acl_map_get(bfd, t.r[i].key, &b0[i]);
    }
    double t0 = now_s();
    struct timespec ts = {(time_t)secs, (long)((secs - (double)(time_t)secs) * 1e9)};
    nanosleep(&ts, NULL);
    double dt = now_s() - t0;
    for (int i = 0; i < t.n; i++) {
        uint64_t p = 0, b = 0;
        acl_map_get(pfd, t.r[i].key, &p);
        if (bfd >= 0) acl_map_get(bfd, t.r[i].key, &b);
        rows[i].r = &t.r[i];
        rows[i].total = p;
        rows[i].pps = p >= p0[i] ? (double)(p - p0[i]) / dt : 0;
        rows[i].bps = b >= b0[i] ? (double)(b - b0[i]) * 8 / dt : 0;
    }
    qsort(rows, (size_t)t.n, sizeof(*rows), top_cmp);
    fprintf(out, "%9s %9s %12s  %-12s %-4s %-16s %-8s %s\n", "PPS", "BPS", "MATCHES", "INTERFACE", "DIR", "LIST", "SEQ", "ENTRY");
    for (int i = 0; i < t.n && i < n; i++) {
        if (!rows[i].total) break;
        char pps[32], bps[32];
        human(pps, sizeof(pps), rows[i].pps, "");
        human(bps, sizeof(bps), rows[i].bps, "");
        fprintf(out, "%9s %9s %12llu  %-12s %-4s %-16s %-8s %s\n", pps, bps, (unsigned long long)rows[i].total,
                rows[i].r->iface, rows[i].r->dir, rows[i].r->acl, rows[i].r->seq, rows[i].r->text);
    }
    free(p0); free(b0); free(rows);
    close(pfd);
    if (bfd >= 0) close(bfd);
    acl_table_free(&t);
    return 0;
}

/* ------------------------------------------------------------------- log */

struct acl_log {
    int fd;
    uint32_t id;
    size_t size, page;
    unsigned long *cons;
    void *prod;          /* producer page, then the data (mapped twice) */
};

struct acl_log *acl_log_open(const char *map_dir) {
    int fd = acl_map_open(map_dir, "BPFC_ACL_LOG");
    if (fd < 0) return NULL;
    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = (uint32_t)fd;
    a.info.info_len = sizeof(info);
    a.info.info = (unsigned long)&info;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) < 0 || info.type != 27 /* BPF_MAP_TYPE_RINGBUF */) { close(fd); return NULL; }
    struct acl_log *l = calloc(1, sizeof(*l));
    if (!l) { close(fd); return NULL; }
    l->fd = fd;
    l->id = info.id;
    l->size = info.max_entries;
    l->page = (size_t)sysconf(_SC_PAGESIZE);
    l->cons = mmap(NULL, l->page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    l->prod = mmap(NULL, l->page + 2 * l->size, PROT_READ, MAP_SHARED, fd, (off_t)l->page);
    if (l->cons == MAP_FAILED || l->prod == MAP_FAILED) {
        if (l->cons != MAP_FAILED) munmap(l->cons, l->page);
        if (l->prod != MAP_FAILED) munmap(l->prod, l->page + 2 * l->size);
        close(fd);
        free(l);
        return NULL;
    }
    return l;
}

int acl_log_fd(const struct acl_log *l) { return l ? l->fd : -1; }
uint32_t acl_log_map_id(const struct acl_log *l) { return l ? l->id : 0; }

void acl_log_close(struct acl_log *l) {
    if (!l) return;
    munmap(l->cons, l->page);
    munmap(l->prod, l->page + 2 * l->size);
    close(l->fd);
    free(l);
}

#define RB_BUSY (1U << 31)
#define RB_DISCARD (1U << 30)

int acl_log_drain(struct acl_log *l, const struct acl_table *t, void (*emit)(const char *line, void *ctx), void *ctx) {
    if (!l) return 0;
    int n = 0;
    unsigned char *data = (unsigned char *)l->prod + l->page;
    for (;;) {
        unsigned long cons = __atomic_load_n(l->cons, __ATOMIC_ACQUIRE);
        unsigned long prod = __atomic_load_n((unsigned long *)l->prod, __ATOMIC_ACQUIRE);
        if (cons >= prod) break;
        while (cons < prod) {
            uint32_t *hdr = (uint32_t *)(data + (cons & (l->size - 1)));
            uint32_t len = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
            if (len & RB_BUSY) goto done;
            uint32_t rl = len & ~(RB_BUSY | RB_DISCARD);
            if (!(len & RB_DISCARD)) {
                char line[1024];
                if (acl_log_format(line, sizeof(line), t, (unsigned char *)(hdr + 2), rl) > 0) emit(line, ctx);
                n++;
            }
            cons += (rl + 8 + 7) & ~7UL;
            __atomic_store_n(l->cons, cons, __ATOMIC_RELEASE);
        }
    }
done:
    return n;
}

static void macfmt(char *b, size_t l, const unsigned char *m) {
    snprintf(b, l, "%02x%02x.%02x%02x.%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int is_ether(uint32_t ifindex) {
    char name[IF_NAMESIZE], p[128], v[16] = "";
    if (!if_indextoname(ifindex, name)) return 1;
    snprintf(p, sizeof(p), "/sys/class/net/%s/type", name);
    FILE *f = fopen(p, "r");
    if (!f) return 1;
    if (!fgets(v, sizeof(v), f)) v[0] = 0;
    fclose(f);
    return atoi(v) == 1;
}

static const char *proto_name(int p, int v6) {
    switch (p) {
    case 1: return "icmp";
    case 2: return "igmp";
    case 6: return "tcp";
    case 17: return "udp";
    case 47: return "gre";
    case 50: return "esp";
    case 58: return v6 ? "icmp" : "58";
    case 89: return "ospf";
    case 132: return "sctp";
    }
    return NULL;
}

int acl_log_format(char *buf, size_t len, const struct acl_table *t, const unsigned char *rec, size_t reclen) {
    if (reclen < 24) return 0;
    uint64_t key;
    uint32_t ifindex, plen;
    memcpy(&key, rec + 8, 8);
    memcpy(&ifindex, rec + 16, 4);
    memcpy(&plen, rec + 20, 4);
    const unsigned char *f = rec + 24;
    size_t fl = reclen - 24;
    if (plen < fl) fl = plen;
    const struct acl_rule *r = acl_table_find(t, key);
    const char *acl = r ? r->acl : "?";
    const char *act = r && !strcmp(r->action, "deny") ? "denied" : "permitted";
    char ifn[IF_NAMESIZE] = "?";
    if (!if_indextoname(ifindex, ifn)) snprintf(ifn, sizeof(ifn), "%u", ifindex);
    size_t l3 = 0;
    int et = 0;
    char smac[20] = "", dmac[20] = "";
    if (is_ether(ifindex) && fl >= 14) {
        macfmt(dmac, sizeof(dmac), f);
        macfmt(smac, sizeof(smac), f + 6);
        et = f[12] << 8 | f[13];
        l3 = 14;
        while ((et == 0x8100 || et == 0x88a8) && fl >= l3 + 4) { et = f[l3 + 2] << 8 | f[l3 + 3]; l3 += 4; }
    } else if (fl) {
        et = (f[0] >> 4) == 6 ? 0x86dd : 0x0800;
    }
    /* log-input: the interface and source MAC after the list name, as IOS does */
    char input[96] = "";
    if (r && r->log == 2) snprintf(input, sizeof(input), " %s%s%s", ifn, smac[0] ? " " : "", smac);
    if (r && !strcmp(r->type, "mac")) {
        return snprintf(buf, len, "%%SEC-6-MACACCESSLOG: list %s %s %s -> %s, type 0x%04x, on %s, 1 packet", acl, act, smac, dmac, et, ifn);
    }
    char src[64], dst[64];
    int proto, v6 = et == 0x86dd;
    size_t l4;
    unsigned frag = 0;
    if (et == 0x0800 && fl >= l3 + 20) {
        const unsigned char *ip = f + l3;
        inet_ntop(AF_INET, ip + 12, src, sizeof(src));
        inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));
        proto = ip[9];
        frag = ((ip[6] << 8) | ip[7]) & 0x1fff;
        l4 = l3 + (size_t)(ip[0] & 15) * 4;
    } else if (v6 && fl >= l3 + 40) {
        const unsigned char *ip = f + l3;
        inet_ntop(AF_INET6, ip + 8, src, sizeof(src));
        inet_ntop(AF_INET6, ip + 24, dst, sizeof(dst));
        proto = ip[6];
        l4 = l3 + 40;
        for (int i = 0; i < 4 && fl >= l4 + 8; i++) {         /* extension headers */
            if (proto == 0 || proto == 43 || proto == 60) { int nh = f[l4]; l4 += ((size_t)f[l4 + 1] + 1) * 8; proto = nh; }
            else if (proto == 44) { frag = ((f[l4 + 2] << 8) | f[l4 + 3]) >> 3; proto = f[l4]; l4 += 8; }
            else break;
        }
    } else {
        return snprintf(buf, len, "%%SEC-6-IPACCESSLOGNP: list %s %s 0x%04x on %s, 1 packet", acl, act, et, ifn);
    }
    const char *tag = v6 ? "%IPV6_ACL-6-ACCESSLOGP" : "%SEC-6-IPACCESSLOGP";
    if (r && !strcmp(r->type, "standard"))
        return snprintf(buf, len, "%%SEC-6-IPACCESSLOGS: list %s %s %s%s%s%s, 1 packet", acl, act, src,
                        input[0] ? " (" : "", input[0] ? input + 1 : "", input[0] ? ")" : "");
    const char *pn = proto_name(proto, v6);
    char pnum[8];
    if (!pn) { snprintf(pnum, sizeof(pnum), "%d", proto); pn = pnum; }
    char inp[100] = "";
    if (input[0]) snprintf(inp, sizeof(inp), " (%s)", input + 1);
    if (!frag && (proto == 6 || proto == 17 || proto == 132) && fl >= l4 + 4) {
        int sp = f[l4] << 8 | f[l4 + 1], dp = f[l4 + 2] << 8 | f[l4 + 3];
        return snprintf(buf, len, "%s: list %s %s %s %s(%d)%s -> %s(%d), 1 packet", tag, acl, act, pn, src, sp, inp, dst, dp);
    }
    if (!frag && (proto == 1 || (v6 && proto == 58)) && fl >= l4 + 2)
        return snprintf(buf, len, "%s: list %s %s %s %s%s -> %s (%d/%d), 1 packet", v6 ? tag : "%SEC-6-IPACCESSLOGDP",
                        acl, act, pn, src, inp, dst, f[l4], f[l4 + 1]);
    return snprintf(buf, len, "%s: list %s %s %s %s%s -> %s%s, 1 packet", v6 ? tag : "%SEC-6-IPACCESSLOGNP", acl, act, pn,
                    src, inp, dst, frag ? " (fragment)" : "");
}
