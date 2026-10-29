/*
 * bpfcctl - shows what bpfcd has installed and lets you inspect programs.
 *
 *   bpfcctl [status] [-a] [-l]            programs per interface, checked against the kernel
 *   bpfcctl show <iface> <dir> <prio>     metadata, source file and failure log
 *   bpfcctl show ... --bytecode           plus the kernel's translated bytecode
 *   bpfcctl reload [--no-wait]            SIGHUP bpfcd and report the outcome
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/bpf.h>

static struct config cfg;
static char conf_path[PATH_MAX] = DEFAULT_CONF_PATH;
static char state_dir_override[PATH_MAX];
static int use_color;

#define C_RED    (use_color ? "\033[31m" : "")
#define C_GREEN  (use_color ? "\033[32m" : "")
#define C_YELLOW (use_color ? "\033[33m" : "")
#define C_DIM    (use_color ? "\033[2m" : "")
#define C_BOLD   (use_color ? "\033[1m" : "")
#define C_OFF    (use_color ? "\033[0m" : "")

static const char *state_dir(void) {
    return state_dir_override[0] ? state_dir_override : cfg.state_dir;
}

static void fmt_time(time_t t, char *out, size_t len) {
    if (!t) { snprintf(out, len, "-"); return; }
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, len, "%Y-%m-%d %H:%M:%S", &tm);
}

/* Path relative to the config dir when it lives inside it, to keep tables narrow. */
static const char *short_path(const char *path, const char *config_dir) {
    size_t n = strlen(config_dir);
    if (n && !strncmp(path, config_dir, n) && path[n] == '/') return path + n + 1;
    return path;
}

/* Is the pid alive and actually bpfcd (not a recycled pid)? */
static int daemon_alive(int pid) {
    if (pid <= 0 || kill(pid, 0) < 0) return 0;
    char p[64], comm[64] = "";
    snprintf(p, sizeof(p), "/proc/%d/comm", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 1;
    if (fgets(comm, sizeof(comm), f)) comm[strcspn(comm, "\n")] = '\0';
    fclose(f);
    return !strcmp(comm, "bpfcd");
}

static int load_state(struct daemon_info *di, struct slot **slots) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", state_dir(), STATE_FILE_NAME);
    int n = state_read(path, di, slots);
    if (n < 0) {
        if (n == -ENOENT)
            fprintf(stderr, "No state at %s: bpfcd has not run yet (start it with: systemctl start bpfcd)\n", path);
        else
            fprintf(stderr, "Cannot read %s: %s\n", path, strerror(-n));
    }
    return n;
}

/* Has the file on disk changed since bpfcd last read it? Mirrors the daemon's mtime-then-hash rule. */
static int file_state(const struct slot *s) {
    struct stat st;
    if (stat(s->path, &st) < 0) return -1; /* deleted */
    int64_t m = (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
    if (m == s->mtime_ns) return 0;
    char hex[65];
    if (sha256_file(s->path, hex) < 0) return -1;
    return strcmp(hex, s->sha256) ? 1 : 0;
}

/* ======================= kernel cross-check ======================= */

struct kview { int ifindex; int dir; int n; struct tc_filter *f; };
static struct kview *kviews;
static int nkviews;

static const struct kview *kernel_view(int ifindex, int dir) {
    for (int i = 0; i < nkviews; i++)
        if (kviews[i].ifindex == ifindex && kviews[i].dir == dir) return &kviews[i];
    struct kview *nv = realloc(kviews, (nkviews + 1) * sizeof(*kviews));
    if (!nv) return NULL;
    kviews = nv;
    struct kview *v = &kviews[nkviews++];
    v->ifindex = ifindex;
    v->dir = dir;
    v->f = NULL;
    v->n = tc_dump_filters(ifindex, dir, &v->f);
    return v;
}

static const struct tc_filter *kernel_at(const char *iface, int dir, int prio) {
    int idx = (int)if_nametoindex(iface);
    if (!idx) return NULL;
    const struct kview *v = kernel_view(idx, dir);
    if (!v || v->n < 0) return NULL;
    for (int i = 0; i < v->n; i++)
        if (v->f[i].prio == prio) return &v->f[i];
    return NULL;
}

/* One word describing whether the kernel agrees with bpfcd's record. */
static const char *kernel_check(const struct slot *s, const char **color) {
    const struct tc_filter *k = kernel_at(s->iface, s->dir, s->prio);
    *color = C_DIM;
    if (s->status == ST_INSTALLED) {
        if (!if_nametoindex(s->iface)) { *color = C_RED; return "no-iface"; }
        if (!k) { *color = C_RED; return "MISSING"; }
        if (k->prog_id != s->prog_id) { *color = C_RED; return "DIFFERS"; }
        *color = C_GREEN;
        return "ok";
    }
    if (k) { *color = C_YELLOW; return "occupied"; }
    return "-";
}

static const char *status_color(int st) {
    switch (st) {
    case ST_INSTALLED: return C_GREEN;
    case ST_PENDING: return C_DIM;
    case ST_FAILED: case ST_DISABLED: return C_RED;
    default: return C_YELLOW;
    }
}

/* ======================= status ======================= */

static int cmd_status(int show_all, int long_fmt) {
    struct daemon_info di;
    struct slot *slots = NULL;
    int n = load_state(&di, &slots);
    if (n < 0) return 1;

    char started[32], reloaded[32];
    fmt_time(di.started, started, sizeof(started));
    fmt_time(di.last_reload, reloaded, sizeof(reloaded));
    int alive = daemon_alive(di.pid);
    if (alive)
        printf("bpfcd: %srunning%s (pid %d, version %s), started %s, last reload %s\n",
               C_GREEN, C_OFF, di.pid, di.version, started, reloaded);
    else
        printf("bpfcd: %snot running%s -- information below is from its last run\n", C_RED, C_OFF);
    printf("programs: %s    external changes: %s\n\n", di.config_dir,
           di.on_external_change == EXT_LOG ? "log" : "reinstall");

    int problems = 0, pending_reload = 0;
    if (n == 0) {
        printf("No programs configured. Add files as %s/<interface>/<ingress|egress>/<priority>.bpfc\n"
               "and run: systemctl reload bpfcd\n", di.config_dir[0] ? di.config_dir : DEFAULT_CONFIG_DIR);
    } else {
        int wif = 5;
        for (int i = 0; i < n; i++) if ((int)strlen(slots[i].iface) > wif) wif = (int)strlen(slots[i].iface);
        printf("%s%-*s  %-7s  %5s  %-19s  %6s  %-16s  %-8s  %s%s\n", C_BOLD, wif, "IFACE", "DIR", "PRIO",
               "STATUS", "PROG", "TAG", "KERNEL", "FILE", C_OFF);
        for (int i = 0; i < n; i++) {
            struct slot *s = &slots[i];
            const char *kc;
            const char *kw = kernel_check(s, &kc);
            char prog[16] = "-";
            if (s->prog_id) snprintf(prog, sizeof(prog), "%u", s->prog_id);
            int fs = file_state(s);
            const char *mark = fs == 1 ? " (modified, reload pending)" : fs < 0 ? " (deleted, reload pending)" : "";
            if (fs != 0) pending_reload = 1;
            printf("%-*s  %-7s  %5d  %s%-19s%s  %6s  %-16s  %s%-8s%s  %s%s%s%s\n", wif, s->iface,
                   dir_name(s->dir), s->prio, status_color(s->status), status_name(s->status), C_OFF,
                   prog, s->tag[0] ? s->tag : "-", kc, kw, C_OFF,
                   short_path(s->path, di.config_dir), C_YELLOW, mark, C_OFF);
            if (s->error[0])
                printf("%*s%s-> %s%s\n", wif + 2, "", C_DIM, s->error, C_OFF);
            if (long_fmt && s->status == ST_INSTALLED) {
                char t[32];
                fmt_time(s->installed_at, t, sizeof(t));
                printf("%*s%sinstalled %s, %u insns, sha256 %.16s, ifindex %d%s\n", wif + 2, "", C_DIM,
                       t, s->insns, s->sha256, s->ifindex, C_OFF);
            }
            if (s->status == ST_FAILED || s->status == ST_DISABLED || s->status == ST_REMOVED_EXT ||
                s->status == ST_REPLACED_EXT || (s->status == ST_INSTALLED && strcmp(kw, "ok")))
                problems++;
        }
    }

    if (show_all) {
        /* Every TC filter on every interface that bpfcd is not responsible for. */
        printf("\n%sFilters not managed by bpfcd%s\n", C_BOLD, C_OFF);
        struct if_nameindex *ifs = if_nameindex();
        int shown = 0;
        for (struct if_nameindex *p = ifs; p && p->if_index; p++) {
            for (int dir = DIR_INGRESS; dir <= DIR_EGRESS; dir++) {
                const struct kview *v = kernel_view((int)p->if_index, dir);
                if (!v || v->n <= 0) continue;
                for (int j = 0; j < v->n; j++) {
                    const struct tc_filter *f = &v->f[j];
                    int managed = 0;
                    for (int i = 0; i < n; i++)
                        if (slots[i].status == ST_INSTALLED && !strcmp(slots[i].iface, p->if_name) &&
                            slots[i].dir == dir && slots[i].prio == f->prio && slots[i].prog_id == f->prog_id)
                            managed = 1;
                    if (managed) continue;
                    if (!shown++)
                        printf("%s%-15s  %-7s  %5s  %-6s  %6s  %-16s  %s%s\n", C_BOLD, "IFACE", "DIR", "PRIO",
                               "KIND", "PROG", "TAG", "NAME", C_OFF);
                    char prog[16] = "-", tag[17] = "-";
                    if (f->prog_id) {
                        snprintf(prog, sizeof(prog), "%u", f->prog_id);
                        struct prog_details d;
                        if (prog_get_details(f->prog_id, 0, &d) == 0) snprintf(tag, sizeof(tag), "%s", d.tag);
                    }
                    printf("%-15s  %-7s  %5d  %-6s  %6s  %-16s  %s\n", p->if_name, dir_name(dir), f->prio,
                           f->kind, prog, tag, f->name[0] ? f->name : "-");
                }
            }
        }
        if (ifs) if_freenameindex(ifs);
        if (!shown) printf("(none)\n");
    }

    if (pending_reload)
        printf("\nFiles changed on disk since the last reload. Apply with: systemctl reload bpfcd\n");
    free(slots);
    /* Exit status lets scripts and monitoring use `bpfcctl status -q`-style checks. */
    return !alive ? 3 : problems ? 2 : 0;
}

/* ======================= show ======================= */

static const char *helper_name_by_addr(uint64_t addr);

static void print_insn(const struct bpf_insn *in, int idx, int total, int *skip) {
    static const char *const alu_ops[16] = {"+=", "-=", "*=", "/=", "|=", "&=", "<<=", ">>=",
                                            "neg", "%=", "^=", "=", "s>>=", "end", "?", "?"};
    static const char *const jmp_ops[16] = {"goto", "==", ">", ">=", "&", "!=", "s>", "s>=",
                                            "call", "exit", "<", "<=", "s<", "s<=", "?", "?"};
    static const char *const sz[4] = {"u32", "u16", "u8", "u64"};
    uint8_t code = in->code, cls = code & 0x07;
    int x = code & 0x08; /* BPF_X: register source */
    printf("%5d: (%02x) ", idx, code);

    if (cls == BPF_ALU || cls == BPF_ALU64) {
        char r = cls == BPF_ALU64 ? 'r' : 'w';
        int op = (code & 0xf0) >> 4;
        if (op == 8) { printf("%c%d = -%c%d\n", r, in->dst_reg, r, in->dst_reg); return; }
        if (op == 13) {
            printf("r%d = %s%d r%d\n", in->dst_reg, x ? "be" : "le", in->imm, in->dst_reg);
            return;
        }
        if (x) printf("%c%d %s %c%d\n", r, in->dst_reg, alu_ops[op], r, in->src_reg);
        else printf("%c%d %s %d\n", r, in->dst_reg, alu_ops[op], in->imm);
        return;
    }
    if (cls == BPF_JMP || cls == BPF_JMP32) {
        int op = (code & 0xf0) >> 4;
        char r = cls == BPF_JMP ? 'r' : 'w';
        if (op == 9) { printf("exit\n"); return; }
        if (op == 8) {
            if (in->src_reg == 1) { printf("call pc%+d\n", in->imm); return; }
            const char *nm = helper_name_by_addr((uint64_t)(int64_t)in->imm);
            if (nm) printf("call %s\n", nm);
            else printf("call #%d\n", in->imm);
            return;
        }
        if (op == 0) { printf("goto pc%+d\n", in->off); return; }
        if (x) printf("if %c%d %s %c%d goto pc%+d\n", r, in->dst_reg, jmp_ops[op], r, in->src_reg, in->off);
        else printf("if %c%d %s 0x%x goto pc%+d\n", r, in->dst_reg, jmp_ops[op], (unsigned)in->imm, in->off);
        return;
    }
    int size = (code & 0x18) >> 3, mode = code & 0xe0;
    if (cls == BPF_LDX) {
        printf("r%d = *(%s *)(r%d %+d)\n", in->dst_reg, sz[size], in->src_reg, in->off);
        return;
    }
    if (cls == BPF_STX) {
        if (mode == 0xc0) printf("lock *(%s *)(r%d %+d) += r%d\n", sz[size], in->dst_reg, in->off, in->src_reg);
        else printf("*(%s *)(r%d %+d) = r%d\n", sz[size], in->dst_reg, in->off, in->src_reg);
        return;
    }
    if (cls == BPF_ST) {
        printf("*(%s *)(r%d %+d) = %d\n", sz[size], in->dst_reg, in->off, in->imm);
        return;
    }
    if (cls == BPF_LD) {
        if (code == (BPF_LD | BPF_DW | BPF_IMM) && idx + 1 < total) {
            uint64_t v = (uint32_t)in->imm | ((uint64_t)(uint32_t)in[1].imm << 32);
            if (in->src_reg) printf("r%d = map[0x%llx]\n", in->dst_reg, (unsigned long long)v);
            else printf("r%d = 0x%llx ll\n", in->dst_reg, (unsigned long long)v);
            *skip = 1;
            return;
        }
        if (mode == 0x20) { printf("r0 = *(%s *)skb[%d]\n", sz[size], in->imm); return; }
        if (mode == 0x40) { printf("r0 = *(%s *)skb[r%d + %d]\n", sz[size], in->src_reg, in->imm); return; }
    }
    printf("(raw) dst=r%d src=r%d off=%d imm=%d\n", in->dst_reg, in->src_reg, in->off, in->imm);
}

/*
 * In translated bytecode a helper call's imm is the helper's address relative
 * to __bpf_call_base. /proc/kallsyms turns it back into a name when kernel
 * pointers are visible (root, kptr_restrict <= 1); otherwise "#imm" is shown.
 */
struct ksym { uint64_t addr; char name[64]; };
static struct ksym *ksyms;
static int nksyms, ksyms_loaded;
static uint64_t call_base;

static void load_kallsyms(void) {
    ksyms_loaded = 1;
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return;
    char line[256];
    int cap = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a;
        char type, name[128];
        if (sscanf(line, "%llx %c %127s", &a, &type, name) != 3 || !a) continue;
        if (!strcmp(name, "__bpf_call_base")) { call_base = a; continue; }
        /* Helper implementations are named bpf_* / sk_* / ____bpf_* etc.; keep text symbols only. */
        if (type != 't' && type != 'T') continue;
        if (strncmp(name, "bpf_", 4) && strncmp(name, "sk_", 3) && strncmp(name, "____bpf", 7)) continue;
        if (nksyms == cap) {
            cap = cap ? cap * 2 : 1024;
            struct ksym *n = realloc(ksyms, cap * sizeof(*ksyms));
            if (!n) break;
            ksyms = n;
        }
        ksyms[nksyms].addr = a;
        snprintf(ksyms[nksyms].name, sizeof(ksyms[nksyms].name), "%s", name);
        nksyms++;
    }
    fclose(f);
}

static const char *helper_name_by_addr(uint64_t rel) {
    if (!ksyms_loaded) load_kallsyms();
    if (!call_base) return NULL;
    uint64_t addr = call_base + rel;
    for (int i = 0; i < nksyms; i++)
        if (ksyms[i].addr == addr) return ksyms[i].name;
    return NULL;
}

static int print_file(const char *path, const char *heading) {
    FILE *f = fopen(path, "r");
    if (!f) return -errno;
    printf("\n%s%s%s\n", C_BOLD, heading, C_OFF);
    char *line = NULL;
    size_t cap = 0;
    int ln = 0;
    while (getline(&line, &cap, f) > 0) {
        line[strcspn(line, "\n")] = '\0';
        printf("%s%4d%s  %s\n", C_DIM, ++ln, C_OFF, line);
    }
    free(line);
    fclose(f);
    return 0;
}

static int cmd_show(int argc, char **argv, int bytecode) {
    /* Accepts "iface dir prio" or "iface/dir/prio". */
    char ifbuf[IFNAMSIZ + 64], *iface, *dirs, *prios;
    if (argc == 1 && strchr(argv[0], '/')) {
        snprintf(ifbuf, sizeof(ifbuf), "%s", argv[0]);
        iface = strtok(ifbuf, "/");
        dirs = strtok(NULL, "/");
        prios = strtok(NULL, "/");
    } else if (argc == 3) {
        iface = argv[0]; dirs = argv[1]; prios = argv[2];
    } else {
        fprintf(stderr, "Usage: bpfcctl show <iface> <ingress|egress> <prio> [--bytecode]\n");
        return 1;
    }
    int dir = dirs ? dir_parse(dirs) : -1;
    int prio = prios ? atoi(prios) : 0;
    if (!iface || dir < 0 || prio <= 0) {
        fprintf(stderr, "Usage: bpfcctl show <iface> <ingress|egress> <prio> [--bytecode]\n");
        return 1;
    }

    struct daemon_info di;
    struct slot *slots = NULL;
    int n = load_state(&di, &slots);
    if (n < 0) return 1;
    struct slot *s = NULL;
    for (int i = 0; i < n; i++)
        if (!strcmp(slots[i].iface, iface) && slots[i].dir == dir && slots[i].prio == prio) s = &slots[i];
    if (!s) {
        fprintf(stderr, "bpfcd does not manage %s %s priority %d.\n", iface, dir_name(dir), prio);
        const struct tc_filter *k = kernel_at(iface, dir, prio);
        if (k) fprintf(stderr, "The kernel has a %s filter there (prog id %u, name %s) installed by something else.\n",
                       k->kind, k->prog_id, k->name[0] ? k->name : "-");
        free(slots);
        return 1;
    }

    char t1[32], t2[32];
    fmt_time(s->installed_at, t1, sizeof(t1));
    fmt_time(s->changed_at, t2, sizeof(t2));
    const char *kc;
    const char *kw = kernel_check(s, &kc);
    int fs = file_state(s);
    printf("%s%s %s priority %d%s\n", C_BOLD, s->iface, dir_name(s->dir), s->prio, C_OFF);
    printf("  status:     %s%s%s%s%s\n", status_color(s->status), status_name(s->status), C_OFF,
           s->error[0] ? " -- " : "", s->error);
    printf("  file:       %s%s\n", s->path,
           fs == 1 ? " (modified since last reload)" : fs < 0 ? " (deleted since last reload)" : "");
    printf("  sha256:     %s\n", s->sha256[0] ? s->sha256 : "-");
    printf("  program:    id %u  tag %s  %u insns\n", s->prog_id, s->tag[0] ? s->tag : "-", s->insns);
    printf("  kernel:     %s%s%s\n", kc, kw, C_OFF);
    printf("  installed:  %s   last change: %s\n", t1, t2);

    const struct tc_filter *k = kernel_at(s->iface, s->dir, s->prio);
    if (k && k->prog_id != s->prog_id)
        printf("  in kernel:  %s filter, prog id %u, name %s\n", k->kind, k->prog_id, k->name[0] ? k->name : "-");

    if (print_file(s->path, "Source") < 0)
        printf("\n(source file %s cannot be read: %s)\n", s->path, strerror(errno));

    if (s->status == ST_FAILED) {
        char ep[PATH_MAX + 64];
        error_log_path(ep, sizeof(ep), state_dir(), s->iface, s->dir, s->prio);
        if (print_file(ep, "bpfc output from the failed attempt") < 0)
            printf("\n(no saved bpfc output at %s)\n", ep);
    }

    int rc = 0;
    if (bytecode) {
        uint32_t id = s->prog_id;
        if (!id && k) id = k->prog_id;
        if (!id) {
            printf("\nNo program is loaded at this priority, so there is no bytecode to show.\n");
        } else {
            struct prog_details d;
            int e = prog_get_details(id, 1, &d);
            if (e < 0) {
                printf("\nCannot read program %u: %s%s\n", id, strerror(-e),
                       e == -EPERM ? " (run as root)" : "");
                rc = 1;
            } else if (!d.xlated) {
                printf("\nThe kernel did not provide bytecode for program %u (check sysctl net.core.bpf_jit_harden / kptr_restrict).\n", id);
            } else {
                int cnt = (int)(d.xlated_len / sizeof(struct bpf_insn));
                printf("\n%sKernel bytecode (translated) -- program %u, tag %s, %d insns, %u bytes JITed%s\n",
                       C_BOLD, d.id, d.tag, cnt, d.jited_len, C_OFF);
                const struct bpf_insn *in = d.xlated;
                for (int i = 0; i < cnt; i++) {
                    int skip = 0;
                    print_insn(&in[i], i, cnt, &skip);
                    i += skip;
                }
                free(d.xlated);
            }
        }
    }
    free(slots);
    return rc;
}

/* ======================= reload ======================= */

static int cmd_reload(int wait) {
    struct daemon_info di;
    struct slot *slots = NULL;
    char pidpath[PATH_MAX + 32];
    snprintf(pidpath, sizeof(pidpath), "%s/%s", state_dir(), PID_FILE_NAME);
    int pid = 0;
    FILE *pf = fopen(pidpath, "r");
    if (pf) { if (fscanf(pf, "%d", &pid) != 1) pid = 0; fclose(pf); }
    if (!daemon_alive(pid)) {
        fprintf(stderr, "bpfcd is not running (no live process in %s)\n", pidpath);
        return 1;
    }
    int n = load_state(&di, &slots);
    unsigned before = n >= 0 ? di.reload_count : 0;
    free(slots);
    slots = NULL;
    if (kill(pid, SIGHUP) < 0) {
        fprintf(stderr, "Cannot signal bpfcd (pid %d): %s\n", pid, strerror(errno));
        return 1;
    }
    if (!wait) { printf("Sent SIGHUP to bpfcd (pid %d)\n", pid); return 0; }

    /* Compiles can take a while; allow a generous window. */
    for (int i = 0; i < 1200; i++) {
        usleep(100000);
        n = load_state(&di, &slots);
        if (n >= 0 && di.reload_count != before) break;
        free(slots);
        slots = NULL;
        n = -1;
    }
    if (n < 0) {
        fprintf(stderr, "bpfcd did not finish reloading within 120s; check: journalctl -u bpfcd\n");
        return 1;
    }
    int counts[ST__COUNT] = {0};
    for (int i = 0; i < n; i++) if (slots[i].status >= 0 && slots[i].status < ST__COUNT) counts[slots[i].status]++;
    printf("Reloaded: %d installed, %d waiting for interface, %d failed\n", counts[ST_INSTALLED],
           counts[ST_PENDING], counts[ST_FAILED] + counts[ST_DISABLED]);
    int failed = 0;
    for (int i = 0; i < n; i++) {
        if (slots[i].status != ST_FAILED && slots[i].status != ST_DISABLED) continue;
        failed++;
        printf("  %sFAILED%s %s %s %d: %s\n", C_RED, C_OFF, slots[i].iface, dir_name(slots[i].dir),
               slots[i].prio, slots[i].error);
    }
    free(slots);
    return failed ? 2 : 0;
}

/* ======================= main ======================= */

static void usage(void) {
    printf("Usage: bpfcctl [options] [command]\n\n"
           "Commands:\n"
           "  status [-a] [-l]               programs managed by bpfcd (default command)\n"
           "      -a, --all                  also list TC filters bpfcd does not manage\n"
           "      -l, --long                 include install time, size and hash\n"
           "  show <iface> <dir> <prio>      details, source and failure output for one program\n"
           "      -b, --bytecode             also print the kernel's translated bytecode\n"
           "  reload [--no-wait]             make bpfcd rescan and report the result\n\n"
           "Options:\n"
           "  -c, --config <file>            bpfc.conf to read state_dir from (default %s)\n"
           "  -s, --state-dir <dir>          bpfcd state directory (default from bpfc.conf)\n"
           "      --color=auto|always|never  colorize output (default auto)\n"
           "  -V, --version                  print version\n\n"
           "Exit status of status: 0 all good, 2 some program needs attention, 3 bpfcd not running.\n",
           DEFAULT_CONF_PATH);
}

int main(int argc, char **argv) {
    int show_all = 0, long_fmt = 0, bytecode = 0, nowait = 0;
    const char *color = "auto";
    static const struct option longopts[] = {
        {"config", required_argument, 0, 'c'}, {"state-dir", required_argument, 0, 's'},
        {"all", no_argument, 0, 'a'}, {"long", no_argument, 0, 'l'}, {"bytecode", no_argument, 0, 'b'},
        {"no-wait", no_argument, 0, 'n'}, {"color", required_argument, 0, 'C'},
        {"version", no_argument, 0, 'V'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    int o;
    /* "+" would stop at the command; we want options anywhere, so permute (GNU default). */
    while ((o = getopt_long(argc, argv, "c:s:albnVh", longopts, NULL)) != -1) {
        switch (o) {
        case 'c': snprintf(conf_path, sizeof(conf_path), "%s", optarg); break;
        case 's': snprintf(state_dir_override, sizeof(state_dir_override), "%s", optarg); break;
        case 'a': show_all = 1; break;
        case 'l': long_fmt = 1; break;
        case 'b': bytecode = 1; break;
        case 'n': nowait = 1; break;
        case 'C': color = optarg; break;
        case 'V': printf("bpfcctl %s\n", BPFC_VERSION); return 0;
        case 'h': usage(); return 0;
        default: usage(); return 1;
        }
    }
    use_color = !strcmp(color, "always") || (!strcmp(color, "auto") && isatty(1) && !getenv("NO_COLOR"));

    config_defaults(&cfg);
    char err[512] = "";
    if (config_load(conf_path, &cfg, err, sizeof(err)) < 0)
        fprintf(stderr, "warning: %s (using defaults)\n", err);

    const char *cmd = optind < argc ? argv[optind++] : "status";
    int rest = argc - optind;
    char **args = argv + optind;
    if (!strcmp(cmd, "status")) return cmd_status(show_all, long_fmt);
    if (!strcmp(cmd, "show")) return cmd_show(rest, args, bytecode);
    if (!strcmp(cmd, "reload")) return cmd_reload(!nowait);
    if (!strcmp(cmd, "help")) { usage(); return 0; }
    fprintf(stderr, "Unknown command '%s'\n", cmd);
    usage();
    return 1;
}
