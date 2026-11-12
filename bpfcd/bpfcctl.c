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
#include "netns.h"

#include <ctype.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/bpf.h>

static struct config cfg;
static char conf_path[PATH_MAX + 16] = DEFAULT_CONF_PATH;
static const char *conf_override;     /* -c */
static const char *netns_arg;         /* -n */
static char state_dir_override[PATH_MAX];
static int use_color;

/*
 * Kernel cross-checks run in the namespace being looked at. kernel_ok is 0
 * when bpfcctl could not get there (not root, or the namespace is missing);
 * kernel_note says why.
 */
static int kernel_ok = 1;
static char kernel_note[600];
static int host_nsfd = -1, host_rtnl = -1;
static int left_host;   /* bpfcctl has entered another namespace */

#define C_RED    (use_color ? "\033[31m" : "")
#define C_GREEN  (use_color ? "\033[32m" : "")
#define C_YELLOW (use_color ? "\033[33m" : "")
#define C_DIM    (use_color ? "\033[2m" : "")
#define C_BOLD   (use_color ? "\033[1m" : "")
#define C_OFF    (use_color ? "\033[0m" : "")

static const char *state_dir(void) {
    return state_dir_override[0] ? state_dir_override : cfg.state_dir;
}

/* The systemd unit and the reload command for the namespace being looked at. */
static const char *unit_name(void) {
    static char u[NETNS_NAME_MAX + 32];
    if (cfg.netns[0]) snprintf(u, sizeof(u), "bpfcd-netns@%s", cfg.netns);
    else snprintf(u, sizeof(u), "bpfcd");
    return u;
}

static const char *reload_cmd(void) {
    static char r[NETNS_NAME_MAX + 64];
    if (cfg.netns[0]) snprintf(r, sizeof(r), "bpfcctl -n %s reload", cfg.netns);
    else snprintf(r, sizeof(r), "systemctl reload bpfcd");
    return r;
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
    if (pid <= 0) return 0;
    /* Signal 0 only probes. EPERM means the process exists but belongs to
     * another user (bpfcd runs as root), so only ESRCH means it is gone. */
    if (kill(pid, 0) < 0 && errno != EPERM) return 0;
    char p[64], comm[64] = "";
    snprintf(p, sizeof(p), "/proc/%d/comm", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 1;
    if (fgets(comm, sizeof(comm), f)) comm[strcspn(comm, "\n")] = '\0';
    fclose(f);
    return !strcmp(comm, "bpfcd");
}

/* The bpfc the daemon uses (from its state file), so programs with includes
 * hash the same here as in bpfcd. */
static char daemon_bpfc[PATH_MAX];

static int load_state(struct daemon_info *di, struct slot **slots) {
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", state_dir(), STATE_FILE_NAME);
    int n = state_read(path, di, slots);
    if (n >= 0) snprintf(daemon_bpfc, sizeof(daemon_bpfc), "%s", di->bpfc_path[0] ? di->bpfc_path : cfg.bpfc_path);
    if (n < 0) {
        if (n == -ENOENT)
            fprintf(stderr, "No state at %s: bpfcd has not run yet (start it with: systemctl start bpfcd)\n", path);
        else
            fprintf(stderr, "Cannot read %s: %s\n", path, strerror(-n));
    }
    return n;
}

/* Has the file on disk (or a file it includes) changed since bpfcd last read it?
 * Always hashes: the program's own mtime does not show changes to its includes. */
/* No commands: only whitespace, ';' and # comments (bpfcd's file_is_empty()). */
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

static int file_state(const struct slot *s) {
    struct stat st;
    if (stat(s->path, &st) < 0) return errno == ENOENT || errno == ENOTDIR ? -1 : 0; /* deleted; unreadable: unknown */
    if (access(s->path, R_OK) < 0) return 0;   /* cannot hash it: say nothing rather than "modified" */
    /* bpfcd records an empty (opt-out) file as "empty", not as its hash */
    if (!strcmp(s->sha256, "empty")) return file_is_empty(s->path) ? 0 : 1;
    char hex[65];
    int has_includes;
    if (sha256_program(daemon_bpfc[0] ? daemon_bpfc : cfg.bpfc_path, s->path, cfg.compile_timeout,
                       hex, &has_includes) < 0) return -1;
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
    if (!kernel_ok) return NULL;
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
    if (!kernel_ok) return "?";
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
    case ST_PENDING: case ST_EXCLUDED: return C_DIM;
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
    if (cfg.netns[0]) {
        int waiting = alive && !strcmp(di.netns_status, "waiting");
        printf("netns: %s%s%s%s  %s\n", cfg.netns, waiting ? " (" : "", waiting ? "waiting" : "",
               waiting ? ")" : "", di.netns_target[0] ? di.netns_target : "");
    }
    printf("programs: %s    external changes: %s\n", di.config_dir,
           di.on_external_change == EXT_LOG ? "log" : "reinstall");
    if (!kernel_ok) printf("%skernel not checked: %s%s\n", C_DIM, kernel_note, C_OFF);
    printf("\n");

    int problems = 0, pending_reload = 0;
    if (n == 0) {
        const char *cd = di.config_dir[0] ? di.config_dir : DEFAULT_CONFIG_DIR;
        printf("No programs configured. Add files as %s/<interface|%%all%%|%%<kind>%%>/<ingress|egress>/<priority>.bpfc\n"
               "or %s/<interface|%%all%%|%%<kind>%%>/xdp.bpfc and run: %s\n", cd, cd, reload_cmd());
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
            char pr[8] = "-";
            if (s->dir != DIR_XDP) snprintf(pr, sizeof(pr), "%d", s->prio);
            printf("%-*s  %-7s  %5s  %s%-19s%s  %6s  %-16s  %s%-8s%s  %s%s%s%s\n", wif, s->iface,
                   dir_name(s->dir), pr, status_color(s->status), status_name(s->status), C_OFF,
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
                s->status == ST_REPLACED_EXT || (s->status == ST_INSTALLED && kernel_ok && strcmp(kw, "ok")))
                problems++;
        }
    }

    if (show_all && !kernel_ok) {
        printf("\n%sFilters not managed by bpfcd: not available (%s)%s\n", C_DIM, kernel_note, C_OFF);
    } else if (show_all) {
        /* Every TC filter on every interface that bpfcd is not responsible for. */
        printf("\n%sFilters not managed by bpfcd%s\n", C_BOLD, C_OFF);
        struct if_nameindex *ifs = if_nameindex();
        int shown = 0;
        for (struct if_nameindex *p = ifs; p && p->if_index; p++) {
            for (int dir = DIR_INGRESS; dir <= DIR_XDP; dir++) {
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
                    char pr[8] = "-";
                    if (dir != DIR_XDP) snprintf(pr, sizeof(pr), "%d", f->prio);
                    printf("%-15s  %-7s  %5s  %-6s  %6s  %-16s  %s\n", p->if_name, dir_name(dir), pr,
                           f->kind, prog, tag, f->name[0] ? f->name : "-");
                }
            }
        }
        if (ifs) if_freenameindex(ifs);
        if (!shown) printf("(none)\n");
    }

    if (pending_reload)
        printf("\nFiles changed on disk since the last reload. Apply with: %s\n", reload_cmd());
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
    /* Accepts "iface dir prio" or "iface/dir/prio"; "iface xdp" or "iface/xdp". */
    static const char usage[] = "Usage: bpfcctl show <iface> <ingress|egress> <prio> [--bytecode]\n"
                                "       bpfcctl show <iface> xdp [--bytecode]\n";
    char ifbuf[IFNAMSIZ + 64], *iface, *dirs, *prios;
    if (argc == 1 && strchr(argv[0], '/')) {
        snprintf(ifbuf, sizeof(ifbuf), "%s", argv[0]);
        iface = strtok(ifbuf, "/");
        dirs = strtok(NULL, "/");
        prios = strtok(NULL, "/");
    } else if (argc == 3 || argc == 2) {
        iface = argv[0]; dirs = argv[1]; prios = argc == 3 ? argv[2] : NULL;
    } else {
        fputs(usage, stderr);
        return 1;
    }
    int dir = dirs ? dir_parse(dirs) : -1;
    int prio = prios ? atoi(prios) : 0;
    if (!iface || dir < 0 || (dir == DIR_XDP ? prio != 0 : prio <= 0)) {
        fputs(usage, stderr);
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
    if (s->dir == DIR_XDP) printf("%s%s xdp%s\n", C_BOLD, s->iface, C_OFF);
    else printf("%s%s %s priority %d%s\n", C_BOLD, s->iface, dir_name(s->dir), s->prio, C_OFF);
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
        if (errno == EPERM)
            fprintf(stderr, "Reloading bpfcd requires root: run 'sudo %s' or 'sudo systemctl reload %s'\n",
                    cfg.netns[0] ? reload_cmd() : "bpfcctl reload", unit_name());
        else
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
        fprintf(stderr, "bpfcd did not finish reloading within 120s; check: journalctl -u %s\n", unit_name());
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

/* ======================= namespaces ======================= */

/*
 * Moves bpfcctl into the namespace cfg describes, for the kernel checks.
 * Only the network namespace changes: files are read as before.
 */
static void enter_cfg_netns(void) {
    kernel_ok = 1;
    kernel_note[0] = '\0';
    for (int i = 0; i < nkviews; i++) free(kviews[i].f);
    nkviews = 0;
    if (left_host) {
        if (setns(host_nsfd, CLONE_NEWNET) < 0) {
            kernel_ok = 0;
            snprintf(kernel_note, sizeof(kernel_note), "cannot return to the host namespace: %s", strerror(errno));
            return;
        }
        left_host = 0;
    }
    if (!cfg.netns[0]) return;
    struct netns_loc loc;
    if (netns_locate(&cfg, host_rtnl, &loc) < 0) {
        kernel_ok = 0;
        snprintf(kernel_note, sizeof(kernel_note), "namespace not found: %s", loc.desc);
        return;
    }
    if (setns(loc.fd, CLONE_NEWNET) < 0) {
        kernel_ok = 0;
        snprintf(kernel_note, sizeof(kernel_note), "cannot enter the namespace: %s%s", strerror(errno),
                 errno == EPERM ? " (needs root)" : "");
    } else {
        left_host = 1;
    }
    netns_loc_close(&loc);
}

/* Loads cfg for netns (NULL: default). Returns 0, or -1 after printing why. */
static int load_cfg(const char *netns) {
    char err[512] = "";
    if (config_resolve(netns, conf_override, &cfg, conf_path, sizeof(conf_path), err, sizeof(err)) < 0) {
        fprintf(stderr, "bpfcctl: %s\n", err);
        return -1;
    }
    return 0;
}

static int cmd_status(int show_all, int long_fmt);

/* status for the default namespace and every namespace with bpfcd state under the run root. */
static int cmd_status_all(int show_all, int long_fmt) {
    int worst = 0, sections = 0;
    char nsdir[PATH_MAX];
    snprintf(nsdir, sizeof(nsdir), "%s/netns", run_root());
    char names[256][NETNS_NAME_MAX + 1];
    int nnames = 0;
    DIR *d = opendir(nsdir);
    struct dirent *de;
    while (d && (de = readdir(d)) && nnames < 256) {
        if (!netns_name_valid(de->d_name)) continue;
        char st[PATH_MAX + NETNS_NAME_MAX + 32];
        snprintf(st, sizeof(st), "%s/%s/%s", nsdir, de->d_name, STATE_FILE_NAME);
        if (access(st, F_OK) == 0) snprintf(names[nnames++], sizeof(names[0]), "%s", de->d_name);
    }
    if (d) closedir(d);
    qsort(names, nnames, sizeof(names[0]), (int (*)(const void *, const void *))strcmp);

    for (int i = -1; i < nnames; i++) {
        if (load_cfg(i < 0 ? NULL : names[i]) < 0) { worst = worst > 1 ? worst : 1; continue; }
        char st[PATH_MAX + 32];
        snprintf(st, sizeof(st), "%s/%s", cfg.state_dir, STATE_FILE_NAME);
        if (i < 0 && access(st, F_OK) < 0) continue;     /* no bpfcd in the default namespace */
        if (sections++) printf("\n");
        printf("%s==== %s ====%s\n", C_BOLD, i < 0 ? "default namespace" : names[i], C_OFF);
        enter_cfg_netns();
        int rc = cmd_status(show_all, long_fmt);
        if (rc > worst) worst = rc;
    }
    if (!sections) printf("No bpfcd state found (default namespace or %s/*).\n", nsdir);
    return worst;
}

/* Shell assignments for scripts: eval "$(bpfcctl -n NAME env)". */
static void shell_quote(const char *k, const char *v) {
    printf("%s='", k);
    for (; *v; v++) {
        if (*v == '\'') fputs("'\\''", stdout);
        else putchar(*v);
    }
    printf("'\n");
}

static void print_env(int with_file) {
    shell_quote("BPFC_NETNS", cfg.netns);
    char conf[PATH_MAX + 16];
    snprintf(conf, sizeof(conf), "%s", conf_path);
    char *fb = strstr(conf, " (fallback)");
    if (fb) *fb = '\0';
    shell_quote("BPFC_CONF", conf);
    shell_quote("BPFC_CONF_FALLBACK", fb ? "1" : "");
    shell_quote("BPFC_CONFIG_DIR", cfg.config_dir);
    shell_quote("BPFC_STATE_DIR", state_dir());
    shell_quote("BPFC_MAP_DIR", cfg.map_dir[0] ? cfg.map_dir : DEFAULT_MAP_ROOT);
    shell_quote("BPFC_BPFC", cfg.bpfc_path);
    if (with_file && cfg.netns[0]) {
        struct netns_loc loc;
        int rc = netns_locate(&cfg, host_rtnl, &loc);
        shell_quote("BPFC_NETNS_FILE", rc == 0 ? loc.witness : "");
        if (rc == 0) netns_loc_close(&loc);
    }
}

static int cmd_env(void) {
    print_env(1);
    return 0;
}

/* Runs a command inside the namespace, with /sys remounted there and BPFC_* set. */
static int cmd_exec(int argc, char **argv) {
    if (!cfg.netns[0]) {
        fprintf(stderr, "bpfcctl: exec needs -n <namespace>\n");
        return 2;
    }
    if (argc < 1) {
        fprintf(stderr, "Usage: bpfcctl -n <namespace> exec [--] <command> [args...]\n");
        return 2;
    }
    struct netns_loc loc;
    if (netns_locate(&cfg, host_rtnl, &loc) < 0) {
        fprintf(stderr, "bpfcctl: network namespace %s not found: %s\n", cfg.netns, loc.desc);
        return 1;
    }
    char conf[PATH_MAX + 16];
    snprintf(conf, sizeof(conf), "%s", conf_path);
    char *fb = strstr(conf, " (fallback)");
    if (fb) *fb = '\0';
    setenv("BPFC_NETNS", cfg.netns, 1);
    setenv("BPFC_IN_NETNS", cfg.netns, 1);   /* scripts: already inside, do not re-enter */
    setenv("BPFC_CONF", conf, 1);
    setenv("BPFC_CONF_FALLBACK", fb ? "1" : "", 1);
    setenv("BPFC_CONFIG_DIR", cfg.config_dir, 1);
    setenv("BPFC_STATE_DIR", state_dir(), 1);
    setenv("BPFC_MAP_DIR", cfg.map_dir[0] ? cfg.map_dir : DEFAULT_MAP_ROOT, 1);
    setenv("BPFC_BPFC", cfg.bpfc_path, 1);
    setenv("BPFC_NETNS_FILE", loc.witness, 1);
    if (netns_enter_for_exec(loc.fd) < 0) return 1;
    netns_loc_close(&loc);
    if (host_nsfd >= 0) close(host_nsfd);
    if (host_rtnl >= 0) close(host_rtnl);
    execvp(argv[0], argv);
    fprintf(stderr, "bpfcctl: %s: %s\n", argv[0], strerror(errno));
    return 127;
}

/* ======================= main ======================= */

static void usage(void) {
    printf("Usage: bpfcctl [options] [command]\n\n"
           "Commands:\n"
           "  status [-a] [-l]               programs managed by bpfcd (default command)\n"
           "      -a, --all                  also list TC filters and XDP programs bpfcd does not manage\n"
           "      -l, --long                 include install time, size and hash\n"
           "  show <iface> <dir> <prio>      details, source and failure output for one program\n"
           "  show <iface> xdp               the same for the interface's XDP program\n"
           "      -b, --bytecode             also print the kernel's translated bytecode\n"
           "  reload [--no-wait]             make bpfcd rescan and report the result\n"
           "  env                            the paths in use, as shell assignments (for scripts)\n"
           "  exec [--] <command> [args]     run a command inside the -n namespace\n\n"
           "Options:\n"
           "  -n, --netns <name>             the bpfcd instance for network namespace <name>\n"
           "      --all-netns                status: every instance (default namespace and all -n ones)\n"
           "  -c, --config <file>            bpfc.conf to read state_dir from (default %s)\n"
           "  -s, --state-dir <dir>          bpfcd state directory (default from bpfc.conf)\n"
           "      --color=auto|always|never  colorize output (default auto)\n"
           "  -V, --version                  print version\n\n"
           "Exit status of status: 0 all good, 2 some program needs attention, 3 bpfcd not running.\n",
           DEFAULT_CONF_PATH);
}

int main(int argc, char **argv) {
    int show_all = 0, long_fmt = 0, bytecode = 0, nowait = 0, all_netns = 0;
    const char *color = "auto";
    enum { OPT_NOWAIT = 256, OPT_ALL_NETNS };
    static const struct option longopts[] = {
        {"config", required_argument, 0, 'c'}, {"state-dir", required_argument, 0, 's'},
        {"netns", required_argument, 0, 'n'}, {"all-netns", no_argument, 0, OPT_ALL_NETNS},
        {"all", no_argument, 0, 'a'}, {"long", no_argument, 0, 'l'}, {"bytecode", no_argument, 0, 'b'},
        {"no-wait", no_argument, 0, OPT_NOWAIT}, {"color", required_argument, 0, 'C'},
        {"version", no_argument, 0, 'V'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};

    /*
     * Options may follow the command ("status -a"), except after "exec":
     * everything from there on belongs to the command being run.
     */
    int opt_argc = argc;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) break;
        if (a[0] == '-' && a[1]) {
            if ((!strcmp(a, "-c") || !strcmp(a, "-s") || !strcmp(a, "-n") || !strcmp(a, "--config") ||
                 !strcmp(a, "--state-dir") || !strcmp(a, "--netns") || !strcmp(a, "--color")) && i + 1 < argc)
                i++;
            continue;
        }
        if (!strcmp(a, "exec")) opt_argc = i + 1;
        break;
    }
    int o;
    /* "+" would stop at the command; we want options anywhere, so permute (GNU default). */
    while ((o = getopt_long(opt_argc, argv, "c:s:n:albVh", longopts, NULL)) != -1) {
        switch (o) {
        case 'c': conf_override = optarg; break;
        case 'n': netns_arg = optarg; break;
        case OPT_ALL_NETNS: all_netns = 1; break;
        case 's': snprintf(state_dir_override, sizeof(state_dir_override), "%s", optarg); break;
        case 'a': show_all = 1; break;
        case 'l': long_fmt = 1; break;
        case 'b': bytecode = 1; break;
        case OPT_NOWAIT: nowait = 1; break;
        case 'C': color = optarg; break;
        case 'V': printf("bpfcctl %s\n", BPFC_VERSION); return 0;
        case 'h': usage(); return 0;
        default: usage(); return 1;
        }
    }
    use_color = !strcmp(color, "always") || (!strcmp(color, "auto") && isatty(1) && !getenv("NO_COLOR"));

    /* Same resolution and BPFCD_* overrides as bpfcd, so `podman exec` finds a relocated state_dir. */
    char err[512] = "";
    if (config_resolve(netns_arg, conf_override, &cfg, conf_path, sizeof(conf_path), err, sizeof(err)) < 0) {
        if (netns_arg) { fprintf(stderr, "bpfcctl: %s\n", err); return 2; }
        fprintf(stderr, "warning: %s (using defaults)\n", err);
    }
    /* Kept from the start: the way back for --all-netns, and the host side of netns_veth. */
    host_nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    host_rtnl = netns_host_socket();

    const char *cmd = optind < argc ? argv[optind++] : "status";
    if (!strcmp(cmd, "exec") && optind < argc && !strcmp(argv[optind], "--")) optind++;
    int rest = argc - optind;
    char **args = argv + optind;
    if (all_netns) {
        if (strcmp(cmd, "status")) { fprintf(stderr, "bpfcctl: --all-netns applies to status\n"); return 2; }
        return cmd_status_all(show_all, long_fmt);
    }
    if (!strcmp(cmd, "env")) return cmd_env();
    if (!strcmp(cmd, "exec")) return cmd_exec(rest, args);
    if (!strcmp(cmd, "status") || !strcmp(cmd, "show")) enter_cfg_netns();
    if (!strcmp(cmd, "status")) return cmd_status(show_all, long_fmt);
    if (!strcmp(cmd, "show")) return cmd_show(rest, args, bytecode);
    if (!strcmp(cmd, "reload")) return cmd_reload(!nowait);
    if (!strcmp(cmd, "help")) { usage(); return 0; }
    fprintf(stderr, "Unknown command '%s'\n", cmd);
    usage();
    return 1;
}
