/*
 * acl - the bpfc frontend for Cisco IOS access lists (20.acl files).
 *
 * bpfc runs it for a program file whose name ends in .acl (see bpfc(8),
 * FRONTENDS): it reads that file and the definitions in $BPFC_CONF_DIR/acl.d,
 * and prints the bpfc program that applies them. doc/firewall.md explains
 * the syntax; in short, as IOS writes it:
 *
 *   ip access-list standard|extended NAME     access-list <number> ...
 *   ipv6 access-list NAME                     mac access-list extended NAME
 *   object-group network NAME                 object-group service NAME
 *   ip access-group NAME [in|out]             ipv6 traffic-filter NAME [in|out]
 *   mac access-group NAME [in]                ip reflexive-list timeout <s>
 *   ! bpfc option on-failure keep|remove
 *
 * Entries: [seq] permit|deny <protocol> <source> [ports] <destination> [ports]
 * [established] [log|log-input] [fragments] [dscp|precedence|tos <v>]
 * [ttl <op> <n>] [<icmp type> [code]] [ack|fin|psh|rst|syn|urg]
 * [reflect NAME [timeout <s>]]; evaluate NAME; remark ...
 * Anything else is an error naming the keyword: nothing is skipped silently.
 *
 * Output (bpfc): per packet family a section that reads the transport header
 * once (transport), then one block per entry, first match wins. Each entry
 * counts packets and bytes in BPFC_ACL_P / BPFC_ACL_B under a key of its own
 * (ACL name, sequence number, interface), described by meta lines that
 * bpfcctl show access-lists reads. permit continues to the next program,
 * deny drops; each list ends in an implicit deny.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- output */

static char *out;
static size_t outlen, outcap;

static void put(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void put(const char *fmt, ...) {
    va_list ap;
    for (;;) {
        va_start(ap, fmt);
        int n = vsnprintf(out + outlen, outcap - outlen, fmt, ap);
        va_end(ap);
        if (n >= 0 && outlen + (size_t)n + 3 < outcap) { outlen += (size_t)n; break; }
        outcap = outcap ? outcap * 2 : 65536;
        out = realloc(out, outcap);
        if (!out) { perror("realloc"); exit(1); }
    }
    out[outlen++] = ';';
    out[outlen++] = '\n';
    out[outlen] = 0;
}

static const char *cur_file;
static int cur_line;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (cur_file && cur_line) fprintf(stderr, "%s:%d: ", cur_file, cur_line);
    else if (cur_file) fprintf(stderr, "%s: ", cur_file);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

#define GROW(arr, n, cap) do { if ((n) == (cap)) { (cap) = (cap) ? (cap) * 2 : 16; \
    (arr) = realloc((arr), (size_t)(cap) * sizeof(*(arr))); if (!(arr)) { perror("realloc"); exit(1); } } } while (0)

/* ----------------------------------------------------------------- names */

struct name_val { const char *n; int v; };

static const struct name_val tcp_ports[] = {
    {"bgp", 179}, {"chargen", 19}, {"cmd", 514}, {"daytime", 13}, {"discard", 9}, {"domain", 53},
    {"echo", 7}, {"exec", 512}, {"finger", 79}, {"ftp", 21}, {"ftp-data", 20}, {"gopher", 70},
    {"hostname", 101}, {"ident", 113}, {"irc", 194}, {"klogin", 543}, {"kshell", 544}, {"login", 513},
    {"lpd", 515}, {"msrpc", 135}, {"nntp", 119}, {"onep-plain", 15001}, {"onep-tls", 15002},
    {"pim-auto-rp", 496}, {"pop2", 109}, {"pop3", 110}, {"smtp", 25}, {"sunrpc", 111}, {"tacacs", 49},
    {"talk", 517}, {"telnet", 23}, {"time", 37}, {"uucp", 540}, {"whois", 43}, {"www", 80}, {NULL, 0}};
static const struct name_val udp_ports[] = {
    {"biff", 512}, {"bootpc", 68}, {"bootps", 67}, {"discard", 9}, {"dnsix", 195}, {"domain", 53},
    {"echo", 7}, {"isakmp", 500}, {"mobile-ip", 434}, {"nameserver", 42}, {"netbios-dgm", 138},
    {"netbios-ns", 137}, {"netbios-ss", 139}, {"non500-isakmp", 4500}, {"ntp", 123}, {"pim-auto-rp", 496},
    {"rip", 520}, {"ripv6", 521}, {"snmp", 161}, {"snmptrap", 162}, {"sunrpc", 111}, {"syslog", 514},
    {"tacacs", 49}, {"talk", 517}, {"tftp", 69}, {"time", 37}, {"who", 513}, {"xdmcp", 177}, {NULL, 0}};
static const struct name_val protos4[] = {
    {"ahp", 51}, {"eigrp", 88}, {"esp", 50}, {"gre", 47}, {"icmp", 1}, {"igmp", 2}, {"ipinip", 4},
    {"nos", 94}, {"ospf", 89}, {"pcp", 108}, {"pim", 103}, {"tcp", 6}, {"udp", 17}, {NULL, 0}};
static const struct name_val protos6[] = {
    {"ahp", 51}, {"esp", 50}, {"hbh", 0}, {"icmp", 58}, {"pcp", 108}, {"sctp", 132}, {"tcp", 6}, {"udp", 17},
    {NULL, 0}};
/* ICMP names: type * 256 + code, or type * 256 + 255 for "any code" */
#define ANYC 255
static const struct name_val icmp4[] = {
    {"administratively-prohibited", 3 * 256 + 13}, {"alternate-address", 6 * 256 + ANYC},
    {"conversion-error", 31 * 256 + ANYC}, {"dod-host-prohibited", 3 * 256 + 10}, {"dod-net-prohibited", 3 * 256 + 9},
    {"echo", 8 * 256 + ANYC}, {"echo-reply", 0 * 256 + ANYC}, {"general-parameter-problem", 12 * 256 + 0},
    {"host-isolated", 3 * 256 + 8}, {"host-precedence-unreachable", 3 * 256 + 14}, {"host-redirect", 5 * 256 + 1},
    {"host-tos-redirect", 5 * 256 + 3}, {"host-tos-unreachable", 3 * 256 + 12}, {"host-unknown", 3 * 256 + 7},
    {"host-unreachable", 3 * 256 + 1}, {"information-reply", 16 * 256 + ANYC}, {"information-request", 15 * 256 + ANYC},
    {"mask-reply", 18 * 256 + ANYC}, {"mask-request", 17 * 256 + ANYC}, {"mobile-redirect", 32 * 256 + ANYC},
    {"net-redirect", 5 * 256 + 0}, {"net-tos-redirect", 5 * 256 + 2}, {"net-tos-unreachable", 3 * 256 + 11},
    {"net-unreachable", 3 * 256 + 0}, {"network-unknown", 3 * 256 + 6}, {"no-room-for-option", 12 * 256 + 2},
    {"option-missing", 12 * 256 + 1}, {"packet-too-big", 3 * 256 + 4}, {"parameter-problem", 12 * 256 + ANYC},
    {"port-unreachable", 3 * 256 + 3}, {"precedence-unreachable", 3 * 256 + 15}, {"protocol-unreachable", 3 * 256 + 2},
    {"reassembly-timeout", 11 * 256 + 1}, {"redirect", 5 * 256 + ANYC}, {"router-advertisement", 9 * 256 + ANYC},
    {"router-solicitation", 10 * 256 + ANYC}, {"source-quench", 4 * 256 + ANYC}, {"source-route-failed", 3 * 256 + 5},
    {"time-exceeded", 11 * 256 + ANYC}, {"timestamp-reply", 14 * 256 + ANYC}, {"timestamp-request", 13 * 256 + ANYC},
    {"traceroute", 30 * 256 + ANYC}, {"ttl-exceeded", 11 * 256 + 0}, {"unreachable", 3 * 256 + ANYC}, {NULL, 0}};
static const struct name_val icmp6[] = {
    {"beyond-scope", 1 * 256 + 2}, {"destination-unreachable", 1 * 256 + ANYC}, {"echo-reply", 129 * 256 + ANYC},
    {"echo-request", 128 * 256 + ANYC}, {"header", 4 * 256 + 0}, {"hop-limit", 3 * 256 + 0},
    {"mld-query", 130 * 256 + ANYC}, {"mld-reduction", 132 * 256 + ANYC}, {"mld-report", 131 * 256 + ANYC},
    {"nd-na", 136 * 256 + ANYC}, {"nd-ns", 135 * 256 + ANYC}, {"next-header", 4 * 256 + 1}, {"no-admin", 1 * 256 + 1},
    {"no-route", 1 * 256 + 0}, {"packet-too-big", 2 * 256 + ANYC}, {"parameter-option", 4 * 256 + 2},
    {"parameter-problem", 4 * 256 + ANYC}, {"port-unreachable", 1 * 256 + 4}, {"reassembly-timeout", 3 * 256 + 1},
    {"redirect", 137 * 256 + ANYC}, {"renum-command", 138 * 256 + 0}, {"renum-result", 138 * 256 + 1},
    {"renum-seq-number", 138 * 256 + 255}, {"router-advertisement", 134 * 256 + ANYC},
    {"router-renumbering", 138 * 256 + ANYC}, {"router-solicitation", 133 * 256 + ANYC},
    {"time-exceeded", 3 * 256 + ANYC}, {"unreachable", 1 * 256 + ANYC}, {NULL, 0}};
static const struct name_val precedences[] = {
    {"routine", 0}, {"priority", 1}, {"immediate", 2}, {"flash", 3}, {"flash-override", 4}, {"critical", 5},
    {"internet", 6}, {"network", 7}, {NULL, 0}};
static const struct name_val toses[] = {
    {"normal", 0}, {"min-monetary-cost", 1}, {"max-reliability", 2}, {"max-throughput", 4}, {"min-delay", 8},
    {NULL, 0}};
static const struct name_val dscps[] = {
    {"default", 0}, {"af11", 10}, {"af12", 12}, {"af13", 14}, {"af21", 18}, {"af22", 20}, {"af23", 22},
    {"af31", 26}, {"af32", 28}, {"af33", 30}, {"af41", 34}, {"af42", 36}, {"af43", 38}, {"cs1", 8}, {"cs2", 16},
    {"cs3", 24}, {"cs4", 32}, {"cs5", 40}, {"cs6", 48}, {"cs7", 56}, {"ef", 46}, {NULL, 0}};

static int lookup(const struct name_val *t, const char *n, int *v) {
    for (; t->n; t++) if (!strcmp(t->n, n)) { *v = t->v; return 1; }
    return 0;
}

static int num(const char *s, long lo, long hi, long *v) {
    char *e;
    errno = 0;
    long x = strtol(s, &e, s[0] == '0' && (s[1] == 'x' || s[1] == 'X') ? 16 : 10);
    if (errno || *e || e == s || x < lo || x > hi) return 0;
    *v = x;
    return 1;
}

/* ----------------------------------------------------------- data model */

enum { A_PERMIT, A_DENY, A_EVAL };
enum { T_STD, T_EXT, T_V6, T_MAC };
enum { P_NONE, P_EQ, P_NEQ, P_LT, P_GT, P_RANGE };
enum { AD_ANY, AD_V4, AD_V6, AD_GROUP, AD_MAC };

struct ports { int op, n, v[10], lo, hi; };
struct addr {
    int kind;
    uint32_t a, w;            /* IPv4: address and wildcard (host order) */
    unsigned char a6[16];
    int len6;
    char grp[96];
    uint64_t mac, macw;       /* MAC and its wildcard */
};
struct rule {
    int seq, action, proto;   /* proto -1: any IP */
    char svc[96];             /* object-group service used as the protocol */
    struct addr src, dst;
    struct ports sp, dp;
    int established, flags, fragments, dscp, prec, tos, ttlop, ttla, ttlb, itype, icode;
    int log;                  /* 1 log, 2 log-input */
    char reflect[96];
    int rtimeout;             /* seconds, 0: the global timeout */
    char eval[96];
    long etype, emask, vlan;  /* MAC entries: -1 when not given */
    char text[640];
    const char *file;
    int line;
};
struct acl {
    char name[96];
    int type;
    struct rule *r;
    int n, cap, nextseq, used, inline_def;
    const char *file;
    int line;
};
struct gnet {
    unsigned char a[16];
    int len, v6;
};
struct gsvc { int proto; struct ports sp, dp; int itype, icode; };
struct group {
    char name[96];
    int service;
    struct gnet *net;
    struct gsvc *svc;
    int n, cap;
    char sub[16][96];
    int nsub;
    const char *file;
    int line;
};

static struct acl *acls;
static int nacls, capacls;
static struct group *groups;
static int ngroups, capgroups;
static int reflex_timeout = 300;
static const char *opt_on_failure;

struct apply { int family; char name[96]; const char *file; int line; };   /* family: 4, 6, 'm' */
static struct apply applies[3];
static int napplies;

static struct acl *acl_find(const char *n) {
    for (int i = 0; i < nacls; i++) if (!strcmp(acls[i].name, n)) return &acls[i];
    return NULL;
}
static struct group *group_find(const char *n) {
    for (int i = 0; i < ngroups; i++) if (!strcmp(groups[i].name, n)) return &groups[i];
    return NULL;
}

/* ------------------------------------------------------------- parsing */

static int is_interface_file;
static const char *ifname, *hook;

static struct acl *acl_new(const char *name, int type) {
    struct acl *o = acl_find(name);
    if (o) {
        if (o->type != type) die("access list %s was defined at %s:%d as another type", name, o->file, o->line);
        return o;      /* as on IOS: more entries for the same list */
    }
    GROW(acls, nacls, capacls);
    struct acl *a = &acls[nacls++];
    memset(a, 0, sizeof(*a));
    snprintf(a->name, sizeof(a->name), "%s", name);
    a->type = type;
    a->file = cur_file;
    a->line = cur_line;
    a->inline_def = is_interface_file;
    return a;
}

static int valid_name(const char *s) {
    if (!*s || strlen(s) > 64) return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && !strchr("_-.:/+@", *s)) return 0;
    return 1;
}

static int parse_v4(const char *s, uint32_t *a) {
    struct in_addr x;
    if (inet_pton(AF_INET, s, &x) != 1) return 0;
    *a = ntohl(x.s_addr);
    return 1;
}

/* MAC as IOS writes it (0011.2233.4455), or with colons */
static int parse_mac(const char *s, uint64_t *m) {
    unsigned a, b, c;
    char tail;
    if (sscanf(s, "%4x.%4x.%4x%c", &a, &b, &c, &tail) == 3 && strlen(s) == 14) {
        *m = (uint64_t)a << 32 | (uint64_t)b << 16 | c;
        return 1;
    }
    unsigned x[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &tail) == 6) {
        *m = 0;
        for (int i = 0; i < 6; i++) *m = *m << 8 | x[i];
        return 1;
    }
    return 0;
}

static int port_value(const char *s, int proto, int *v) {
    long x;
    if (num(s, 0, 65535, &x)) { *v = (int)x; return 1; }
    if (proto == 6 && lookup(tcp_ports, s, v)) return 1;
    if (proto == 17 && lookup(udp_ports, s, v)) return 1;
    if (proto == -2 && lookup(tcp_ports, s, v)) {     /* tcp-udp in a service group */
        int u;
        if (lookup(udp_ports, s, &u) && u == *v) return 1;
    }
    return 0;
}

/* <op> <port>...: returns tokens used (0 if tok[i] is not an operator) */
static int parse_ports(char **tok, int n, int i, int proto, struct ports *p) {
    if (i >= n) return 0;
    const char *op = tok[i];
    memset(p, 0, sizeof(*p));
    if (!strcmp(op, "eq")) {
        p->op = P_EQ;
        int k = i + 1;
        while (k < n && p->n < 10 && port_value(tok[k], proto, &p->v[p->n])) { p->n++; k++; }
        if (!p->n) die("eq needs a port number or name (%s)", k < n ? tok[k] : "end of line");
        return k - i;
    }
    int code = !strcmp(op, "neq") ? P_NEQ : !strcmp(op, "lt") ? P_LT : !strcmp(op, "gt") ? P_GT :
               !strcmp(op, "range") ? P_RANGE : 0;
    if (!code) return 0;
    p->op = code;
    if (i + 1 >= n || !port_value(tok[i + 1], proto, &p->lo)) die("%s needs a port number or name", op);
    if (code == P_RANGE) {
        if (i + 2 >= n || !port_value(tok[i + 2], proto, &p->hi) || p->hi < p->lo) die("range needs two ports, low and high");
        return 3;
    }
    if (code == P_LT && p->lo == 0) die("lt 0 matches nothing");
    if (code == P_GT && p->lo == 65535) die("gt 65535 matches nothing");
    return 2;
}

/* IPv4 address: any | host A | object-group N | A W (W optional for standard lists) */
static int parse_addr4(char **tok, int n, int i, struct addr *a, int wild_optional) {
    memset(a, 0, sizeof(*a));
    if (i >= n) die("an address is missing");
    if (!strcmp(tok[i], "any")) { a->kind = AD_ANY; return 1; }
    if (!strcmp(tok[i], "host")) {
        if (i + 1 >= n || !parse_v4(tok[i + 1], &a->a)) die("host needs an IPv4 address");
        a->kind = AD_V4;
        return 2;
    }
    if (!strcmp(tok[i], "object-group")) {
        if (i + 1 >= n) die("object-group needs a name");
        a->kind = AD_GROUP;
        snprintf(a->grp, sizeof(a->grp), "%s", tok[i + 1]);
        return 2;
    }
    if (!parse_v4(tok[i], &a->a)) die("'%s' is not an address (any, host A.B.C.D, A.B.C.D WILDCARD or object-group NAME)", tok[i]);
    a->kind = AD_V4;
    if (i + 1 < n && parse_v4(tok[i + 1], &a->w)) { a->a &= ~a->w; return 2; }
    if (!wild_optional) die("%s needs a wildcard mask (or host %s)", tok[i], tok[i]);
    return 1;
}

static int parse_addr6(char **tok, int n, int i, struct addr *a) {
    memset(a, 0, sizeof(*a));
    if (i >= n) die("an address is missing");
    if (!strcmp(tok[i], "any")) { a->kind = AD_ANY; return 1; }
    if (!strcmp(tok[i], "host")) {
        if (i + 1 >= n || inet_pton(AF_INET6, tok[i + 1], a->a6) != 1) die("host needs an IPv6 address");
        a->kind = AD_V6;
        a->len6 = 128;
        return 2;
    }
    if (!strcmp(tok[i], "object-group")) {
        if (i + 1 >= n) die("object-group needs a name");
        a->kind = AD_GROUP;
        snprintf(a->grp, sizeof(a->grp), "%s", tok[i + 1]);
        return 2;
    }
    char b[96];
    snprintf(b, sizeof(b), "%s", tok[i]);
    char *sl = strchr(b, '/');
    long len;
    if (!sl) die("'%s' is not an IPv6 address: any, host X:X::X or X:X::X/<length>", tok[i]);
    *sl = 0;
    if (!num(sl + 1, 0, 128, &len) || inet_pton(AF_INET6, b, a->a6) != 1) die("'%s' is not an IPv6 prefix", tok[i]);
    a->kind = AD_V6;
    a->len6 = (int)len;
    for (int k = 0; k < 16; k++) {
        int bits = (int)len - 8 * k;
        a->a6[k] &= bits >= 8 ? 0xFF : bits <= 0 ? 0 : (unsigned char)(0xFF << (8 - bits));
    }
    return 1;
}

static int parse_addr_mac(char **tok, int n, int i, struct addr *a) {
    memset(a, 0, sizeof(*a));
    if (i >= n) die("a MAC address is missing");
    if (!strcmp(tok[i], "any")) { a->kind = AD_ANY; return 1; }
    if (!strcmp(tok[i], "host")) {
        if (i + 1 >= n || !parse_mac(tok[i + 1], &a->mac)) die("host needs a MAC address (HHHH.HHHH.HHHH)");
        a->kind = AD_MAC;
        return 2;
    }
    if (!parse_mac(tok[i], &a->mac)) die("'%s' is not a MAC address: any, host HHHH.HHHH.HHHH or HHHH.HHHH.HHHH MASK", tok[i]);
    if (i + 1 >= n || !parse_mac(tok[i + 1], &a->macw)) die("%s needs a wildcard mask (or host %s)", tok[i], tok[i]);
    a->kind = AD_MAC;
    a->mac &= ~a->macw;
    return 2;
}

static void text_of(char **tok, int n, int from, char *buf, size_t len) {
    buf[0] = 0;
    size_t o = 0;
    for (int i = from; i < n; i++) {
        int w = snprintf(buf + o, len - o, "%s%s", o ? " " : "", tok[i]);
        if (w < 0 || (size_t)w >= len - o) break;
        o += (size_t)w;
    }
}

static void unsupported(const char *kw) {
    die("'%s' is not supported (bpfc refuses what it cannot apply exactly; see doc/firewall.md)", kw);
}

static void add_rule(struct acl *a, struct rule *r) {
    if (r->seq < 0) r->seq = a->nextseq + 10;
    for (int i = 0; i < a->n; i++)
        if (a->r[i].seq == r->seq) die("access list %s already has an entry %d (%s:%d)", a->name, r->seq, a->r[i].file, a->r[i].line);
    if (r->seq > a->nextseq) a->nextseq = r->seq;
    r->file = cur_file;
    r->line = cur_line;
    GROW(a->r, a->n, a->cap);
    /* entries are kept in sequence order, as IOS shows and applies them */
    int k = a->n++;
    while (k > 0 && a->r[k - 1].seq > r->seq) { a->r[k] = a->r[k - 1]; k--; }
    a->r[k] = *r;
}

/* An entry of an access list: tok[0] is the action (after any sequence number). */
static void parse_entry(struct acl *a, char **tok, int n, int seq) {
    struct rule r;
    memset(&r, 0, sizeof(r));
    r.seq = seq;
    r.proto = -1;
    r.dscp = r.prec = r.tos = r.itype = r.icode = -1;
    r.etype = r.emask = r.vlan = -1;
    int i = 0;
    /* IPv6 lists also take "sequence N" after the entry */
    for (int k = 0; k + 1 < n; k++)
        if (!strcmp(tok[k], "sequence") && a->type == T_V6) {
            long s;
            if (!num(tok[k + 1], 1, 2147483647, &s)) die("sequence needs a number");
            r.seq = (int)s;
            memmove(&tok[k], &tok[k + 2], (size_t)(n - k - 2) * sizeof(*tok));
            n -= 2;
            break;
        }
    if (!strcmp(tok[0], "remark")) return;
    if (!strcmp(tok[0], "evaluate")) {
        if (a->type == T_STD || a->type == T_MAC) die("evaluate is for extended IP and IPv6 lists");
        if (n != 2) die("usage: evaluate <reflexive list name>");
        r.action = A_EVAL;
        snprintf(r.eval, sizeof(r.eval), "%s", tok[1]);
        text_of(tok, n, 0, r.text, sizeof(r.text));
        add_rule(a, &r);
        return;
    }
    if (!strcmp(tok[0], "permit")) r.action = A_PERMIT;
    else if (!strcmp(tok[0], "deny")) r.action = A_DENY;
    else if (!strcmp(tok[0], "dynamic")) unsupported("dynamic");
    else die("'%s': an entry is permit, deny, remark or evaluate", tok[0]);
    text_of(tok, n, 0, r.text, sizeof(r.text));
    i = 1;

    if (a->type == T_MAC) {
        i += parse_addr_mac(tok, n, i, &r.src);
        i += parse_addr_mac(tok, n, i, &r.dst);
        while (i < n) {
            long v, m;
            if (!strcmp(tok[i], "vlan")) {
                if (i + 1 >= n || !num(tok[i + 1], 0, 4095, &v)) die("vlan needs a VLAN id 0-4095");
                r.vlan = v; i += 2;
            } else if (!strcmp(tok[i], "log")) { r.log = 1; i++; }
            else if (!strcmp(tok[i], "cos")) unsupported("cos");
            else if (!strcmp(tok[i], "lsap")) unsupported("lsap");
            else if (num(tok[i], 0, 65535, &v)) {
                if (i + 1 >= n || !num(tok[i + 1], 0, 65535, &m)) die("an EtherType needs a mask: 0x0806 0x0");
                r.etype = v; r.emask = m; i += 2;
            } else die("'%s' is not supported in a MAC list here (an EtherType as number and mask, vlan, log)", tok[i]);
        }
        add_rule(a, &r);
        return;
    }
    if (a->type == T_STD) {
        i += parse_addr4(tok, n, i, &r.src, 1);
        while (i < n) {
            if (!strcmp(tok[i], "log")) { r.log = 1; i++; }
            else die("'%s': a standard list matches the source address only (log is allowed)", tok[i]);
        }
        add_rule(a, &r);
        return;
    }

    int v6 = a->type == T_V6;
    /* protocol */
    if (i >= n) die("the protocol is missing");
    int p;
    long pn;
    if (!strcmp(tok[i], v6 ? "ipv6" : "ip")) { r.proto = -1; i++; }
    else if (!strcmp(tok[i], "object-group")) {
        if (i + 1 >= n) die("object-group needs a name");
        snprintf(r.svc, sizeof(r.svc), "%s", tok[i + 1]);
        i += 2;
    } else if (lookup(v6 ? protos6 : protos4, tok[i], &p)) { r.proto = p; i++; }
    else if (num(tok[i], 0, 255, &pn)) { r.proto = (int)pn; i++; }
    else die("'%s' is not a protocol (%s, tcp, udp, icmp, a number, object-group NAME, ...)", tok[i], v6 ? "ipv6" : "ip");
    int has_ports = r.proto == 6 || r.proto == 17 || r.proto == 132;
    int icmp = r.proto == (v6 ? 58 : 1);
    /* source, ports, destination, ports */
    i += v6 ? parse_addr6(tok, n, i, &r.src) : parse_addr4(tok, n, i, &r.src, 0);
    if (has_ports) i += parse_ports(tok, n, i, r.proto == 132 ? 6 : r.proto, &r.sp);
    i += v6 ? parse_addr6(tok, n, i, &r.dst) : parse_addr4(tok, n, i, &r.dst, 0);
    if (has_ports) i += parse_ports(tok, n, i, r.proto == 132 ? 6 : r.proto, &r.dp);
    /* ICMP type [code] or name */
    if (icmp && i < n) {
        long t, c;
        int nv;
        if (num(tok[i], 0, 255, &t)) {
            r.itype = (int)t; i++;
            if (i < n && num(tok[i], 0, 255, &c)) { r.icode = (int)c; i++; }
        } else if (lookup(v6 ? icmp6 : icmp4, tok[i], &nv)) {
            r.itype = nv >> 8;
            if ((nv & 255) != ANYC) r.icode = nv & 255;
            i++;
        }
    }
    /* options */
    while (i < n) {
        const char *o = tok[i];
        long v;
        int nv;
        if (!strcmp(o, "log")) { r.log = 1; i++; }
        else if (!strcmp(o, "log-input")) { r.log = 2; i++; }
        else if (!strcmp(o, "established")) {
            if (r.proto != 6) die("established is for tcp entries");
            r.established = 1; i++;
        } else if (!strcmp(o, "fragments")) {
            if (r.sp.op || r.dp.op || r.itype >= 0) die("fragments cannot be combined with ports or ICMP types (as on IOS)");
            r.fragments = 1; i++;
        } else if (!strcmp(o, "dscp")) {
            if (i + 1 >= n || !(lookup(dscps, tok[i + 1], &nv) || (num(tok[i + 1], 0, 63, &v) && (nv = (int)v, 1))))
                die("dscp needs a value 0-63 or a name (af11, cs1, ef, default, ...)");
            r.dscp = nv; i += 2;
        } else if (!strcmp(o, "precedence")) {
            if (v6) die("precedence is for IPv4 (use dscp)");
            if (i + 1 >= n || !(lookup(precedences, tok[i + 1], &nv) || (num(tok[i + 1], 0, 7, &v) && (nv = (int)v, 1))))
                die("precedence needs 0-7 or a name (routine, priority, ... network)");
            r.prec = nv; i += 2;
        } else if (!strcmp(o, "tos")) {
            if (v6) die("tos is for IPv4 (use dscp)");
            if (i + 1 >= n || !(lookup(toses, tok[i + 1], &nv) || (num(tok[i + 1], 0, 15, &v) && (nv = (int)v, 1))))
                die("tos needs 0-15 or a name (normal, min-delay, ...)");
            r.tos = nv; i += 2;
        } else if (!strcmp(o, "ttl")) {
            if (v6) unsupported("ttl in an IPv6 list");
            if (i + 2 >= n) die("usage: ttl eq|neq|lt|gt <n> | ttl range <low> <high>");
            const char *op = tok[i + 1];
            r.ttlop = !strcmp(op, "eq") ? P_EQ : !strcmp(op, "neq") ? P_NEQ : !strcmp(op, "lt") ? P_LT :
                      !strcmp(op, "gt") ? P_GT : !strcmp(op, "range") ? P_RANGE : 0;
            if (!r.ttlop || !num(tok[i + 2], 0, 255, &v)) die("usage: ttl eq|neq|lt|gt <n> | ttl range <low> <high>");
            r.ttla = (int)v;
            i += 3;
            if (r.ttlop == P_RANGE) {
                if (i >= n || !num(tok[i], r.ttla, 255, &v)) die("ttl range needs a low and a high value");
                r.ttlb = (int)v; i++;
            }
        } else if (!strcmp(o, "reflect")) {
            if (r.action != A_PERMIT) die("reflect is for permit entries");
            if (i + 1 >= n || !valid_name(tok[i + 1])) die("reflect needs a name");
            snprintf(r.reflect, sizeof(r.reflect), "%s", tok[i + 1]);
            i += 2;
            if (i + 1 < n && !strcmp(tok[i], "timeout")) {
                if (!num(tok[i + 1], 1, 2147483, &v)) die("timeout needs seconds, 1-2147483");
                r.rtimeout = (int)v; i += 2;
            }
        } else if (!strcmp(o, "ack") || !strcmp(o, "fin") || !strcmp(o, "psh") || !strcmp(o, "rst") ||
                   !strcmp(o, "syn") || !strcmp(o, "urg")) {
            if (r.proto != 6) die("%s is for tcp entries", o);
            r.flags |= !strcmp(o, "fin") ? 1 : !strcmp(o, "syn") ? 2 : !strcmp(o, "rst") ? 4 :
                       !strcmp(o, "psh") ? 8 : !strcmp(o, "ack") ? 16 : 32;
            i++;
        } else if (!strcmp(o, "time-range") || !strcmp(o, "option") || !strcmp(o, "match-all") ||
                   !strcmp(o, "match-any") || !strcmp(o, "flow-label") || !strcmp(o, "routing") ||
                   !strcmp(o, "routing-type") || !strcmp(o, "undetermined-transport") || !strcmp(o, "hbh") ||
                   !strcmp(o, "mobility") || !strcmp(o, "mobility-type") || !strcmp(o, "dest-option") ||
                   !strcmp(o, "dest-option-type") || !strcmp(o, "auth") || !strcmp(o, "packet-length")) {
            unsupported(o);
        } else if (icmp && (lookup(v6 ? icmp6 : icmp4, o, &nv) || num(o, 0, 255, &v))) {
            die("'%s': the ICMP type goes right after the destination", o);
        } else if (!has_ports && (!strcmp(o, "eq") || !strcmp(o, "neq") || !strcmp(o, "lt") || !strcmp(o, "gt") || !strcmp(o, "range")))
            die("'%s': ports are for tcp, udp and sctp entries", o);
        else die("'%s' is not an option IOS has here", o);
    }
    if (r.fragments && (r.established || r.flags)) die("fragments cannot be combined with TCP flags (as on IOS)");
    add_rule(a, &r);
}

static void parse_group_entry(struct group *g, char **tok, int n) {
    if (!strcmp(tok[0], "description")) return;
    if (!strcmp(tok[0], "group-object")) {
        if (n != 2) die("usage: group-object <name>");
        if (g->nsub >= 16) die("at most 16 group-object lines per group");
        snprintf(g->sub[g->nsub++], sizeof(g->sub[0]), "%s", tok[1]);
        return;
    }
    if (!g->service) {
        GROW(g->net, g->n, g->cap);
        struct gnet *e = &g->net[g->n];
        memset(e, 0, sizeof(*e));
        uint32_t a, m;
        if (!strcmp(tok[0], "host") && n == 2) {
            if (parse_v4(tok[1], &a)) { a = htonl(a); memcpy(e->a, &a, 4); e->len = 32; }
            else if (inet_pton(AF_INET6, tok[1], e->a) == 1) { e->v6 = 1; e->len = 128; }
            else die("host needs an address");
        } else if (n == 2 && parse_v4(tok[0], &a) && parse_v4(tok[1], &m)) {
            int len = __builtin_popcount(m);
            if (len && (uint32_t)(~0U << (32 - len)) != m) die("%s: an object-group network takes a subnet mask with contiguous bits", tok[1]);
            a &= m;
            a = htonl(a);
            memcpy(e->a, &a, 4);
            e->len = len;
        } else if (n == 1 && strchr(tok[0], '/')) {
            char b[96];
            snprintf(b, sizeof(b), "%s", tok[0]);
            char *sl = strchr(b, '/');
            *sl = 0;
            long len;
            if (parse_v4(b, &a) && num(sl + 1, 0, 32, &len)) {
                a &= len ? ~0U << (32 - len) : 0;
                a = htonl(a); memcpy(e->a, &a, 4); e->len = (int)len;
            } else if (inet_pton(AF_INET6, b, e->a) == 1 && num(sl + 1, 0, 128, &len)) {
                e->v6 = 1; e->len = (int)len;
                for (int k = 0; k < 16; k++) {
                    int bits = (int)len - 8 * k;
                    e->a[k] &= bits >= 8 ? 0xFF : bits <= 0 ? 0 : (unsigned char)(0xFF << (8 - bits));
                }
            } else die("'%s' is not a prefix", tok[0]);
        } else if (!strcmp(tok[0], "range")) unsupported("range in an object-group network");
        else die("'%s': an object-group network entry is host A, A MASK, A/len, group-object or description", tok[0]);
        g->n++;
        return;
    }
    GROW(g->svc, g->n, g->cap);
    struct gsvc *e = &g->svc[g->n];
    memset(e, 0, sizeof(*e));
    e->itype = e->icode = -1;
    int i = 1, p;
    long v;
    if (!strcmp(tok[0], "tcp-udp")) e->proto = -2;
    else if (lookup(protos4, tok[0], &p)) e->proto = p;
    else if (num(tok[0], 0, 255, &v)) e->proto = (int)v;
    else if (!strcmp(tok[0], "ip")) e->proto = -1;
    else die("'%s': a service is tcp, udp, tcp-udp, icmp, a protocol, group-object or description", tok[0]);
    if (e->proto == 6 || e->proto == 17 || e->proto == -2) {
        int pp = e->proto == -2 ? -2 : e->proto;
        if (i < n && !strcmp(tok[i], "source")) {
            i++;
            int used = parse_ports(tok, n, i, pp, &e->sp);
            if (!used) die("source needs eq, lt, gt, neq or range");
            i += used;
        }
        i += parse_ports(tok, n, i, pp, &e->dp);
    } else if (e->proto == 1 && i < n) {
        int nv;
        if (lookup(icmp4, tok[i], &nv)) { e->itype = nv >> 8; if ((nv & 255) != ANYC) e->icode = nv & 255; i++; }
        else if (num(tok[i], 0, 255, &v)) { e->itype = (int)v; i++; }
    }
    if (i != n) die("'%s' is not understood in this service entry", tok[i]);
    g->n++;
}

enum { CTX_NONE, CTX_ACL, CTX_GROUP, CTX_IFACE };

static void parse_file(const char *path, int interface_file) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "%s: %s\n", path, strerror(errno)); exit(1); }
    cur_file = strdup(path);
    cur_line = 0;
    is_interface_file = interface_file;
    int ctx = CTX_NONE;
    struct acl *ca = NULL;
    int cg = -1;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) > 0) {
        cur_line++;
        line[strcspn(line, "\r\n")] = 0;
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (!strncmp(p, "! bpfc option ", 14) || !strncmp(p, "!bpfc option ", 13)) {
            char *o = strstr(p, "option ") + 7;
            if (!strcmp(o, "on-failure keep")) opt_on_failure = "keep";
            else if (!strcmp(o, "on-failure remove")) opt_on_failure = "remove";
            else die("usage: ! bpfc option on-failure keep|remove");
            continue;
        }
        if (!*p || *p == '!' || *p == '#') continue;
        char *tok[96];
        int n = 0;
        for (char *s, *w = strtok_r(p, " \t", &s); w && n < 96; w = strtok_r(NULL, " \t", &s)) tok[n++] = w;
        if (!n) continue;
        if (n == 96) die("line too long");
        const char *k = tok[0];
        int top = !strcmp(k, "ip") || !strcmp(k, "ipv6") || !strcmp(k, "mac") || !strcmp(k, "access-list") ||
                  !strcmp(k, "object-group") || !strcmp(k, "interface") || !strcmp(k, "end") || !strcmp(k, "exit");
        if (!top && ctx == CTX_ACL) {
            long seq = -1;
            int i = 0;
            if (num(tok[0], 1, 2147483647, &seq)) i = 1;
            if (i >= n) die("an entry number needs an entry");
            parse_entry(ca, tok + i, n - i, (int)seq);
            continue;
        }
        if (!top && ctx == CTX_GROUP) { parse_group_entry(&groups[cg], tok, n); continue; }
        if (!top && ctx == CTX_IFACE) die("'%s' is not supported under interface (ip access-group, ipv6 traffic-filter, mac access-group)", k);
        ctx = CTX_NONE;
        if (!strcmp(k, "end") || !strcmp(k, "exit")) continue;
        if (!strcmp(k, "ip") && n >= 3 && !strcmp(tok[1], "access-list")) {
            if (!strcmp(tok[2], "logging") || !strcmp(tok[2], "log-update") || !strcmp(tok[2], "resequence"))
                unsupported(tok[2]);
            if (n != 4 || (strcmp(tok[2], "standard") && strcmp(tok[2], "extended")))
                die("usage: ip access-list standard|extended <name>");
            if (!valid_name(tok[3])) die("'%s' is not a valid access list name", tok[3]);
            ca = acl_new(tok[3], !strcmp(tok[2], "standard") ? T_STD : T_EXT);
            ctx = CTX_ACL;
        } else if (!strcmp(k, "ipv6") && n == 3 && !strcmp(tok[1], "access-list")) {
            if (!valid_name(tok[2])) die("'%s' is not a valid access list name", tok[2]);
            ca = acl_new(tok[2], T_V6);
            ctx = CTX_ACL;
        } else if (!strcmp(k, "mac") && n == 4 && !strcmp(tok[1], "access-list") && !strcmp(tok[2], "extended")) {
            if (!valid_name(tok[3])) die("'%s' is not a valid access list name", tok[3]);
            ca = acl_new(tok[3], T_MAC);
            ctx = CTX_ACL;
        } else if (!strcmp(k, "access-list") && n >= 3) {
            long no;
            if (!num(tok[1], 1, 2699, &no)) die("'%s': numbered lists are 1-99, 1300-1999 (standard), 100-199, 2000-2699 (extended)", tok[1]);
            int std = (no >= 1 && no <= 99) || (no >= 1300 && no <= 1999);
            int ext = (no >= 100 && no <= 199) || (no >= 2000 && no <= 2699);
            if (!std && !ext) die("'%s': numbered lists are 1-99, 1300-1999 (standard), 100-199, 2000-2699 (extended)", tok[1]);
            if (!strcmp(tok[2], "dynamic")) unsupported("dynamic");
            struct acl *na = acl_new(tok[1], std ? T_STD : T_EXT);
            parse_entry(na, tok + 2, n - 2, -1);
        } else if (!strcmp(k, "object-group") && n == 3 && (!strcmp(tok[1], "network") || !strcmp(tok[1], "service"))) {
            if (!valid_name(tok[2])) die("'%s' is not a valid object-group name", tok[2]);
            struct group *og = group_find(tok[2]);
            if (og && og->service != !strcmp(tok[1], "service"))
                die("object-group %s was defined at %s:%d as another kind", tok[2], og->file, og->line);
            if (!og) {
                GROW(groups, ngroups, capgroups);
                og = &groups[ngroups++];
                memset(og, 0, sizeof(*og));
                snprintf(og->name, sizeof(og->name), "%s", tok[2]);
                og->service = !strcmp(tok[1], "service");
                og->file = cur_file;
                og->line = cur_line;
            }
            cg = (int)(og - groups);
            ctx = CTX_GROUP;
        } else if (!strcmp(k, "ip") && n == 4 && !strcmp(tok[1], "reflexive-list") && !strcmp(tok[2], "timeout")) {
            long v;
            if (!num(tok[3], 1, 2147483, &v)) die("ip reflexive-list timeout needs seconds");
            reflex_timeout = (int)v;
        } else if (!strcmp(k, "interface") && n == 2) {
            if (!interface_file) die("interface lines belong in the interface's own file, not in acl.d");
            if (ifname && *ifname && strcmp(tok[1], ifname))
                die("this file is attached to %s, but it says interface %s", ifname, tok[1]);
            ctx = CTX_IFACE;
        } else if ((!strcmp(k, "ip") && n >= 3 && !strcmp(tok[1], "access-group")) ||
                   (!strcmp(k, "ipv6") && n >= 3 && !strcmp(tok[1], "traffic-filter")) ||
                   (!strcmp(k, "mac") && n >= 3 && !strcmp(tok[1], "access-group"))) {
            if (!interface_file) die("%s %s belongs in an interface's file (interfaces.d/<interface>/<ingress|egress>/<prio>.acl)", k, tok[1]);
            if (n > 4) die("usage: %s %s <name> [in|out]", k, tok[1]);
            if (n == 4 && strcmp(tok[3], "in") && strcmp(tok[3], "out")) die("the direction is in or out");
            const char *want = hook && !strcmp(hook, "egress") ? "out" : "in";
            if (n == 4 && hook && *hook && strcmp(tok[3], want))
                die("'%s %s %s %s' in a file for %s: the directory decides the direction", k, tok[1], tok[2], tok[3], hook);
            int fam = k[2] == 'v' ? 6 : k[0] == 'm' ? 'm' : 4;
            if (fam == 'm' && n == 4 && !strcmp(tok[3], "out")) die("mac access-group applies inbound only (as on IOS)");
            for (int a = 0; a < napplies; a++)
                if (applies[a].family == fam) die("a second %s %s in one file", k, tok[1]);
            struct apply *ap = &applies[napplies++];
            ap->family = fam;
            snprintf(ap->name, sizeof(ap->name), "%s", tok[2]);
            ap->file = cur_file;
            ap->line = cur_line;
            ctx = CTX_NONE;
        } else {
            die("'%s' is not supported here (access lists, object groups, access-group lines; see doc/firewall.md)", k);
        }
    }
    free(line);
    fclose(f);
}

/* ------------------------------------------------------------- emitting */

static uint64_t fmix(uint64_t k) {
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
    return k;
}
static uint64_t str_hash(const char *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 0x100000001b3ULL; }
    return fmix(h);
}
static unsigned long ifindex_v;

/* The counter key of an entry (or seq 0: the implicit deny) on this interface */
static uint64_t rule_key(const char *acl, int seq) {
    uint64_t k = fmix(str_hash(acl) ^ fmix((uint64_t)seq + 0x9e3779b97f4a7c15ULL) ^ ((uint64_t)ifindex_v << 1));
    return k ? k : 1;
}

/* A map name for an object, within bpfc's 31 characters of [A-Za-z0-9_.-] */
static void map_name(char *buf, size_t len, const char *prefix, const char *name) {
    char clean[96];
    size_t o = 0;
    for (const char *p = name; *p && o < sizeof(clean) - 1; p++)
        clean[o++] = (isalnum((unsigned char)*p) || *p == '_' || *p == '-' || *p == '.') ? *p : '_';
    clean[o] = 0;
    if (strlen(prefix) + o <= 31 && !strcmp(clean, name)) snprintf(buf, len, "%s%s", prefix, clean);
    else snprintf(buf, len, "%s%.14s_%08llx", prefix, clean, (unsigned long long)(str_hash(name) & 0xffffffffULL));
}

static int group_depth;
/* All prefixes of a network group, nested groups included, into one map */
static void emit_group_prefixes(const char *mapn, struct group *g, int v6) {
    if (++group_depth > 8) die("object-group %s: group-object nested too deep (or a loop)", g->name);
    for (int i = 0; i < g->n; i++) {
        struct gnet *e = &g->net[i];
        if (e->v6 != v6) continue;
        char a[64];
        inet_ntop(v6 ? AF_INET6 : AF_INET, e->a, a, sizeof(a));
        put("prefix %s %s/%d", mapn, a, e->len);
    }
    for (int i = 0; i < g->nsub; i++) {
        struct group *s = group_find(g->sub[i]);
        if (!s || s->service) die("object-group %s: group-object %s is not a network group", g->name, g->sub[i]);
        emit_group_prefixes(mapn, s, v6);
    }
    group_depth--;
}

/* Declared once per program */
static char declared[256][40];
static int ndeclared;
static int declare(const char *kind, const char *name) {
    char k[40];
    snprintf(k, sizeof(k), "%.3s:%s", kind, name);
    for (int i = 0; i < ndeclared; i++) if (!strcmp(declared[i], k)) return 0;
    if (ndeclared < 256) snprintf(declared[ndeclared++], sizeof(declared[0]), "%s", k);
    return 1;
}

static const char *net_group_map(const char *gname, int v6) {
    static char buf[64];
    struct group *g = group_find(gname);
    if (!g) die("object-group %s is not defined (in this file or %s)", gname, "acl.d");
    if (g->service) die("object-group %s is a service group; an address needs a network group", gname);
    map_name(buf, sizeof(buf), v6 ? "OGN6_" : "OGN_", gname);
    if (declare("ogn", buf)) {
        put("prefix-map %s 4096%s static", buf, v6 ? " ipv6" : "");
        group_depth = 0;
        emit_group_prefixes(buf, g, v6);
    }
    return buf;
}

static int opened;                 /* blocks opened for the entry being emitted */
static int terminated;             /* an entry matched everything: the rest never runs */
static void cond(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void cond(const char *fmt, ...) {
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    put("%s", b);
    opened++;
}
static void close_all(void) { while (opened > 0) { put("end-match"); opened--; } }

static void emit_addr(const char *field, const struct addr *a, int v6) {
    char b[64], m[64];
    struct in_addr x;
    switch (a->kind) {
    case AD_ANY: return;
    case AD_V4:
        x.s_addr = htonl(a->a);
        inet_ntop(AF_INET, &x, b, sizeof(b));
        if (!a->w) { cond("match %s %s", field, b); return; }
        x.s_addr = htonl(~a->w);
        inet_ntop(AF_INET, &x, m, sizeof(m));
        cond("match %s %s/%s", field, b, m);
        return;
    case AD_V6:
        inet_ntop(AF_INET6, a->a6, b, sizeof(b));
        cond("match %s %s/%d", field, b, a->len6);
        return;
    case AD_GROUP:
        cond("match %s in %s", field, net_group_map(a->grp, v6));
        return;
    }
}

static void emit_ports(const char *var, const struct ports *p, int eqv) {
    switch (p->op) {
    case P_NONE: return;
    case P_EQ: cond("if %s eq %d", var, eqv); return;
    case P_NEQ: cond("if %s ne %d", var, p->lo); return;
    case P_LT: cond("if %s lt %d", var, p->lo); return;
    case P_GT: cond("if %s gt %d", var, p->lo); return;
    case P_RANGE: cond("if %s ge %d", var, p->lo); cond("if %s le %d", var, p->hi); return;
    }
}

static int any_log, section_log;
static const char *acl_name_cur;
static int acl_type_cur;

static void reflect_key(int v6) {
    put("hash __RK 64 symmetric %s %s %%LP:8 src-port dst-port icmp-id", v6 ? "ip6-src" : "ip-src", v6 ? "ip6-dst" : "ip-dst");
}

/* 2^20 ns ticks (about 1.05 ms) for s seconds */
static unsigned long long ticks(long s) { return (unsigned long long)((s * 1000000000.0) / (1 << 20) + 0.5); }

/* The body of an entry that matched: which entry (AK), what to do (M),
 * whether to log (LG), and a reflexive entry to make. Counting, logging and
 * acting happen once, after the entries (emit_tail), so an entry costs only
 * its comparisons. */
static void emit_body(const struct rule *r, int v6, int family) {
    if (opened == 1) terminated = 1;      /* nothing but "not matched yet": matches everything */
    uint64_t key = rule_key(acl_name_cur, r->seq);
    put("set val AK 0x%016llx", (unsigned long long)key);
    put("set val M %d", r->action == A_DENY ? 2 : 1);
    if (r->log) { any_log = section_log = 1; put("set val LG 1"); }
    if (r->reflect[0]) {
        char mn[64];
        map_name(mn, sizeof(mn), "RFX_", r->reflect);
        if (declare("rfx", mn)) put("hash-map %s 65536", mn);
        long to = r->rtimeout ? r->rtimeout : reflex_timeout;
        reflect_key(v6);
        put("get time __RN");
        put("calc rsh __RN 20");
        put("set val __RV %%__RN");
        put("calc add __RV %llu", ticks(to));
        put("set val __T %%TF");
        put("calc and __T 5");                  /* FIN or RST: the entry ends 5 s later */
        put("if __T ne 0");
        put("set val __RV %%__RN");
        put("calc add __RV %llu", ticks(5));
        put("end-if");
        put("calc or __RV %llu", (unsigned long long)ticks(to) << 40);
        put("set map %s %%__RK %%__RV", mn);
    }
    (void)family;
}

/* One variant of an entry (a service group entry and an eq port picked). */
static void emit_variant(const struct rule *r, int v6, int family, int proto, const struct ports *sp, int spv,
                         const struct ports *dp, int dpv, int itype, int icode, int frag_mode) {
    if (terminated) return;
    opened = 0;
    cond("if M eq 0");
    if (family == 'm') {
        if (r->src.kind == AD_MAC) {
            put("pack __M src-mac");
            put("calc and __M %llu", (unsigned long long)(~r->src.macw & 0xFFFFFFFFFFFFULL));
            cond("if __M eq %llu", (unsigned long long)r->src.mac);
        }
        if (r->dst.kind == AD_MAC) {
            put("pack __M dst-mac");
            put("calc and __M %llu", (unsigned long long)(~r->dst.macw & 0xFFFFFFFFFFFFULL));
            cond("if __M eq %llu", (unsigned long long)r->dst.mac);
        }
        if (r->etype >= 0) {
            put("set val __M %%ET");
            put("calc and __M %ld", ~r->emask & 0xFFFF);
            cond("if __M eq %ld", r->etype & ~r->emask & 0xFFFF);
        }
        if (r->vlan >= 0) { put("pack __M vlan-id"); cond("if __M eq %ld", r->vlan); }
        emit_body(r, 0, family);
        close_all();
        return;
    }
    /* frag_mode: 0 every packet, 1 first fragments and whole packets, 2 later fragments only */
    if (frag_mode == 1) cond("if NF eq 0");
    if (frag_mode == 2) cond("if NF ne 0");
    if (proto >= 0) cond("if LP eq %d", proto);
    emit_addr(v6 ? "ip6-src" : "ip-src", &r->src, v6);
    emit_addr(v6 ? "ip6-dst" : "ip-dst", &r->dst, v6);
    if (frag_mode != 2) {
        emit_ports("SP", sp, spv);
        emit_ports("DP", dp, dpv);
        if (r->established) { put("set val __T %%TF"); put("calc and __T 20"); cond("if __T ne 0"); }
        if (r->flags) { put("set val __T %%TF"); put("calc and __T %d", r->flags); cond("if __T eq %d", r->flags); }
        if (itype >= 0) cond("if IT eq %d", itype);
        if (icode >= 0) cond("if IC eq %d", icode);
    }
    if (r->dscp >= 0) cond("match dscp %d", r->dscp);
    if (r->prec >= 0) { put("get ip-tos __TS"); put("calc rsh __TS 5"); cond("if __TS eq %d", r->prec); }
    if (r->tos >= 0) { put("get ip-tos __TS"); put("calc rsh __TS 1"); put("calc and __TS 15"); cond("if __TS eq %d", r->tos); }
    if (r->ttlop) {
        put("get ip-ttl __TT");
        switch (r->ttlop) {
        case P_EQ: cond("if __TT eq %d", r->ttla); break;
        case P_NEQ: cond("if __TT ne %d", r->ttla); break;
        case P_LT: cond("if __TT lt %d", r->ttla); break;
        case P_GT: cond("if __TT gt %d", r->ttla); break;
        case P_RANGE: cond("if __TT ge %d", r->ttla); cond("if __TT le %d", r->ttlb); break;
        }
    }
    emit_body(r, v6, family);
    close_all();
}

/* An entry: expanded over its service group and eq port lists; with
 * transport information, later fragments are matched on the rest only by
 * permit entries (IOS's rule for non-initial fragments). */
static void emit_rule(const struct rule *r, int v6, int family) {
    if (terminated) return;
    if (r->action == A_EVAL) {
        char mn[64];
        map_name(mn, sizeof(mn), "RFX_", r->eval);
        if (declare("rfx", mn)) put("hash-map %s 65536", mn);
        put("if M eq 0");
        reflect_key(v6);
        put("get map %s %%__RK __RV", mn);
        put("if __RV ne 0");
        put("get time __RN");
        put("calc rsh __RN 20");
        put("set val __RE %%__RV");
        put("calc and __RE 1099511627775");
        put("if __RE gt %%__RN");
        put("set val __RT %%__RV");
        put("calc rsh __RT 40");
        put("set val __T %%TF");
        put("calc and __T 5");
        put("if __T ne 0");
        put("set val __RT %llu", ticks(5));
        put("end-if");
        put("set val __RE %%__RN");
        put("calc add __RE %%__RT");
        put("set val __RV %%__RT");
        put("calc lsh __RV 40");
        put("calc or __RV %%__RE");
        put("set map %s %%__RK %%__RV", mn);
        put("set val AK 0x%016llx", (unsigned long long)rule_key(acl_name_cur, r->seq));
        put("set val M 1");
        put("end-if");
        put("end-if");
        put("end-if");
        return;
    }
    if (family == 'm') { emit_variant(r, 0, family, -1, NULL, 0, NULL, 0, -1, -1, 0); return; }

    /* the protocol/port alternatives: from the service group, or the entry itself */
    struct gsvc alts[64];
    int nalt = 0;
    if (r->svc[0]) {
        struct group *g = group_find(r->svc);
        if (!g) die("object-group %s is not defined", r->svc);
        if (!g->service) die("object-group %s is a network group; a protocol needs a service group", r->svc);
        struct group *stack[16] = {g};
        int sn = 1, guard = 0;
        while (sn > 0) {
            struct group *x = stack[--sn];
            if (++guard > 32) die("object-group %s: group-object nested too deep (or a loop)", r->svc);
            for (int i = 0; i < x->n; i++) {
                if (nalt >= 64) die("object-group %s: more than 64 services", r->svc);
                alts[nalt] = x->svc[i];
                if (alts[nalt].proto == -2) {          /* tcp-udp: both */
                    alts[nalt].proto = 6;
                    if (nalt + 1 >= 64) die("object-group %s: more than 64 services", r->svc);
                    alts[nalt + 1] = alts[nalt];
                    alts[nalt + 1].proto = 17;
                    nalt++;
                }
                if (v6 && alts[nalt].proto == 1) alts[nalt].proto = 58;
                nalt++;
            }
            for (int i = 0; i < x->nsub && sn < 16; i++) {
                struct group *s = group_find(x->sub[i]);
                if (!s || !s->service) die("object-group %s: group-object %s is not a service group", x->name, x->sub[i]);
                stack[sn++] = s;
            }
        }
        if (!nalt) die("object-group %s has no services", r->svc);
    } else {
        memset(&alts[0], 0, sizeof(alts[0]));
        alts[0].proto = r->proto;
        alts[0].sp = r->sp;
        alts[0].dp = r->dp;
        alts[0].itype = r->itype;
        alts[0].icode = r->icode;
        nalt = 1;
    }
    for (int a = 0; a < nalt; a++) {
        const struct gsvc *s = &alts[a];
        int l4 = s->sp.op || s->dp.op || s->itype >= 0 || r->established || r->flags;
        int ns = s->sp.op == P_EQ ? s->sp.n : 1, nd = s->dp.op == P_EQ ? s->dp.n : 1;
        if (r->fragments) { emit_variant(r, v6, family, s->proto, &s->sp, 0, &s->dp, 0, -1, -1, 2); continue; }
        for (int i = 0; i < ns; i++)
            for (int j = 0; j < nd; j++)
                emit_variant(r, v6, family, s->proto, &s->sp, s->sp.op == P_EQ ? s->sp.v[i] : 0, &s->dp,
                             s->dp.op == P_EQ ? s->dp.v[j] : 0, s->itype, s->icode, l4 ? 1 : 0);
        /* a later fragment carries no transport header: a permit entry with
         * transport conditions matches it on the rest, a deny entry does not */
        if (l4 && r->action == A_PERMIT)
            emit_variant(r, v6, family, s->proto, &s->sp, 0, &s->dp, 0, -1, -1, 2);
    }
}

static const char *type_name(int t) {
    return t == T_STD ? "standard" : t == T_EXT ? "extended" : t == T_V6 ? "ipv6" : "mac";
}

static void emit_meta(const struct acl *a, const char *dir) {
    put("meta acl %s %s %s %s", type_name(a->type), a->name, dir, ifname && *ifname ? ifname : "-");
    for (int i = 0; i < a->n; i++) {
        const struct rule *r = &a->r[i];
        put("meta acl-rule %s %d %016llx %s %d %s", a->name, r->seq, (unsigned long long)rule_key(a->name, r->seq),
            r->action == A_PERMIT ? "permit" : r->action == A_DENY ? "deny" : "evaluate", r->log, r->text);
    }
    put("meta acl-rule %s implicit %016llx deny 0 %s", a->name, (unsigned long long)rule_key(a->name, 0),
        a->type == T_V6 ? "deny ipv6 any any" : a->type == T_MAC ? "deny any any" : a->type == T_STD ? "deny any" : "deny ip any any");
}

static void emit_acl(struct acl *a, int family) {
    acl_name_cur = a->name;
    acl_type_cur = a->type;
    int v6 = family == 6;
    if (family == 'm') {
        put("pack ET eth-proto");
        put("if ET ne 2048");
        put("if ET ne 34525");
    } else {
        put(v6 ? "match ip6" : "match ip");
        put("transport LP SP DP TF IT IC NF");
    }
    terminated = section_log = 0;
    for (int i = 0; i < a->n; i++) emit_rule(&a->r[i], v6, family);
    if (v6 && !terminated) {
        /* IOS: every IPv6 list ends in permit icmp any any nd-na, nd-ns
         * (uncounted, as IOS shows no matches for them), deny ipv6 any any */
        put("if M eq 0");
        put("if LP eq 58");
        put("if IT ge 135");
        put("if IT le 136");
        put("set val M 3");
        put("end-if");
        put("end-if");
        put("end-if");
        put("end-if");
    }
    if (!terminated) {
        put("if M eq 0");
        put("set val AK 0x%016llx", (unsigned long long)rule_key(a->name, 0));
        put("set val M 2");
        put("end-if");
    }
    /* once per packet: count the entry, log (a flow's first packet, then at
     * most every 5 minutes, as IOS does), act */
    put("if M lt 3");
    put("count BPFC_ACL_P BPFC_ACL_B %%AK");
    put("end-if");
    if (section_log) {
        put("if LG ne 0");
        if (family == 'm') put("hash __LK 64 %%AK src-mac dst-mac eth-proto");
        else put("hash __LK 64 %%AK %s %s %%LP:8 %%SP:16 %%DP:16", v6 ? "ip6-src" : "ip-src", v6 ? "ip6-dst" : "ip-dst");
        put("match seen BPFC_ACL_LOGSEEN %%__LK within 300s");
        put("else");
        put("log BPFC_ACL_LOG %%AK 128");
        put("end-match");
        put("end-if");
    }
    put("if M eq 2");
    put("drop");
    put("end-if");
    put("continue");
    put("end-match");
    if (family == 'm') put("end-match");
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: acl <file.acl>   (run by bpfc for .acl program files; see bpfc(8), FRONTENDS)\n");
        return 2;
    }
    ifname = getenv("BPFC_IFNAME");
    hook = getenv("BPFC_HOOK");
    const char *ix = getenv("BPFC_IFINDEX");
    ifindex_v = ix && *ix ? strtoul(ix, NULL, 10) : 0;
    const char *conf = getenv("BPFC_CONF_DIR");
    const char *l3 = getenv("BPFC_L3OFF");

    /* definitions first (acl.d, in name order), then the interface's file */
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s/acl.d", conf && *conf ? conf : "/etc/bpfc");
    char *files[1024];
    int nf = 0;
    DIR *d = opendir(dir);
    struct dirent *de;
    while (d && (de = readdir(d)) && nf < 1024) {
        size_t l = strlen(de->d_name);
        if (de->d_name[0] == '.' || l < 5 || strcmp(de->d_name + l - 4, ".acl")) continue;
        char *p = malloc(strlen(dir) + l + 2);
        if (!p) { perror("malloc"); return 1; }
        sprintf(p, "%s/%s", dir, de->d_name);
        files[nf++] = p;
    }
    if (d) closedir(d);
    qsort(files, (size_t)nf, sizeof(files[0]), cmp_str);
    for (int i = 0; i < nf; i++) parse_file(files[i], 0);
    parse_file(argv[1], 1);
    cur_file = argv[1];
    cur_line = 0;

    /* no access-group line: the lists defined in the file apply, one per family */
    if (!napplies) {
        int seen[3] = {0};
        for (int i = 0; i < nacls; i++) {
            if (!acls[i].inline_def) continue;
            int fam = acls[i].type == T_V6 ? 6 : acls[i].type == T_MAC ? 'm' : 4;
            int slot = fam == 4 ? 0 : fam == 6 ? 1 : 2;
            if (seen[slot]++) die("more than one %s list in this file: say which applies with %s", fam == 4 ? "IPv4" : fam == 6 ? "IPv6" : "MAC",
                                  fam == 4 ? "ip access-group NAME" : fam == 6 ? "ipv6 traffic-filter NAME" : "mac access-group NAME");
            struct apply *ap = &applies[napplies++];
            ap->family = fam;
            snprintf(ap->name, sizeof(ap->name), "%s", acls[i].name);
        }
        if (!napplies) die("nothing to apply: define an access list here or name one with ip access-group NAME");
    }
    struct acl *chosen[3] = {NULL, NULL, NULL};
    for (int i = 0; i < napplies; i++) {
        cur_file = applies[i].file ? applies[i].file : argv[1];
        cur_line = applies[i].line;
        struct acl *a = acl_find(applies[i].name);
        if (!a) die("access list %s is not defined (in this file or %s/*.acl)", applies[i].name, dir);
        int fam = applies[i].family;
        if (fam == 4 && a->type != T_STD && a->type != T_EXT) die("%s is not an IPv4 access list", a->name);
        if (fam == 6 && a->type != T_V6) die("%s is not an IPv6 access list (ipv6 traffic-filter takes those)", a->name);
        if (fam == 'm' && a->type != T_MAC) die("%s is not a MAC access list", a->name);
        if (fam == 'm' && l3 && !strcmp(l3, "0")) die("a MAC access list needs an Ethernet header; this interface has none");
        if (fam == 'm' && hook && !strcmp(hook, "egress")) die("mac access-group applies inbound only (as on IOS)");
        chosen[fam == 4 ? 0 : fam == 6 ? 1 : 2] = a;
    }

    const char *dirw = hook && !strcmp(hook, "egress") ? "out" : "in";
    char nm[80];
    int o = snprintf(nm, sizeof(nm), "acl");
    for (int k = 0; k < 3; k++)
        if (chosen[k] && o < (int)sizeof(nm))
            o += snprintf(nm + o, sizeof(nm) - (size_t)o, " %s%s", k == 1 ? "v6:" : k == 2 ? "mac:" : "", chosen[k]->name);
    if (strlen(nm) > 60) nm[60] = 0;
    put("name %s %s", nm, dirw);
    if (opt_on_failure) put("option on-failure %s", opt_on_failure);
    for (int i = 0; i < nf; i++) put("depends %s", files[i]);
    put("hash-map BPFC_ACL_P 65536");
    put("hash-map BPFC_ACL_B 65536");
    put("decl AK 8");
    put("decl M 8");
    put("decl LG 8");
    /* scratch: declared once, so a variable set in one entry's block is
     * known (and zeroed) everywhere */
    static const char *scratch[] = {"__T", "__M", "__TS", "__TT", "__LK", "__RK", "__RV", "__RN", "__RE", "__RT"};
    for (size_t i = 0; i < sizeof(scratch) / sizeof(scratch[0]); i++) put("decl %s 8", scratch[i]);
    for (int k = 0; k < 3; k++) if (chosen[k]) emit_meta(chosen[k], dirw);
    /* the log maps are declared before the entries use them */
    size_t mark = outlen;
    if (chosen[2]) emit_acl(chosen[2], 'm');
    if (chosen[0]) emit_acl(chosen[0], 4);
    if (chosen[1]) emit_acl(chosen[1], 6);
    if (any_log) {
        char *rest = strdup(out + mark);
        if (!rest) { perror("strdup"); return 1; }
        outlen = mark;
        out[outlen] = 0;
        put("ringbuf-map BPFC_ACL_LOG 262144");
        put("hash-map BPFC_ACL_LOGSEEN 65536");
        size_t rl = strlen(rest);
        while (outlen + rl + 1 > outcap) { outcap *= 2; out = realloc(out, outcap); if (!out) return 1; }
        memcpy(out + outlen, rest, rl + 1);
        outlen += rl;
        free(rest);
    }
    fwrite(out, 1, outlen, stdout);
    return 0;
}
