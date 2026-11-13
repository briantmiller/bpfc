/*
 * Minimal JSON writer and parser; see json.h.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "json.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ======================= writer ======================= */

void jb_init(struct jbuf *b, int pretty) {
    memset(b, 0, sizeof(*b));
    b->pretty = pretty;
}

void jb_free(struct jbuf *b) {
    free(b->s);
    b->s = NULL;
    b->len = b->cap = 0;
}

void jb_raw(struct jbuf *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 1024;
        while (nc < b->len + n + 1) nc *= 2;
        char *ns = realloc(b->s, nc);
        if (!ns) { b->oom = 1; return; }
        b->s = ns;
        b->cap = nc;
    }
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = '\0';
}

static void put(struct jbuf *b, const char *s) { jb_raw(b, s, strlen(s)); }

static void newline(struct jbuf *b, int depth) {
    if (!b->pretty) return;
    put(b, "\n");
    for (int i = 0; i < depth; i++) put(b, "  ");
}

/* Separator and indentation before a value or key at the current level. */
static void before_value(struct jbuf *b) {
    if (b->after_key) { b->after_key = 0; return; }
    if (b->depth == 0) return;
    int d = b->depth < JSON_MAX_DEPTH ? b->depth : JSON_MAX_DEPTH - 1;
    if (b->count[d]++) put(b, ",");
    newline(b, b->depth);
}

static void open_level(struct jbuf *b, const char *c) {
    before_value(b);
    put(b, c);
    b->depth++;
    if (b->depth < JSON_MAX_DEPTH) b->count[b->depth] = 0;
}

static void close_level(struct jbuf *b, const char *c) {
    int d = b->depth < JSON_MAX_DEPTH ? b->depth : JSON_MAX_DEPTH - 1;
    int had = b->count[d];
    if (b->depth > 0) b->depth--;
    if (had) newline(b, b->depth);
    put(b, c);
    if (b->depth == 0 && b->pretty) put(b, "\n");
}

void jb_obj(struct jbuf *b) { open_level(b, "{"); }
void jb_obj_end(struct jbuf *b) { close_level(b, "}"); }
void jb_arr(struct jbuf *b) { open_level(b, "["); }
void jb_arr_end(struct jbuf *b) { close_level(b, "]"); }

/* Length of the valid UTF-8 sequence at p (n bytes left), or 0 if invalid. */
static size_t utf8_seq(const unsigned char *p, size_t n) {
    if (p[0] < 0x80) return 1;
    size_t len;
    uint32_t cp;
    if ((p[0] & 0xe0) == 0xc0) { len = 2; cp = p[0] & 0x1f; }
    else if ((p[0] & 0xf0) == 0xe0) { len = 3; cp = p[0] & 0x0f; }
    else if ((p[0] & 0xf8) == 0xf0) { len = 4; cp = p[0] & 0x07; }
    else return 0;
    if (len > n) return 0;
    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (p[i] & 0x3f);
    }
    /* overlong forms, UTF-16 surrogates and values beyond Unicode are not UTF-8 */
    if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return 0;
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
    return len;
}

static void put_escaped(struct jbuf *b, const char *v, size_t n) {
    put(b, "\"");
    const unsigned char *p = (const unsigned char *)v;
    size_t i = 0, run = 0;
    while (i < n) {
        unsigned char c = p[i];
        const char *esc = NULL;
        char tmp[8];
        size_t seq = 1;
        if (c == '"') esc = "\\\"";
        else if (c == '\\') esc = "\\\\";
        else if (c == '\n') esc = "\\n";
        else if (c == '\r') esc = "\\r";
        else if (c == '\t') esc = "\\t";
        else if (c == '\b') esc = "\\b";
        else if (c == '\f') esc = "\\f";
        else if (c < 0x20 || c == 0x7f) { snprintf(tmp, sizeof(tmp), "\\u%04x", c); esc = tmp; }
        else if (c >= 0x80) {
            seq = utf8_seq(p + i, n - i);
            if (!seq) { esc = "\\ufffd"; seq = 1; }
        }
        if (esc) {
            if (run) jb_raw(b, v + i - run, run);
            run = 0;
            put(b, esc);
            i += seq;
        } else {
            run += seq;
            i += seq;
        }
    }
    if (run) jb_raw(b, v + n - run, run);
    put(b, "\"");
}

void jb_key(struct jbuf *b, const char *k) {
    before_value(b);
    put_escaped(b, k, strlen(k));
    put(b, b->pretty ? ": " : ":");
    b->after_key = 1;
}

void jb_strn(struct jbuf *b, const char *v, size_t n) {
    before_value(b);
    put_escaped(b, v, n);
}

void jb_str(struct jbuf *b, const char *v) {
    if (!v) { jb_null(b); return; }
    jb_strn(b, v, strlen(v));
}

void jb_int(struct jbuf *b, long long v) {
    char tmp[32];
    before_value(b);
    snprintf(tmp, sizeof(tmp), "%lld", v);
    put(b, tmp);
}

void jb_bool(struct jbuf *b, int v) { before_value(b); put(b, v ? "true" : "false"); }
void jb_null(struct jbuf *b) { before_value(b); put(b, "null"); }

void jb_time(struct jbuf *b, time_t t) {
    if (!t) { jb_null(b); return; }
    struct tm tm;
    char tmp[32];
    gmtime_r(&t, &tm);
    strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%SZ", &tm);
    jb_str(b, tmp);
}

void jb_lines(struct jbuf *b, const char *text, size_t len) {
    jb_arr(b);
    size_t i = 0;
    while (i < len) {
        const char *nl = memchr(text + i, '\n', len - i);
        size_t l = nl ? (size_t)(nl - (text + i)) : len - i;
        jb_strn(b, text + i, l);
        i += l + (nl ? 1 : 0);
    }
    jb_arr_end(b);
}

void jb_kstr(struct jbuf *b, const char *k, const char *v) { jb_key(b, k); jb_str(b, v); }
void jb_kint(struct jbuf *b, const char *k, long long v) { jb_key(b, k); jb_int(b, v); }
void jb_kbool(struct jbuf *b, const char *k, int v) { jb_key(b, k); jb_bool(b, v); }
void jb_knull(struct jbuf *b, const char *k) { jb_key(b, k); jb_null(b); }
void jb_ktime(struct jbuf *b, const char *k, time_t t) { jb_key(b, k); jb_time(b, t); }

/* ======================= parser: an array of strings ======================= */

struct jparse { const unsigned char *p; size_t len, pos; char *err; size_t errlen; };

static int perr(struct jparse *j, const char *what) {
    snprintf(j->err, j->errlen, "invalid JSON at byte %zu: %s", j->pos, what);
    return -1;
}

static void skip_ws(struct jparse *j) {
    while (j->pos < j->len && (j->p[j->pos] == ' ' || j->p[j->pos] == '\t' ||
                               j->p[j->pos] == '\n' || j->p[j->pos] == '\r'))
        j->pos++;
}

static int hex4(struct jparse *j, uint32_t *out) {
    if (j->len - j->pos < 4) return perr(j, "truncated \\u escape");
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = j->p[j->pos + i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return perr(j, "bad hex digit in \\u escape");
    }
    j->pos += 4;
    *out = v;
    return 0;
}

static void put_utf8(char *o, size_t *k, uint32_t cp) {
    if (cp < 0x80) o[(*k)++] = (char)cp;
    else if (cp < 0x800) { o[(*k)++] = (char)(0xc0 | (cp >> 6)); o[(*k)++] = (char)(0x80 | (cp & 0x3f)); }
    else if (cp < 0x10000) {
        o[(*k)++] = (char)(0xe0 | (cp >> 12));
        o[(*k)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[(*k)++] = (char)(0x80 | (cp & 0x3f));
    } else {
        o[(*k)++] = (char)(0xf0 | (cp >> 18));
        o[(*k)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        o[(*k)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[(*k)++] = (char)(0x80 | (cp & 0x3f));
    }
}

/* Parses a string at j->pos (which is at '"') into a malloc'd C string. */
static int parse_string(struct jparse *j, char **out) {
    j->pos++;   /* opening quote */
    /* Decoded text is never longer than the source. */
    size_t start = j->pos;
    size_t end = start;
    while (end < j->len && j->p[end] != '"') end += j->p[end] == '\\' ? 2 : 1;
    if (end >= j->len) { j->pos = j->len; return perr(j, "unterminated string"); }
    char *o = malloc(end - start + 1);
    if (!o) return perr(j, "out of memory");
    size_t k = 0;
    while (j->pos < j->len) {
        unsigned char c = j->p[j->pos];
        if (c == '"') {
            j->pos++;
            o[k] = '\0';
            *out = o;
            return 0;
        }
        if (c < 0x20) { free(o); return perr(j, "control character in string (escape it)"); }
        if (c == '\\') {
            if (j->pos + 1 >= j->len) break;
            unsigned char e = j->p[j->pos + 1];
            j->pos += 2;
            switch (e) {
            case '"': o[k++] = '"'; break;
            case '\\': o[k++] = '\\'; break;
            case '/': o[k++] = '/'; break;
            case 'b': o[k++] = '\b'; break;
            case 'f': o[k++] = '\f'; break;
            case 'r': o[k++] = '\r'; break;
            case 't': o[k++] = '\t'; break;
            case 'n': j->pos -= 2; free(o); return perr(j, "a line may not contain a line break: send one string per line");
            case 'u': {
                uint32_t cp;
                if (hex4(j, &cp) < 0) { free(o); return -1; }
                if (cp >= 0xdc00 && cp <= 0xdfff) { free(o); return perr(j, "lone low surrogate in \\u escape"); }
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    uint32_t lo;
                    if (j->len - j->pos < 6 || j->p[j->pos] != '\\' || j->p[j->pos + 1] != 'u') {
                        free(o);
                        return perr(j, "high surrogate without a low one");
                    }
                    j->pos += 2;
                    if (hex4(j, &lo) < 0) { free(o); return -1; }
                    if (lo < 0xdc00 || lo > 0xdfff) { free(o); return perr(j, "high surrogate without a low one"); }
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                if (cp == 0) { free(o); return perr(j, "NUL (\\u0000) is not allowed"); }
                if (cp == '\n') { free(o); return perr(j, "a line may not contain a line break: send one string per line"); }
                put_utf8(o, &k, cp);   /* at most 4 bytes for at least 6 source bytes */
                break;
            }
            default:
                j->pos -= 1;
                free(o);
                return perr(j, "unknown escape");
            }
            continue;
        }
        if (c >= 0x80) {
            size_t seq = utf8_seq(j->p + j->pos, j->len - j->pos);
            if (!seq) { free(o); return perr(j, "invalid UTF-8"); }
            memcpy(o + k, j->p + j->pos, seq);
            k += seq;
            j->pos += seq;
            continue;
        }
        o[k++] = (char)c;
        j->pos++;
    }
    free(o);
    return perr(j, "unterminated string");
}

void json_lines_free(char **lines, int n) {
    for (int i = 0; i < n; i++) free(lines[i]);
    free(lines);
}

int json_parse_lines(const char *buf, size_t len, char ***lines_out, int *n_out, char *err, size_t errlen) {
    struct jparse j = {.p = (const unsigned char *)buf, .len = len, .err = err, .errlen = errlen};
    char **lines = NULL;
    int n = 0, cap = 0;
    *lines_out = NULL;
    *n_out = 0;
    skip_ws(&j);
    if (j.pos >= j.len || j.p[j.pos] != '[') { perr(&j, "expected an array of strings, one per line"); goto fail; }
    j.pos++;
    skip_ws(&j);
    if (j.pos < j.len && j.p[j.pos] == ']') {
        j.pos++;
    } else {
        for (;;) {
            skip_ws(&j);
            if (j.pos >= j.len || j.p[j.pos] != '"') { perr(&j, "expected a string (each line of the program is one string)"); goto fail; }
            if (n == JSON_MAX_LINES) { perr(&j, "too many lines"); goto fail; }
            if (n == cap) {
                int nc = cap ? cap * 2 : 64;
                char **nl = realloc(lines, nc * sizeof(*lines));
                if (!nl) { perr(&j, "out of memory"); goto fail; }
                lines = nl;
                cap = nc;
            }
            if (parse_string(&j, &lines[n]) < 0) goto fail;
            n++;
            skip_ws(&j);
            if (j.pos < j.len && j.p[j.pos] == ',') { j.pos++; continue; }
            if (j.pos < j.len && j.p[j.pos] == ']') { j.pos++; break; }
            perr(&j, "expected ',' or ']'");
            goto fail;
        }
    }
    skip_ws(&j);
    if (j.pos != j.len) { perr(&j, "unexpected data after the array"); goto fail; }
    *lines_out = lines;
    *n_out = n;
    return 0;
fail:
    json_lines_free(lines, n);
    return -1;
}

/* ======================= status objects ======================= */

static int under(const char *path, const char *dir) {
    size_t n = dir ? strlen(dir) : 0;
    return n && !strncmp(path, dir, n) && path[n] == '/';
}

const char *json_file_source(const char *path, const struct json_status_ctx *c) {
    if (under(path, c->rest_dir)) return "rest";
    if (under(path, c->config_dir)) return "config";
    return NULL;
}

void json_file_scope(const char *path, int dir, char *out, size_t outlen) {
    /* .../<scope>/<dir>/<prio>.bpfc, or .../<scope>/xdp.bpfc */
    out[0] = '\0';
    const char *end = strrchr(path, '/');
    if (!end) return;
    int up = dir == DIR_XDP ? 0 : 1;
    while (up-- > 0) {
        const char *p = end;
        while (p > path && p[-1] != '/') p--;
        if (p == path) return;
        end = p - 1;
    }
    const char *start = end;
    while (start > path && start[-1] != '/') start--;
    snprintf(out, outlen, "%.*s", (int)(end - start), start);
}

int json_status_is_problem(int st) {
    return st == ST_FAILED || st == ST_DISABLED || st == ST_REMOVED_EXT || st == ST_REPLACED_EXT;
}

void json_slot(struct jbuf *b, const struct slot *s, const struct json_status_ctx *c) {
    char scope[IFNAMSIZ + 40];
    json_file_scope(s->path, s->dir, scope, sizeof(scope));
    jb_obj(b);
    jb_kstr(b, "interface", s->iface);
    jb_kstr(b, "direction", dir_name(s->dir));
    if (s->dir == DIR_XDP) jb_knull(b, "priority");
    else jb_kint(b, "priority", s->prio);
    jb_kstr(b, "status", status_name(s->status));
    jb_kstr(b, "file", s->path);
    jb_kstr(b, "source", json_file_source(s->path, c));
    jb_kstr(b, "template", scope[0] == '%' ? scope : NULL);
    if (s->prog_id) jb_kint(b, "prog_id", s->prog_id);
    else jb_knull(b, "prog_id");
    jb_kstr(b, "tag", s->tag[0] ? s->tag : NULL);
    if (s->insns) jb_kint(b, "insns", s->insns);
    else jb_knull(b, "insns");
    if (s->ifindex) jb_kint(b, "ifindex", s->ifindex);
    else jb_knull(b, "ifindex");
    jb_kstr(b, "sha256", strcmp(s->sha256, "empty") ? s->sha256 : NULL);
    jb_ktime(b, "installed_at", s->status == ST_INSTALLED ? s->installed_at : 0);
    jb_ktime(b, "changed_at", s->changed_at);
    jb_kstr(b, "error", s->error[0] ? s->error : NULL);
    if (c->extra) c->extra(b, s, c->arg);
    jb_obj_end(b);
}

void json_daemon(struct jbuf *b, const struct daemon_info *di, int running) {
    jb_obj(b);
    jb_kbool(b, "running", running);
    if (di->pid && running) jb_kint(b, "pid", di->pid);
    else jb_knull(b, "pid");
    jb_kstr(b, "version", di->version[0] ? di->version : NULL);
    jb_ktime(b, "started", di->started);
    jb_ktime(b, "last_reload", di->last_reload);
    jb_kint(b, "reload_count", di->reload_count);
    jb_kstr(b, "netns", di->netns[0] ? di->netns : NULL);
    if (di->netns[0]) {
        jb_kstr(b, "netns_status", di->netns_status);
        jb_kstr(b, "netns_target", di->netns_target);
    }
    jb_kstr(b, "config_dir", di->config_dir);
    jb_kstr(b, "rest_dir", di->rest_dir[0] ? di->rest_dir : NULL);
    jb_kstr(b, "rest_socket", di->rest_socket[0] ? di->rest_socket : NULL);
    jb_kstr(b, "on_external_change", di->on_external_change == EXT_LOG ? "log" : "reinstall");
    jb_obj_end(b);
}

void json_summary(struct jbuf *b, const struct slot *slots, int n, int extra_problems) {
    int counts[ST__COUNT] = {0}, problems = extra_problems;
    for (int i = 0; i < n; i++) {
        if (slots[i].status >= 0 && slots[i].status < ST__COUNT) counts[slots[i].status]++;
        if (json_status_is_problem(slots[i].status)) problems++;
    }
    jb_obj(b);
    jb_kint(b, "programs", n);
    for (int st = 0; st < ST__COUNT; st++) {
        /* "pending-iface" -> "pending_iface": keys that need no quoting in jq */
        char k[32];
        snprintf(k, sizeof(k), "%s", status_name(st));
        for (char *p = k; *p; p++) if (*p == '-') *p = '_';
        jb_kint(b, k, counts[st]);
    }
    jb_kint(b, "problems", problems);
    jb_obj_end(b);
}
