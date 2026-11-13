/*
 * Minimal JSON for bpfcd's REST socket and `bpfcctl status --json`: a writer
 * into a growable buffer, a strict parser for the one input the API takes (an
 * array of strings, one per program line), and the status objects both
 * programs print.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef BPFC_JSON_H
#define BPFC_JSON_H

#include <stddef.h>
#include <time.h>
#include "common.h"

#define JSON_MAX_DEPTH 32

struct jbuf {
    char *s;
    size_t len, cap;
    int oom;                        /* an allocation failed: the text is incomplete */
    int pretty;                     /* newlines and two-space indentation */
    int depth;
    int count[JSON_MAX_DEPTH];      /* elements written at each open level */
    int after_key;                  /* the next value belongs to the key just written */
};

void jb_init(struct jbuf *b, int pretty);
void jb_free(struct jbuf *b);
/* Appends raw text (no separators): for building non-JSON output in the same buffer. */
void jb_raw(struct jbuf *b, const char *s, size_t n);

void jb_obj(struct jbuf *b);
void jb_obj_end(struct jbuf *b);
void jb_arr(struct jbuf *b);
void jb_arr_end(struct jbuf *b);
void jb_key(struct jbuf *b, const char *k);
/* A string; NULL writes null. Bytes that are not valid UTF-8 become U+FFFD. */
void jb_str(struct jbuf *b, const char *v);
void jb_strn(struct jbuf *b, const char *v, size_t n);
void jb_int(struct jbuf *b, long long v);
void jb_bool(struct jbuf *b, int v);
void jb_null(struct jbuf *b);
/* "2026-11-11T23:15:00Z", or null for 0. */
void jb_time(struct jbuf *b, time_t t);
/* Each line of text (split at '\n'; a final newline adds no empty line) as an array of strings. */
void jb_lines(struct jbuf *b, const char *text, size_t len);

/* key + value shorthands */
void jb_kstr(struct jbuf *b, const char *k, const char *v);
void jb_kint(struct jbuf *b, const char *k, long long v);
void jb_kbool(struct jbuf *b, const char *k, int v);
void jb_knull(struct jbuf *b, const char *k);
void jb_ktime(struct jbuf *b, const char *k, time_t t);

/*
 * Parses exactly one JSON array of strings (whitespace around it allowed,
 * nothing else). Strings may not contain a line break or NUL once decoded.
 * On success returns 0 and a malloc'd array of *n malloc'd strings (free with
 * json_lines_free); on failure -1 with a message (with the byte offset) in err.
 */
#define JSON_MAX_LINES 100000
int json_parse_lines(const char *buf, size_t len, char ***lines, int *n, char *err, size_t errlen);
void json_lines_free(char **lines, int n);

/* ---------------- status objects (bpfcd's GET /, bpfcctl status --json) ---------------- */

struct json_status_ctx {
    const char *config_dir;     /* to tell where a program file lives */
    const char *rest_dir;
    /* optional: extra members appended to each program object */
    void (*extra)(struct jbuf *b, const struct slot *s, void *arg);
    void *arg;
};

/* Where a file is: "rest" (rest_dir), "config" (config_dir) or NULL. */
const char *json_file_source(const char *path, const struct json_status_ctx *c);
/* The scope a program file belongs to ("eth0", "%all%", "%veth%"), from its path; "" if unknown. */
void json_file_scope(const char *path, int dir, char *out, size_t outlen);

/* One program slot, as an object. */
void json_slot(struct jbuf *b, const struct slot *s, const struct json_status_ctx *c);
/* The "bpfcd" object: the daemon, its namespace and directories. */
void json_daemon(struct jbuf *b, const struct daemon_info *di, int running);
/* The "summary" object: slots per status and the number needing attention. */
void json_summary(struct jbuf *b, const struct slot *slots, int n, int extra_problems);
/* Status counts as a problem (failed, disabled, removed or replaced externally). */
int json_status_is_problem(int status);

#endif
