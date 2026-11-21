/*
 * acl.h - the access lists the acl frontend installed, as bpfcctl and bpfcd
 * see them: the meta table (the files in <state_dir>/meta: one "acl" line per list and
 * one "acl-rule" line per entry with its counter key), the counters
 * (BPFC_ACL_P, BPFC_ACL_B) and the log ring buffer (BPFC_ACL_LOG).
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef BPFC_ACL_H
#define BPFC_ACL_H

#include <stdint.h>
#include <stdio.h>

struct acl_rule {
    uint64_t key;
    char acl[96], seq[16], action[16], iface[64], dir[8], type[16];
    int log;
    char text[640];
};

struct acl_table {
    struct acl_rule *r;
    int n, cap;
};

/* Reads every meta file of state_dir; 0, or -1 with errno */
int acl_table_load(struct acl_table *t, const char *state_dir);
void acl_table_free(struct acl_table *t);
const struct acl_rule *acl_table_find(const struct acl_table *t, uint64_t key);

/* An open pinned map (BPF_OBJ_GET), or -1 with errno */
int acl_map_open(const char *map_dir, const char *name);
int acl_map_get(int fd, uint64_t key, uint64_t *val);   /* 0 found, -1 not */
int acl_map_del(int fd, uint64_t key);

/* bpfcctl show access-lists [NAME] [interface IF] */
int acl_show(FILE *out, const char *state_dir, const char *map_dir, const char *name, const char *iface, int bytes);
/* bpfcctl clear access-list counters [NAME]: entries cleared, or -1 */
int acl_clear(const char *state_dir, const char *map_dir, const char *name);
/* bpfcctl top: entries by packet rate over secs seconds, the n busiest */
int acl_top(FILE *out, const char *state_dir, const char *map_dir, double secs, int n);

/* bpfcd: the log ring buffer, and its records as IOS writes them */
struct acl_log;
struct acl_log *acl_log_open(const char *map_dir);      /* NULL: no ACL logs yet */
int acl_log_fd(const struct acl_log *l);                /* poll it for POLLIN */
uint32_t acl_log_map_id(const struct acl_log *l);
uint32_t acl_pinned_map_id(const char *map_dir, const char *name);  /* 0: not pinned */
/* Reads every waiting record, calls emit(line) for each; returns records read */
int acl_log_drain(struct acl_log *l, const struct acl_table *t, void (*emit)(const char *line, void *ctx), void *ctx);
void acl_log_close(struct acl_log *l);
/* One record (ktime, key, ifindex, len, frame) as an IOS log line */
int acl_log_format(char *buf, size_t len, const struct acl_table *t, const unsigned char *rec, size_t reclen);

#endif
