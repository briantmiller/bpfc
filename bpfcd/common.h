/*
 * Shared code for bpfcd (daemon) and bpfcctl (status tool).
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef BPFC_COMMON_H
#define BPFC_COMMON_H

#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <net/if.h>
#include <limits.h>

#ifndef BPFC_VERSION
#define BPFC_VERSION "0.0.0"
#endif

#define DEFAULT_CONF_PATH   "/etc/bpfc/bpfc.conf"
#define DEFAULT_CONFIG_DIR  "/etc/bpfc/interfaces.d"
#define DEFAULT_STATE_DIR   "/run/bpfc"
#define DEFAULT_BPFC_PATH   "/usr/sbin/bpfc"
#define STATE_FILE_NAME     "state"
#define PID_FILE_NAME       "bpfcd.pid"
#define ERROR_DIR_NAME      "errors"

/* Prefix of TC filter names owned by bpfcd: "bpfcd:<iface>/<dir>/<prio>". */
#define FILTER_NAME_PREFIX  "bpfcd:"

enum direction { DIR_INGRESS = 0, DIR_EGRESS = 1 };

const char *dir_name(int dir);
int dir_parse(const char *s); /* returns -1 when not "ingress"/"egress" */

/* ---------------- logging ---------------- */

enum log_level { LOG_LVL_ERR = 3, LOG_LVL_WARN = 4, LOG_LVL_INFO = 6, LOG_LVL_DEBUG = 7 };

/*
 * LOG_TO_STDERR prints plain lines; when stderr is the systemd journal the
 * "<N>" sd-daemon priority prefix is added so journald keeps severities.
 * LOG_TO_SYSLOG is used when bpfcd daemonizes itself (non-systemd systems).
 */
enum log_target { LOG_TO_STDERR, LOG_TO_SYSLOG };

void log_init(const char *ident, enum log_target target, int max_level);
void log_set_level(int max_level);
void logmsg(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int log_level_parse(const char *s);

/* ---------------- configuration ---------------- */

enum ext_policy { EXT_REINSTALL = 0, EXT_LOG = 1 };

struct config {
    char bpfc_path[PATH_MAX];
    char config_dir[PATH_MAX];
    char state_dir[PATH_MAX];
    char map_dir[PATH_MAX];      /* empty: bpfc's default (/sys/fs/bpf) */
    int on_external_change;      /* enum ext_policy */
    int remove_on_stop;          /* bool */
    int reinstall_limit;         /* max automatic reinstalls per slot per minute */
    int compile_timeout;         /* seconds before a bpfc run is killed */
    int log_level;               /* enum log_level */
};

void config_defaults(struct config *c);
/*
 * Reads "key = value" lines; '#' starts a comment. A missing file is not an
 * error (defaults apply). Returns 0, or -1 with a message in err.
 */
int config_load(const char *path, struct config *c, char *err, size_t errlen);
/*
 * Overrides settings from BPFCD_<SETTING> environment variables (for example
 * BPFCD_ON_EXTERNAL_CHANGE=log), so containers can configure bpfcd without a
 * config file. Applied after config_load(). Returns 0, or -1 with a message.
 */
int config_apply_env(struct config *c, char *err, size_t errlen);

/* ---------------- hashing ---------------- */

/* SHA-256 of a file as 64 lowercase hex chars + NUL. Returns 0 or -errno. */
int sha256_file(const char *path, char out_hex[65]);

/*
 * Hash of a program for change detection. A program that mentions "include"
 * is hashed together with every file it reads (bpfc -M lists them), so
 * editing an included file counts as a change; *has_includes is then set,
 * because the program file's own mtime no longer shows every change. Any
 * other program hashes exactly as sha256_file(). Returns 0 or -errno.
 */
int sha256_program(const char *bpfc_path, const char *path, int timeout_s,
                   char out_hex[65], int *has_includes);

/* ---------------- running bpfc ---------------- */

#define MAX_CAPTURE (1024 * 1024)      /* bpfc output kept per run (verifier logs can be long) */

struct run_result { int exit_code; int timed_out; char *out; size_t outlen; };

/*
 * Runs argv (in workdir, if given) with stdout+stderr captured, killing it
 * after timeout_s seconds. exit_code is -1 if it did not exit normally.
 * The caller frees r->out.
 */
int run_capture(char *const argv[], struct run_result *r, int timeout_s, const char *workdir);

/* ---------------- state file ---------------- */

enum slot_status {
    ST_INSTALLED = 0,     /* program loaded and attached, kernel matches */
    ST_PENDING,           /* interface does not exist (yet) */
    ST_FAILED,            /* compile, verifier or attach failure; priority left empty */
    ST_REMOVED_EXT,       /* removed by something other than bpfcd (log policy) */
    ST_REPLACED_EXT,      /* replaced by something other than bpfcd (log policy) */
    ST_DISABLED,          /* reinstall limit hit; waits for the next reload */
    ST_EXCLUDED,          /* an empty file opts this interface out of a %all% / %<kind>% program */
    ST__COUNT
};

const char *status_name(int st);
int status_parse(const char *s);

struct slot {
    char iface[IFNAMSIZ];
    int dir;
    int prio;
    char path[PATH_MAX];
    int64_t mtime_ns;
    char sha256[65];
    int status;
    int ifindex;              /* ifindex the program was installed on, 0 if none */
    uint32_t prog_id;
    char tag[17];
    uint32_t insns;
    time_t installed_at;      /* when the current program was attached */
    time_t changed_at;        /* last status change */
    char error[512];          /* short reason for failed / external states */
    /* daemon-only bookkeeping (not persisted) */
    int seen;                 /* present in the latest scan of the config dir */
    int dirty;                /* needs (re)install */
    int is_new;               /* first seen in this scan (for log wording) */
    int has_includes;         /* hash covers included files; mtime alone does not show changes */
    int from_template;        /* comes from %all% or %<kind>% for this interface */
    int excluded;             /* the chosen file is empty: nothing at this priority */
    time_t reinstall_window;  /* start of the current one-minute reinstall window */
    int reinstall_count;
};

struct daemon_info {
    int pid;
    time_t started;
    time_t last_reload;
    unsigned reload_count;      /* bumped after every completed rescan */
    char version[32];
    char config_dir[PATH_MAX];
    int on_external_change;
    char bpfc_path[PATH_MAX];   /* the daemon's bpfc, for hashing programs with includes */
};

/* Atomically writes the state file (temp file + rename). Returns 0 or -errno. */
int state_write(const char *path, const struct daemon_info *di,
                const struct slot *slots, int nslots);
/* Reads a state file into a malloc'd slot array. Returns the count or -errno. */
int state_read(const char *path, struct daemon_info *di, struct slot **slots_out);

/* Path of the saved bpfc output for a failed slot. */
void error_log_path(char *out, size_t outlen, const char *state_dir,
                    const char *iface, int dir, int prio);

/* ---------------- TC filter dump ---------------- */

struct tc_filter {
    int prio;
    uint16_t proto;
    uint32_t handle;
    char kind[16];
    uint32_t prog_id;   /* bpf classifier only */
    char name[256];     /* bpf classifier name (TCA_BPF_NAME) */
};

/*
 * Lists the filters attached to one clsact hook of an interface. Only real
 * filter entries are returned (the per-priority chain headers are skipped).
 * Returns the number of filters (an interface without clsact returns 0), or
 * -errno. *out is malloc'd and must be freed by the caller.
 */
int tc_dump_filters(int ifindex, int dir, struct tc_filter **out);

/* ---------------- bpf program info ---------------- */

struct prog_details {
    uint32_t id;
    char tag[17];
    char name[17];
    uint32_t xlated_len;          /* bytes */
    uint32_t jited_len;           /* bytes */
    uint64_t load_time_ns;        /* since boot */
    void *xlated;                 /* malloc'd struct bpf_insn[], may be NULL */
};

/* Fetches program info by id; with want_insns the translated bytecode too. */
int prog_get_details(uint32_t id, int want_insns, struct prog_details *out);

/* ---------------- misc ---------------- */

int mkdir_p(const char *path, int mode);
/* Characters allowed in an interface directory name (Linux allows more, we are strict). */
int valid_ifname(const char *s);
/* "%all%" or "%<kind>%" (kind: lowercase letters, digits, '_', '-', '.'). No interface can
 * have such a name: the kernel treats '%' in a new name as a numbering pattern. */
int valid_template_name(const char *s);

/* ---------------- links ---------------- */

#define ARPHRD_ETHER_ 1
#define ARPHRD_LOOPBACK_ 772

struct link_info {
    int index;
    int type;               /* ARPHRD_* (dev->type) */
    char name[IFNAMSIZ];
    char kind[32];          /* rtnetlink kind; "lo" for loopback, "nic" without a kind */
    int has_kind;           /* the message carried IFLA_INFO_KIND */
};

struct nlmsghdr;
/* Parses an RTM_NEWLINK / RTM_DELLINK message. Returns 0, or -1 without a name. */
int link_parse(const struct nlmsghdr *h, struct link_info *out);
/* Lists every interface. Returns the count or -errno; *out is malloc'd. */
int link_dump(struct link_info **out);


#endif
