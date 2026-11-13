/*
 * A small HTTP/1.1 server on a unix socket, for bpfcd's REST API.
 *
 * Single-threaded and driven by the daemon's poll loop: http_pollfds() adds
 * the listening socket and every client, http_process() handles what poll
 * reported. A request is handled once it has arrived completely (headers and
 * Content-Length body); the handler runs synchronously, so a slow handler (a
 * bpfc compile) delays the others. Each connection carries one request and is
 * closed after the response ("Connection: close"): no keep-alive, no
 * pipelining, no chunked request bodies.
 *
 * Limits: HTTP_MAX_HEADER bytes of request line and headers, HTTP_MAX_BODY of
 * body, HTTP_MAX_CLIENTS connections, and HTTP_TIMEOUT_MS for a request to
 * arrive completely.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef BPFC_HTTP_H
#define BPFC_HTTP_H

#include <poll.h>
#include <stddef.h>
#include <sys/types.h>
#include "json.h"

#define HTTP_MAX_HEADER  (16 * 1024)
#define HTTP_MAX_BODY    (1024 * 1024)
#define HTTP_MAX_CLIENTS 32
#define HTTP_TIMEOUT_MS  10000
#define HTTP_LINGER_MS   1000       /* reading what a client still sends after an early error response */

struct http_request {
    char method[8];             /* GET, HEAD, POST, PUT, DELETE, ... */
    const char *path;           /* raw (percent-encoded) path, starts with '/' */
    const char *query;          /* raw query string without '?', or NULL */
    const char *body;           /* NUL-terminated for convenience; body_len bytes */
    size_t body_len;
    pid_t peer_pid;             /* SO_PEERCRED of the connecting process */
    uid_t peer_uid;
    gid_t peer_gid;
};

struct http_response {
    int status;
    struct jbuf body;           /* JSON text */
    char headers[1024];         /* extra header lines, each ending in \r\n */
};

typedef void (*http_handler)(const struct http_request *req, struct http_response *resp);

/* Fills resp with {"error": {"status": N, "message": "..."}}. */
void http_error(struct http_response *resp, int status, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/* Adds one "Name: value" header line (value must not contain CR or LF). */
void http_add_header(struct http_response *resp, const char *name, const char *value);
const char *http_reason(int status);

/*
 * Creates the listening socket at path with owner uid:gid and mode, replacing
 * a stale socket left there. The socket is never reachable with looser
 * permissions than mode. Returns the fd, or -1 with a message in err.
 */
int http_listen(const char *path, uid_t uid, gid_t gid, unsigned mode, char *err, size_t errlen);

struct http_server;
/* Takes ownership of lfd. */
struct http_server *http_server_new(int lfd, http_handler handler);
/* Closes the listener and every connection. */
void http_server_free(struct http_server *srv);

/* Room http_pollfds() may need: the listener, the clients, and a few being told 503. */
#define HTTP_MAX_POLLFDS (1 + HTTP_MAX_CLIENTS + 8)
/* Appends the server's pollfds to pfd (room for max). Returns how many were added. */
int http_pollfds(struct http_server *srv, struct pollfd *pfd, int max);
/* Handles events for the pollfds http_pollfds() added (pfd points at the first), and timeouts. */
void http_process(struct http_server *srv, const struct pollfd *pfd, int n);
/* Milliseconds until the next connection times out, or -1 when none is waiting. */
int http_timeout_ms(const struct http_server *srv);

/* Percent-decodes one path segment into out. Returns 0, or -1 for a decoded '/' or NUL. */
int http_unescape(const char *in, size_t inlen, char *out, size_t outlen);
/* Value of a query parameter: 1 and *val set when present ("" for a bare name), else 0. */
int http_query_get(const char *query, const char *name, char *val, size_t vallen);

/* ---- for tests: parse a complete request buffer the way the server does ---- */
struct http_parsed {
    char method[8];
    size_t header_len;          /* bytes up to and including the blank line */
    long long content_length;   /* -1 when absent */
    int expect_continue;
    size_t target_off, target_len;
};
/*
 * Parses the request line and headers in buf[0..len). Returns 1 when
 * complete (p filled), 0 when more data is needed, or an HTTP error status
 * (400, 405, 411, 413, 414, 431, 501, 505) with a message in err.
 */
int http_parse_head(const char *buf, size_t len, struct http_parsed *p, char *err, size_t errlen);

#endif
