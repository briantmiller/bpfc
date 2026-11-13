/*
 * Small HTTP/1.1 server on a unix socket; see http.h.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "http.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define HTTP_MAX_TARGET   4096
#define HTTP_BUSY_SLOTS   8         /* connections over the limit that still get a proper 503 */
#define HTTP_MAX_HEADERS  100

/* ======================= responses ======================= */

const char *http_reason(int status) {
    switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 201: return "Created";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 417: return "Expectation Failed";
    case 422: return "Unprocessable Content";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "Unknown";
    }
}

void http_error(struct http_response *resp, int status, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    int pretty = resp->body.pretty;
    jb_free(&resp->body);
    jb_init(&resp->body, pretty);
    resp->status = status;
    jb_obj(&resp->body);
    jb_key(&resp->body, "error");
    jb_obj(&resp->body);
    jb_kint(&resp->body, "status", status);
    jb_kstr(&resp->body, "message", msg);
    jb_obj_end(&resp->body);
    jb_obj_end(&resp->body);
}

void http_add_header(struct http_response *resp, const char *name, const char *value) {
    if (strpbrk(value, "\r\n")) return;
    size_t used = strlen(resp->headers);
    snprintf(resp->headers + used, sizeof(resp->headers) - used, "%s: %s\r\n", name, value);
}

/* ======================= request parsing ======================= */

static int is_tchar(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c));
}

/* Next line in [p, end): sets *eol to the terminator (\r\n or \n), returns its length or 0 if none. */
static size_t line_end(const char *p, const char *end, const char **eol) {
    const char *nl = memchr(p, '\n', (size_t)(end - p));
    if (!nl) return 0;
    *eol = nl > p && nl[-1] == '\r' ? nl - 1 : nl;
    return (size_t)(nl - *eol) + 1;
}

int http_parse_head(const char *buf, size_t len, struct http_parsed *p, char *err, size_t errlen) {
    memset(p, 0, sizeof(*p));
    p->content_length = -1;
    const char *end = buf + len;

    /* The head ends at the first empty line; find it before parsing anything. */
    const char *q = buf, *eol;
    size_t tl;
    int lines = 0;
    const char *head_end = NULL;
    while (q < end && (tl = line_end(q, end, &eol))) {
        if (eol == q) { head_end = eol + tl; break; }
        q = eol + tl;
        if (++lines > HTTP_MAX_HEADERS + 1) {
            snprintf(err, errlen, "too many header lines");
            return 431;
        }
    }
    if (!head_end) {
        if (len > HTTP_MAX_HEADER) { snprintf(err, errlen, "request headers exceed %d bytes", HTTP_MAX_HEADER); return 431; }
        return 0;
    }
    if ((size_t)(head_end - buf) > HTTP_MAX_HEADER) {
        snprintf(err, errlen, "request headers exceed %d bytes", HTTP_MAX_HEADER);
        return 431;
    }
    p->header_len = (size_t)(head_end - buf);

    /* Request line: METHOD SP target SP HTTP/1.x */
    tl = line_end(buf, end, &eol);
    const char *s = buf, *le = eol;
    size_t m = 0;
    while (s + m < le && s[m] >= 'A' && s[m] <= 'Z') m++;
    if (m == 0 || m >= sizeof(p->method) || s + m >= le || s[m] != ' ') {
        snprintf(err, errlen, "malformed request line");
        return 400;
    }
    memcpy(p->method, s, m);
    p->method[m] = '\0';
    const char *t = s + m + 1;
    const char *sp = memchr(t, ' ', (size_t)(le - t));
    if (!sp) { snprintf(err, errlen, "malformed request line"); return 400; }
    if (*t != '/') { snprintf(err, errlen, "the request target must be a path starting with '/'"); return 400; }
    if ((size_t)(sp - t) > HTTP_MAX_TARGET) { snprintf(err, errlen, "request target too long"); return 414; }
    for (const char *c = t; c < sp; c++)
        if ((unsigned char)*c <= 0x20 || (unsigned char)*c >= 0x7f) {
            snprintf(err, errlen, "invalid character in request target");
            return 400;
        }
    p->target_off = (size_t)(t - buf);
    p->target_len = (size_t)(sp - t);
    const char *ver = sp + 1;
    size_t vl = (size_t)(le - ver);
    if (vl != 8 || strncmp(ver, "HTTP/", 5) || ver[6] != '.' || ver[5] < '0' || ver[5] > '9' ||
        ver[7] < '0' || ver[7] > '9') {
        snprintf(err, errlen, "malformed request line");
        return 400;
    }
    if (ver[5] != '1') { snprintf(err, errlen, "only HTTP/1.0 and HTTP/1.1 are supported"); return 505; }

    /* Headers */
    for (q = eol + tl; q < head_end; ) {
        tl = line_end(q, end, &eol);
        if (eol == q) break;
        if (*q == ' ' || *q == '\t') { snprintf(err, errlen, "folded header lines are not supported"); return 400; }
        const char *colon = memchr(q, ':', (size_t)(eol - q));
        if (!colon || colon == q) { snprintf(err, errlen, "malformed header line"); return 400; }
        for (const char *c = q; c < colon; c++)
            if (!is_tchar((unsigned char)*c)) { snprintf(err, errlen, "malformed header name"); return 400; }
        size_t nl = (size_t)(colon - q);
        const char *v = colon + 1, *ve = eol;
        while (v < ve && (*v == ' ' || *v == '\t')) v++;
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
        size_t vlen = (size_t)(ve - v);
        for (const char *c = v; c < ve; c++)
            if ((unsigned char)*c < 0x20 && *c != '\t') { snprintf(err, errlen, "control character in header value"); return 400; }

        if (nl == 14 && !strncasecmp(q, "Content-Length", 14)) {
            if (vlen == 0 || vlen > 15) { snprintf(err, errlen, "invalid Content-Length"); return 400; }
            long long cl = 0;
            for (size_t i = 0; i < vlen; i++) {
                if (v[i] < '0' || v[i] > '9') { snprintf(err, errlen, "invalid Content-Length"); return 400; }
                cl = cl * 10 + (v[i] - '0');
            }
            if (p->content_length >= 0 && p->content_length != cl) {
                snprintf(err, errlen, "conflicting Content-Length headers");
                return 400;
            }
            p->content_length = cl;
        } else if (nl == 17 && !strncasecmp(q, "Transfer-Encoding", 17)) {
            snprintf(err, errlen, "Transfer-Encoding is not supported; send the body with a Content-Length");
            return 501;
        } else if (nl == 6 && !strncasecmp(q, "Expect", 6)) {
            if (vlen == 12 && !strncasecmp(v, "100-continue", 12)) p->expect_continue = 1;
            else { snprintf(err, errlen, "unsupported Expect header"); return 417; }
        }
        q = eol + tl;
    }
    if (p->content_length > HTTP_MAX_BODY) {
        snprintf(err, errlen, "request body exceeds %d bytes", HTTP_MAX_BODY);
        return 413;
    }
    if (p->content_length < 0 && (!strcmp(p->method, "POST") || !strcmp(p->method, "PUT"))) {
        snprintf(err, errlen, "a %s needs a Content-Length", p->method);
        return 411;
    }
    return 1;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int http_unescape(const char *in, size_t inlen, char *out, size_t outlen) {
    size_t k = 0;
    for (size_t i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        /* '%' not followed by two hex digits stays as it is, so "%all%" works unencoded. */
        if (c == '%' && i + 2 < inlen && hexval(in[i + 1]) >= 0 && hexval(in[i + 2]) >= 0) {
            c = hexval(in[i + 1]) * 16 + hexval(in[i + 2]);
            i += 2;
            if (c == 0 || c == '/') return -1;
        }
        if (k + 1 >= outlen) return -1;
        out[k++] = (char)c;
    }
    out[k] = '\0';
    return 0;
}

int http_query_get(const char *query, const char *name, char *val, size_t vallen) {
    if (!query) return 0;
    size_t nlen = strlen(name);
    for (const char *p = query; *p; ) {
        const char *amp = strchr(p, '&');
        size_t l = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', l);
        size_t kl = eq ? (size_t)(eq - p) : l;
        if (kl == nlen && !strncmp(p, name, nlen)) {
            if (eq) {
                if (http_unescape(eq + 1, l - kl - 1, val, vallen) < 0) val[0] = '\0';
            } else if (vallen) {
                val[0] = '\0';
            }
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

/* ======================= listening socket ======================= */

int http_listen(const char *path, uid_t uid, gid_t gid, unsigned mode, char *err, size_t errlen) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(sa.sun_path)) {
        snprintf(err, errlen, "%s: socket path too long (at most %zu bytes)", path, sizeof(sa.sun_path) - 1);
        return -1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);

    /* The directory, if missing. */
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        int rc = mkdir_p(dir, 0755);
        if (rc < 0) { snprintf(err, errlen, "cannot create %s: %s", dir, strerror(-rc)); return -1; }
    }

    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            snprintf(err, errlen, "%s exists and is not a socket; not replacing it", path);
            return -1;
        }
        unlink(path);   /* left by an earlier run: the pid file lock says no other bpfcd is using it */
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { snprintf(err, errlen, "socket: %s", strerror(errno)); return -1; }
    /* Created owner-only, so no one can connect before ownership and mode are set. */
    mode_t old = umask(0177);
    int rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    umask(old);
    if (rc < 0) {
        snprintf(err, errlen, "cannot bind %s: %s", path, strerror(e));
        close(fd);
        return -1;
    }
    if (chown(path, uid, gid) < 0 || chmod(path, mode & 07777) < 0) {
        e = errno;
        snprintf(err, errlen, "cannot set owner %u:%u and mode %04o on %s: %s", (unsigned)uid, (unsigned)gid,
                 mode, path, strerror(e));
        close(fd);
        unlink(path);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        e = errno;
        snprintf(err, errlen, "listen on %s: %s", path, strerror(e));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

/* ======================= connections ======================= */

enum { C_READ, C_WRITE, C_LINGER, C_CLOSED };

struct conn {
    int fd;
    int state;
    char *in;
    size_t inlen, incap;
    int head_done;
    struct http_parsed hp;
    int continue_sent;
    char *out;
    size_t outlen, outoff;
    long long deadline;         /* monotonic ms */
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

struct http_server {
    int lfd;
    http_handler handler;
    struct conn conns[HTTP_MAX_CLIENTS + HTTP_BUSY_SLOTS];
    int nconns;
    int polled_conns;           /* connections http_pollfds() reported, in order */
    int polled_listener;
};

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct http_server *http_server_new(int lfd, http_handler handler) {
    struct http_server *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->lfd = lfd;
    srv->handler = handler;
    return srv;
}

static void conn_close(struct conn *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    free(c->in);
    free(c->out);
    c->in = c->out = NULL;
    c->state = C_CLOSED;
}

void http_server_free(struct http_server *srv) {
    if (!srv) return;
    for (int i = 0; i < srv->nconns; i++) conn_close(&srv->conns[i]);
    if (srv->lfd >= 0) close(srv->lfd);
    free(srv);
}

/* Serializes resp as the connection's output and starts writing it. */
static void conn_respond(struct conn *c, struct http_response *resp, int head_only) {
    if (resp->body.oom) http_error(resp, 500, "out of memory");
    const char *body = resp->body.s ? resp->body.s : "";
    size_t blen = resp->body.len;
    char head[2048];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                      "Cache-Control: no-store\r\nConnection: close\r\n%s\r\n",
                      resp->status, http_reason(resp->status), blen, resp->headers);
    if (hl < 0 || (size_t)hl >= sizeof(head)) hl = (int)strlen(head);
    free(c->out);
    c->outlen = (size_t)hl + (head_only ? 0 : blen);
    c->out = malloc(c->outlen);
    if (!c->out) { conn_close(c); return; }
    memcpy(c->out, head, (size_t)hl);
    if (!head_only) memcpy(c->out + hl, body, blen);
    c->outoff = 0;
    c->state = C_WRITE;
    c->deadline = now_ms() + HTTP_TIMEOUT_MS;
}

static void conn_error(struct conn *c, int status, const char *msg) {
    struct http_response r = {.status = status};
    jb_init(&r.body, 1);
    http_error(&r, status, "%s", msg);
    conn_respond(c, &r, 0);
    jb_free(&r.body);
}

static void conn_write(struct conn *c) {
    while (c->outoff < c->outlen) {
        ssize_t w = send(c->fd, c->out + c->outoff, c->outlen - c->outoff, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            conn_close(c);
            return;
        }
        c->outoff += (size_t)w;
    }
    /* Done: stop sending, then read (and drop) whatever the client still sends
     * until it closes, so an early error is not lost to a connection reset. */
    shutdown(c->fd, SHUT_WR);
    c->state = C_LINGER;
    c->deadline = now_ms() + HTTP_LINGER_MS;
}

static void conn_dispatch(struct http_server *srv, struct conn *c) {
    char *target = c->in + c->hp.target_off;
    target[c->hp.target_len] = '\0';    /* overwrites the space before "HTTP/1.x" */
    char *query = strchr(target, '?');
    if (query) *query++ = '\0';
    char *frag = strchr(query ? query : target, '#');
    if (frag) *frag = '\0';
    size_t blen = c->hp.content_length > 0 ? (size_t)c->hp.content_length : 0;
    char *body = c->in + c->hp.header_len;
    body[blen] = '\0';                  /* the buffer always has a spare byte */

    struct http_request req = {
        .path = target, .query = query, .body = body, .body_len = blen,
        .peer_pid = c->pid, .peer_uid = c->uid, .peer_gid = c->gid};
    snprintf(req.method, sizeof(req.method), "%s", c->hp.method);
    struct http_response resp = {.status = 200};
    jb_init(&resp.body, 1);
    srv->handler(&req, &resp);
    conn_respond(c, &resp, !strcmp(req.method, "HEAD"));
    jb_free(&resp.body);
    if (c->state == C_WRITE) conn_write(c);
}

static void conn_read(struct http_server *srv, struct conn *c) {
    for (;;) {
        if (c->inlen + 1 >= c->incap) {
            size_t limit = (size_t)HTTP_MAX_HEADER + HTTP_MAX_BODY + 2;
            if (c->incap >= limit) {
                /* Full head + body limit reached without a complete request. */
                conn_error(c, c->head_done ? 413 : 431, "request too large");
                conn_write(c);
                return;
            }
            size_t nc = c->incap ? c->incap * 2 : 4096;
            if (nc > limit) nc = limit;
            char *n = realloc(c->in, nc);
            if (!n) { conn_close(c); return; }
            c->in = n;
            c->incap = nc;
        }
        ssize_t r = recv(c->fd, c->in + c->inlen, c->incap - c->inlen - 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            conn_close(c);
            return;
        }
        if (r == 0) { conn_close(c); return; }   /* gone before a complete request */
        c->inlen += (size_t)r;

        if (!c->head_done) {
            char err[256];
            int rc = http_parse_head(c->in, c->inlen, &c->hp, err, sizeof(err));
            if (rc == 0) continue;
            if (rc != 1) { conn_error(c, rc, err); conn_write(c); return; }
            c->head_done = 1;
        }
        size_t need = c->hp.header_len + (c->hp.content_length > 0 ? (size_t)c->hp.content_length : 0);
        if (c->inlen >= need) { conn_dispatch(srv, c); return; }
        if (c->hp.expect_continue && !c->continue_sent) {
            static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
            /* Small enough for any socket buffer; a short write only costs the client a wait. */
            if (send(c->fd, cont, sizeof(cont) - 1, MSG_NOSIGNAL) < 0) { /* the client still sends */ }
            c->continue_sent = 1;
        }
    }
    /* A complete head that arrived in the same read as nothing else: handle now. */
    if (c->head_done) {
        size_t need = c->hp.header_len + (c->hp.content_length > 0 ? (size_t)c->hp.content_length : 0);
        if (c->inlen >= need) conn_dispatch(srv, c);
        else if (c->hp.expect_continue && !c->continue_sent) {
            static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
            if (send(c->fd, cont, sizeof(cont) - 1, MSG_NOSIGNAL) < 0) { /* see above */ }
            c->continue_sent = 1;
        }
    }
}

static void conn_linger(struct conn *c) {
    char buf[4096];
    for (;;) {
        ssize_t r = recv(c->fd, buf, sizeof(buf), 0);
        if (r > 0) continue;
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        conn_close(c);
        return;
    }
}

static void accept_all(struct http_server *srv) {
    for (;;) {
        int fd = accept4(srv->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                logmsg(LOG_LVL_WARN, "rest: accept: %s", strerror(errno));
            return;
        }
        if (srv->nconns >= HTTP_MAX_CLIENTS && srv->nconns < HTTP_MAX_CLIENTS + HTTP_BUSY_SLOTS) {
            /* Over the limit: answer 503 through a connection slot of its own, so the
             * reply is written and lingered like any other (no reset under the client). */
            struct conn *c = &srv->conns[srv->nconns++];
            memset(c, 0, sizeof(*c));
            c->fd = fd;
            conn_error(c, 503, "too many connections; try again");
            if (c->state == C_WRITE) conn_write(c);
            continue;
        }
        if (srv->nconns >= HTTP_MAX_CLIENTS) {
            static const char busy_body[] =
                "{\"error\": {\"status\": 503, \"message\": \"too many connections; try again\"}}\n";
            char busy[256];
            int bl = snprintf(busy, sizeof(busy),
                              "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                              sizeof(busy_body) - 1, busy_body);
            if (send(fd, busy, (size_t)bl, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) { /* best effort */ }
            close(fd);
            continue;
        }
        struct conn *c = &srv->conns[srv->nconns++];
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->state = C_READ;
        c->deadline = now_ms() + HTTP_TIMEOUT_MS;
        struct ucred cr;
        socklen_t cl = sizeof(cr);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) {
            c->pid = cr.pid;
            c->uid = cr.uid;
            c->gid = cr.gid;
        } else {
            c->pid = 0;
            c->uid = (uid_t)-1;
            c->gid = (gid_t)-1;
        }
    }
}

int http_pollfds(struct http_server *srv, struct pollfd *pfd, int max) {
    int n = 0;
    srv->polled_listener = 0;
    srv->polled_conns = 0;
    if (max <= 0) return 0;
    pfd[n++] = (struct pollfd){.fd = srv->lfd, .events = POLLIN};
    srv->polled_listener = 1;
    for (int i = 0; i < srv->nconns && n < max; i++) {
        struct conn *c = &srv->conns[i];
        pfd[n++] = (struct pollfd){.fd = c->fd, .events = c->state == C_WRITE ? POLLOUT : POLLIN};
        srv->polled_conns++;
    }
    return n;
}

void http_process(struct http_server *srv, const struct pollfd *pfd, int n) {
    int k = 0;
    int listen_ready = srv->polled_listener && n > 0 && (pfd[0].revents & POLLIN);
    if (srv->polled_listener) k = 1;
    long long now = now_ms();
    for (int i = 0; i < srv->polled_conns && k < n; i++, k++) {
        struct conn *c = &srv->conns[i];
        short re = pfd[k].revents;
        if (c->state == C_CLOSED) continue;
        if (re & (POLLERR | POLLNVAL)) { conn_close(c); continue; }
        if (c->state == C_READ && (re & (POLLIN | POLLHUP))) conn_read(srv, c);
        else if (c->state == C_WRITE && (re & (POLLOUT | POLLHUP))) conn_write(c);
        else if (c->state == C_LINGER && (re & (POLLIN | POLLHUP))) conn_linger(c);
    }
    /* Timeouts, for every connection. */
    now = now_ms();
    for (int i = 0; i < srv->nconns; i++) {
        struct conn *c = &srv->conns[i];
        if (c->state == C_CLOSED || now < c->deadline) continue;
        if (c->state == C_READ) { conn_error(c, 408, "request not received in time"); conn_write(c); }
        else conn_close(c);
    }
    /* Compact closed connections away (order does not matter). */
    for (int i = 0; i < srv->nconns;) {
        if (srv->conns[i].state == C_CLOSED) { srv->conns[i] = srv->conns[--srv->nconns]; continue; }
        i++;
    }
    if (listen_ready) accept_all(srv);
    srv->polled_conns = 0;
    srv->polled_listener = 0;
}

int http_timeout_ms(const struct http_server *srv) {
    if (!srv || !srv->nconns) return -1;
    long long now = now_ms(), best = -1;
    for (int i = 0; i < srv->nconns; i++) {
        long long d = srv->conns[i].deadline - now;
        if (d < 0) d = 0;
        if (best < 0 || d < best) best = d;
    }
    return (int)(best > 60000 ? 60000 : best);
}
