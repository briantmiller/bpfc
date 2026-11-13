/*
 * Fuzz test for bpfcd's REST input handling: the HTTP request parser, the
 * percent-decoder and query lookup, the JSON line-array parser, the JSON
 * writer (output must parse back to the same strings), and the server's
 * connection handling over a real unix socket.
 *
 *   make fuzz [FUZZ_ITERS=n]     builds with ASan/UBSan and runs n iterations
 *
 * Inputs are random and mutated from a corpus of valid requests, so the
 * parsers see both garbage and nearly valid input. Any sanitizer report or
 * failed property aborts with a non-zero exit status.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "http.h"
#include "json.h"
#include "common.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static size_t rn(size_t n) { return n ? (size_t)(rnd() % n) : 0; }

#define FAIL(...) do { fprintf(stderr, "fuzz-rest: FAIL: " __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)

static const char *corpus[] = {
    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET /interfaces/eth0/ingress/10 HTTP/1.1\r\n\r\n",
    "POST /interfaces/%25all%25/egress/5?dry-run HTTP/1.1\r\nContent-Length: 17\r\n\r\n[\"match ip\",\"x\"]",
    "PUT /interfaces/eth0/xdp HTTP/1.0\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n[]",
    "DELETE /interfaces/eth0/ingress/1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "HEAD /interfaces HTTP/1.1\r\nX: y\r\n\r\n",
    "GET /a%2fb?x=%00&dry-run=true HTTP/1.1\n\n",
};
static const char *jcorpus[] = {
    "[]", "[\"a\"]", "[\"\\u00e9\\ud83d\\ude00\", \"b\\t\\\"\"]", " [ \"x\" , \"y\" ] ",
    "[\"\\ud800\"]", "[\"a\\nb\"]", "[1]", "[\"\xc3\xa9\", \"\xf0\x9f\x98\x80\"]", "[\"unterminated",
};

static void mutate(char *buf, size_t *len, size_t cap) {
    int n = 1 + (int)rn(8);
    while (n--) {
        size_t l = *len;
        switch (rn(6)) {
        case 0: if (l) buf[rn(l)] = (char)rnd(); break;                       /* flip a byte */
        case 1: if (l < cap) { size_t p = rn(l + 1); memmove(buf + p + 1, buf + p, l - p); buf[p] = (char)rnd(); (*len)++; } break;
        case 2: if (l) { size_t p = rn(l); memmove(buf + p, buf + p + 1, l - p - 1); (*len)--; } break;
        case 3: if (l) *len = rn(l); break;                                     /* truncate */
        case 4: {                                                                /* insert a token */
            static const char *tok[] = {"\r\n", "\r\n\r\n", "%", "%2", "%25", "\\u", "\"", "[", "]", ",",
                                        "Content-Length: 99999999\r\n", "Transfer-Encoding: x\r\n", "\\", "\xff", "\x00"};
            const char *t = tok[rn(sizeof(tok) / sizeof(*tok))];
            size_t tl = strlen(t) ? strlen(t) : 1, p = rn(l + 1);
            if (l + tl <= cap) { memmove(buf + p + tl, buf + p, l - p); memcpy(buf + p, t, tl); *len += tl; }
            break;
        }
        case 5: if (l && l * 2 <= cap) { memcpy(buf + l, buf, l); *len *= 2; } break;  /* duplicate */
        }
    }
}

static void fuzz_parsers(int iters) {
    enum { CAP = 64 * 1024 };
    char *buf = malloc(CAP + 1), *out = malloc(CAP + 1), err[256];
    for (int it = 0; it < iters; it++) {
        size_t len;
        if (rn(4) == 0) { len = rn(512); for (size_t i = 0; i < len; i++) buf[i] = (char)rnd(); }
        else {
            const char *c = corpus[rn(sizeof(corpus) / sizeof(*corpus))];
            len = strlen(c);
            memcpy(buf, c, len);
            mutate(buf, &len, CAP);
        }
        /* An exact-size heap copy, so ASan sees any read past the end. */
        char *exact = malloc(len ? len : 1);
        memcpy(exact, buf, len);
        struct http_parsed p;
        int rc = http_parse_head(exact, len, &p, err, sizeof(err));
        if (rc == 1) {
            if (p.header_len > len || p.target_off + p.target_len > len) FAIL("offsets beyond input");
            if (exact[p.target_off] != '/') FAIL("target does not start with '/'");
            char seg[64];
            http_unescape(exact + p.target_off, p.target_len, seg, sizeof(seg));
        } else if (rc != 0 && (rc < 400 || rc > 505)) {
            FAIL("unexpected status %d", rc);
        }
        size_t ul = rn(len + 1);
        http_unescape(exact, ul, out, 1 + rn(128));
        char *q = malloc(ul + 1);
        memcpy(q, exact, ul);
        q[ul] = '\0';
        char v[32];
        http_query_get(q, "dry-run", v, sizeof(v));
        free(q);
        free(exact);

        /* JSON parser */
        if (rn(3) == 0) { len = rn(256); for (size_t i = 0; i < len; i++) buf[i] = (char)rnd(); }
        else {
            const char *c = jcorpus[rn(sizeof(jcorpus) / sizeof(*jcorpus))];
            len = strlen(c);
            memcpy(buf, c, len);
            mutate(buf, &len, CAP);
        }
        exact = malloc(len ? len : 1);
        memcpy(exact, buf, len);
        char **lines;
        int n;
        if (json_parse_lines(exact, len, &lines, &n, err, sizeof(err)) == 0) {
            for (int i = 0; i < n; i++) if (strchr(lines[i], '\n')) FAIL("parsed line contains a newline");
            json_lines_free(lines, n);
        }
        free(exact);

        /* Writer round trip: random strings out, parsed back identical (when representable). */
        struct jbuf b;
        jb_init(&b, (int)rn(2));
        int ns = (int)rn(6);
        char strs[6][64];
        size_t sl[6];
        jb_arr(&b);
        for (int i = 0; i < ns; i++) {
            sl[i] = rn(sizeof(strs[i]));
            for (size_t k = 0; k < sl[i]; k++) {
                unsigned char c = (unsigned char)rnd();
                if (rn(2)) c = (unsigned char)(0x20 + rn(0x5f));   /* mostly printable */
                if (c == '\n' || c == 0) c = 'n';
                strs[i][k] = (char)c;
            }
            jb_strn(&b, strs[i], sl[i]);
        }
        jb_arr_end(&b);
        if (b.oom) FAIL("writer out of memory");
        if (json_parse_lines(b.s, b.len, &lines, &n, err, sizeof(err)) < 0) FAIL("writer output does not parse: %s\n%s", err, b.s);
        if (n != ns) FAIL("round trip: %d strings, wrote %d", n, ns);
        for (int i = 0; i < n; i++) {
            /* bytes that are not UTF-8 became U+FFFD; everything else must survive */
            int ascii = 1;
            for (size_t k = 0; k < sl[i]; k++) if ((unsigned char)strs[i][k] >= 0x80) ascii = 0;
            if (ascii && (strlen(lines[i]) != sl[i] || memcmp(lines[i], strs[i], sl[i]))) FAIL("round trip changed a string");
        }
        json_lines_free(lines, n);
        jb_free(&b);
    }
    free(buf);
    free(out);
}

/* ---- the server over a real socket ---- */

static void handler(const struct http_request *req, struct http_response *resp) {
    char **lines;
    int n;
    char err[256];
    jb_obj(&resp->body);
    jb_kstr(&resp->body, "path", req->path);
    jb_kstr(&resp->body, "query", req->query);
    if (json_parse_lines(req->body, req->body_len, &lines, &n, err, sizeof(err)) == 0) {
        jb_kint(&resp->body, "lines", n);
        json_lines_free(lines, n);
    }
    jb_obj_end(&resp->body);
}

static void pump(struct http_server *srv, int ms) {
    struct pollfd pfd[HTTP_MAX_POLLFDS];
    int n = http_pollfds(srv, pfd, HTTP_MAX_POLLFDS);
    int t = http_timeout_ms(srv);
    poll(pfd, n, t >= 0 && t < ms ? t : ms);
    http_process(srv, pfd, n);
}

static void fuzz_server(int iters) {
    char dir[] = "/tmp/fuzz-rest.XXXXXX", path[128], err[256];
    if (!mkdtemp(dir)) FAIL("mkdtemp");
    snprintf(path, sizeof(path), "%s/s", dir);
    int lfd = http_listen(path, getuid(), getgid(), 0600, err, sizeof(err));
    if (lfd < 0) FAIL("%s", err);
    struct http_server *srv = http_server_new(lfd, handler);
    char *buf = malloc(256 * 1024 + 1);
    int open_fds[64], nopen = 0;
    for (int it = 0; it < iters; it++) {
        size_t len;
        const char *c = corpus[rn(sizeof(corpus) / sizeof(*corpus))];
        len = strlen(c);
        memcpy(buf, c, len);
        if (rn(3)) mutate(buf, &len, 256 * 1024);
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        struct sockaddr_un sa = {.sun_family = AF_UNIX};
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 && errno != EAGAIN) { close(fd); pump(srv, 1); continue; }
        pump(srv, 0);
        /* send in random pieces, pumping the server between them */
        size_t off = 0;
        while (off < len) {
            size_t piece = 1 + rn(len - off < 4096 ? len - off : 4096);
            ssize_t w = send(fd, buf + off, piece, MSG_NOSIGNAL);
            if (w <= 0) break;
            off += (size_t)w;
            if (rn(4) == 0) pump(srv, 0);
        }
        if (rn(5) == 0) shutdown(fd, SHUT_WR);
        if (rn(4) == 0 && nopen < 64) { open_fds[nopen++] = fd; }   /* leave some open (idle clients) */
        else {
            for (int k = 0; k < 3; k++) {
                pump(srv, 1);
                char r[4096];
                while (recv(fd, r, sizeof(r), 0) > 0) {}
            }
            close(fd);
        }
        if (nopen == 64 || rn(50) == 0) { while (nopen) close(open_fds[--nopen]); }
    }
    while (nopen) close(open_fds[--nopen]);
    for (int k = 0; k < 20; k++) pump(srv, 1);
    http_server_free(srv);
    unlink(path);
    rmdir(dir);
    free(buf);
}

int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 200000;
    if (argc > 2) rng ^= strtoull(argv[2], NULL, 0);
    log_init("fuzz-rest", LOG_TO_STDERR, LOG_LVL_ERR);
    fuzz_parsers(iters);
    fuzz_server(iters / 50 > 200 ? iters / 50 : 200);
    printf("fuzz-rest: %d parser iterations and %d connections without a fault\n", iters,
           iters / 50 > 200 ? iters / 50 : 200);
    return 0;
}
