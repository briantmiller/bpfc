/*
 * Finding the network namespace a bpfcd instance manages: /run/netns/<name>,
 * a netns_path (symlinks followed), or the namespace of a host veth's peer.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include "netns.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <linux/net_namespace.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifndef NSIO
#define NSIO 0xb7
#endif
#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE _IO(NSIO, 0x3)
#endif
#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif
#ifndef IFLA_LINK_NETNSID
#define IFLA_LINK_NETNSID 37
#endif

/* ======================= small helpers ======================= */

int netns_fd_identity(int fd, uint64_t *dev, uint64_t *ino) {
    struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    *dev = (uint64_t)st.st_dev;
    *ino = (uint64_t)st.st_ino;
    return 0;
}

int netns_path_identity(const char *path, uint64_t *dev, uint64_t *ino) {
    struct stat st;
    if (stat(path, &st) < 0) return -errno;   /* stat follows every symlink */
    *dev = (uint64_t)st.st_dev;
    *ino = (uint64_t)st.st_ino;
    return 0;
}

/* Is fd a network namespace? (A /run/netns entry left behind unmounted is an empty file.) */
static int is_netns_fd(int fd) {
    int t = ioctl(fd, NS_GET_NSTYPE);
    if (t >= 0) return t == CLONE_NEWNET;
    struct statfs sf;   /* kernels before 4.11: nsfs, and hope it is a net namespace */
    return fstatfs(fd, &sf) == 0 && (unsigned long)sf.f_type == NSFS_MAGIC;
}

/* "a -> b -> c" for a symlink chain, so status shows where a path led. */
static void describe_chain(const char *path, char *out, size_t len) {
    char cur[PATH_MAX], tgt[PATH_MAX];
    snprintf(cur, sizeof(cur), "%s", path);
    size_t o = (size_t)snprintf(out, len, "%s", path);
    for (int hop = 0; hop < 40 && o < len; hop++) {
        ssize_t n = readlink(cur, tgt, sizeof(tgt) - 1);
        if (n < 0) break;
        tgt[n] = '\0';
        if (tgt[0] != '/') {
            if (!strncmp(tgt, "net:[", 5)) {          /* /proc/<pid>/ns/net */
                o += (size_t)snprintf(out + o, len - o, " (%s)", tgt);
                break;
            }
            char base[PATH_MAX];                      /* relative link: from its directory */
            snprintf(base, sizeof(base), "%s", cur);
            char *slash = strrchr(base, '/');
            if (slash) slash[1] = '\0'; else base[0] = '\0';
            char joined[PATH_MAX * 2];
            snprintf(joined, sizeof(joined), "%s%s", base, tgt);
            snprintf(tgt, sizeof(tgt), "%s", joined);
        }
        o += (size_t)snprintf(out + o, len - o, " -> %s", tgt);
        snprintf(cur, sizeof(cur), "%s", tgt);
    }
}

/* ======================= rtnetlink ======================= */

int netns_host_socket(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return -errno;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(s); return e; }
    struct timeval tv = {.tv_sec = 2};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return s;
}

static void addattr(struct nlmsghdr *n, int type, const void *data, int len) {
    struct rtattr *r = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type = type;
    r->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(r), data, len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(r->rta_len);
}

/* Sends one request and copies the single reply into buf. Returns its length or -errno. */
static int rtnl_ask(int sock, struct nlmsghdr *req, char *buf, size_t buflen) {
    static uint32_t seq;
    req->nlmsg_seq = ++seq;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (sendto(sock, req, req->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) return -errno;
    for (;;) {
        ssize_t len = recv(sock, buf, buflen, 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != req->nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                return e ? e : -ENODATA;
            }
            if ((char *)h != buf) memmove(buf, h, h->nlmsg_len);
            return (int)h->nlmsg_len;
        }
    }
}

/* The nsid the host namespace uses for the namespace behind fd; -1 when it has none. */
static int nsid_of_fd(int host_rtnl, int fd) {
    struct { struct nlmsghdr n; struct rtgenmsg g; char attrs[32]; } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.n.nlmsg_type = RTM_GETNSID;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.g.rtgen_family = AF_UNSPEC;
    uint32_t f = (uint32_t)fd;
    addattr(&req.n, NETNSA_FD, &f, sizeof(f));
    char buf[1024];
    int len = rtnl_ask(host_rtnl, &req.n, buf, sizeof(buf));
    if (len < 0) return -1;
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int alen = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(struct rtgenmsg));
    for (struct rtattr *a = (struct rtattr *)((char *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct rtgenmsg)));
         RTA_OK(a, alen); a = RTA_NEXT(a, alen))
        if (a->rta_type == NETNSA_NSID) return *(int32_t *)RTA_DATA(a);
    return -1;
}

struct veth_info { int ifindex; int has_nsid; int nsid; char kind[32]; };

/* Looks a link up by name in the host namespace. Returns 0, -ENOENT, or -errno. */
static int veth_query(int host_rtnl, const char *name, struct veth_info *vi) {
    memset(vi, 0, sizeof(*vi));
    struct { struct nlmsghdr n; struct ifinfomsg i; char attrs[64]; } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_type = RTM_GETLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.i.ifi_family = AF_UNSPEC;
    addattr(&req.n, IFLA_IFNAME, name, (int)strlen(name) + 1);
    char buf[16384];
    int len = rtnl_ask(host_rtnl, &req.n, buf, sizeof(buf));
    if (len == -ENODEV) return -ENOENT;
    if (len < 0) return len;
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    if (h->nlmsg_type != RTM_NEWLINK) return -EPROTO;
    struct ifinfomsg *ifi = NLMSG_DATA(h);
    vi->ifindex = ifi->ifi_index;
    int alen = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*ifi));
    for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
        if (a->rta_type == IFLA_LINK_NETNSID) {
            vi->has_nsid = 1;
            vi->nsid = *(int32_t *)RTA_DATA(a);
        } else if (a->rta_type == IFLA_LINKINFO) {
            int blen = RTA_PAYLOAD(a);
            for (struct rtattr *b = RTA_DATA(a); RTA_OK(b, blen); b = RTA_NEXT(b, blen))
                if (b->rta_type == IFLA_INFO_KIND)
                    snprintf(vi->kind, sizeof(vi->kind), "%.*s", (int)RTA_PAYLOAD(b), (char *)RTA_DATA(b));
        }
    }
    return 0;
}

/* Parent pid of pid, or -1. */
static int ppid_of(int pid) {
    char p[64], buf[512];
    snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');      /* comm may contain spaces and parentheses */
    int ppid = -1;
    if (rp && sscanf(rp + 1, " %*c %d", &ppid) != 1) ppid = -1;
    return ppid;
}

/*
 * Finds a path outside bpfcd that refers to the namespace with this nsid:
 * a /run/netns entry, else /proc/<pid>/ns/net of a process that is neither
 * bpfcd nor one of its children. On success *fdp is that namespace, opened.
 */
static int find_witness(int host_rtnl, int nsid, char *witness, size_t wlen, int *fdp) {
    /* Each namespace is queried once, however many processes share it. */
    struct { uint64_t dev, ino; } seen[256];
    int nseen = 0;
    int self = (int)getpid();
    const char *dirs[] = {NETNS_RUN_DIR, "/proc"};

    for (int d = 0; d < 2; d++) {
        DIR *dp = opendir(dirs[d]);
        if (!dp) continue;
        struct dirent *de;
        while ((de = readdir(dp))) {
            char path[PATH_MAX];
            int pid = 0;
            if (d == 0) {
                if (de->d_name[0] == '.') continue;
                snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, de->d_name);
            } else {
                if (!isdigit((unsigned char)de->d_name[0])) continue;
                pid = atoi(de->d_name);
                if (pid == self) continue;
                snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
            }
            uint64_t dev = 0, ino = 0;
            if (netns_path_identity(path, &dev, &ino) < 0) continue;
            int dup = 0;
            for (int i = 0; i < nseen; i++)
                if (seen[i].dev == dev && seen[i].ino == ino) { dup = 1; break; }
            if (dup) continue;
            if (nseen < (int)(sizeof(seen) / sizeof(seen[0]))) {
                seen[nseen].dev = dev;
                seen[nseen].ino = ino;
                nseen++;
            }
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) continue;
            if (!is_netns_fd(fd) || nsid_of_fd(host_rtnl, fd) != nsid) { close(fd); continue; }
            /* bpfcd's own short-lived bpfc runs are not a reason to keep a namespace */
            if (pid && ppid_of(pid) == self) {
                close(fd);
                nseen--;     /* another process may still share it */
                continue;
            }
            closedir(dp);
            snprintf(witness, wlen, "%s", path);
            *fdp = fd;
            return 0;
        }
        closedir(dp);
    }
    return -ENOENT;
}

/* ======================= locating ======================= */

void netns_loc_close(struct netns_loc *loc) {
    if (loc->fd >= 0) close(loc->fd);
    loc->fd = -1;
    loc->dev = loc->ino = 0;
    loc->witness[0] = '\0';
}

static int locate_path(const char *path, struct netns_loc *loc) {
    char chain[sizeof(loc->desc) - 64];
    describe_chain(path, chain, sizeof(chain));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        snprintf(loc->desc, sizeof(loc->desc), "%s: %s", chain, strerror(e));
        return e == ENOENT || e == ENOTDIR ? -ENOENT : -e;
    }
    if (!is_netns_fd(fd)) {
        close(fd);
        snprintf(loc->desc, sizeof(loc->desc), "%s: not a network namespace", chain);
        return -ENOENT;   /* e.g. a /run/netns entry left unmounted: wait for a real one */
    }
    loc->fd = fd;
    netns_fd_identity(fd, &loc->dev, &loc->ino);
    snprintf(loc->witness, sizeof(loc->witness), "%s", path);
    snprintf(loc->desc, sizeof(loc->desc), "%s", chain);
    return 0;
}

static int locate_veth(const struct config *cfg, int host_rtnl, struct netns_loc *loc) {
    struct veth_info vi;
    int rc = veth_query(host_rtnl, cfg->netns_veth, &vi);
    if (rc == -ENOENT) {
        snprintf(loc->desc, sizeof(loc->desc), "veth %s: no such interface", cfg->netns_veth);
        return -ENOENT;
    }
    if (rc < 0) {
        snprintf(loc->desc, sizeof(loc->desc), "veth %s: %s", cfg->netns_veth, strerror(-rc));
        return rc;
    }
    if (strcmp(vi.kind, "veth")) {
        snprintf(loc->desc, sizeof(loc->desc), "%s is %s%s, not a veth", cfg->netns_veth,
                 vi.kind[0] ? "a " : "a device without a kind", vi.kind);
        return -EINVAL;
    }
    if (!vi.has_nsid) {
        snprintf(loc->desc, sizeof(loc->desc),
                 "veth %s: its peer is still in this namespace (not moved into one yet)", cfg->netns_veth);
        return -ENOENT;
    }
    int fd;
    char witness[PATH_MAX];
    if (find_witness(host_rtnl, vi.nsid, witness, sizeof(witness), &fd) < 0) {
        snprintf(loc->desc, sizeof(loc->desc),
                 "veth %s: its peer's namespace (nsid %d) has no process or %s entry in it",
                 cfg->netns_veth, vi.nsid, NETNS_RUN_DIR);
        return -ENOENT;
    }
    loc->fd = fd;
    netns_fd_identity(fd, &loc->dev, &loc->ino);
    loc->veth_ifindex = vi.ifindex;
    loc->veth_nsid = vi.nsid;
    snprintf(loc->witness, sizeof(loc->witness), "%s", witness);
    snprintf(loc->desc, sizeof(loc->desc), "peer of veth %s (nsid %d, %s)", cfg->netns_veth, vi.nsid, witness);
    return 0;
}

int netns_locate(const struct config *cfg, int host_rtnl, struct netns_loc *loc) {
    loc->fd = -1;
    loc->dev = loc->ino = 0;
    loc->witness[0] = '\0';
    loc->veth_ifindex = 0;
    loc->veth_nsid = -1;
    if (cfg->netns_veth[0]) {
        if (host_rtnl < 0) {
            snprintf(loc->desc, sizeof(loc->desc), "veth %s: no host rtnetlink socket", cfg->netns_veth);
            return -EBADF;
        }
        return locate_veth(cfg, host_rtnl, loc);
    }
    char path[PATH_MAX];
    if (cfg->netns_path[0]) snprintf(path, sizeof(path), "%s", cfg->netns_path);
    else snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, cfg->netns);
    return locate_path(path, loc);
}

int netns_changed(const struct config *cfg, int host_rtnl, struct netns_loc *loc) {
    uint64_t dev = 0, ino = 0;
    if (!cfg->netns_veth[0]) {
        /* The configured path (re-followed through any symlinks; it may itself
         * have changed on a reload) must still lead to the same namespace. */
        char path[PATH_MAX];
        if (cfg->netns_path[0]) snprintf(path, sizeof(path), "%s", cfg->netns_path);
        else snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, cfg->netns);
        if (strcmp(path, loc->witness)) return 1;
        if (netns_path_identity(path, &dev, &ino) < 0) return 1;
        return dev != loc->dev || ino != loc->ino;
    }
    struct veth_info vi;
    if (veth_query(host_rtnl, cfg->netns_veth, &vi) < 0 || strcmp(vi.kind, "veth") || !vi.has_nsid ||
        vi.ifindex != loc->veth_ifindex || vi.nsid != loc->veth_nsid)
        return 1;
    if (netns_path_identity(loc->witness, &dev, &ino) == 0 && dev == loc->dev && ino == loc->ino)
        return 0;
    /* The witness went away: is anything else besides bpfcd still in that namespace? */
    int fd;
    char witness[PATH_MAX];
    if (find_witness(host_rtnl, loc->veth_nsid, witness, sizeof(witness), &fd) < 0) return 1;
    close(fd);
    snprintf(loc->witness, sizeof(loc->witness), "%s", witness);
    snprintf(loc->desc, sizeof(loc->desc), "peer of veth %s (nsid %d, %s)", cfg->netns_veth, loc->veth_nsid, witness);
    return 0;
}

/* ======================= entering for a command ======================= */

static void unescape_mountinfo(char *s) {
    char *o = s;
    for (char *p = s; *p; p++) {
        if (p[0] == '\\' && p[1] >= '0' && p[1] <= '3' && p[2] >= '0' && p[2] <= '7' && p[3] >= '0' && p[3] <= '7') {
            *o++ = (char)((p[1] - '0') * 64 + (p[2] - '0') * 8 + (p[3] - '0'));
            p += 3;
        } else {
            *o++ = *p;
        }
    }
    *o = '\0';
}

int netns_enter_for_exec(int nsfd) {
    if (setns(nsfd, CLONE_NEWNET) < 0) {
        int e = errno;
        fprintf(stderr, "bpfcctl: cannot enter the network namespace: %s%s\n", strerror(e),
                e == EPERM ? " (run as root)" : "");
        return -e;
    }
    if (unshare(CLONE_NEWNS) < 0) {
        int e = errno;
        fprintf(stderr, "bpfcctl: cannot create a mount namespace: %s\n", strerror(e));
        return -e;
    }
    /* Changes made below must not reach the host's mounts. */
    if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
        int e = errno;
        fprintf(stderr, "bpfcctl: cannot make mounts private: %s\n", strerror(e));
        return -e;
    }

    /* Mounts below /sys (bpffs, cgroup, debugfs, ...) in mount order, held open across the remount. */
    struct { char path[PATH_MAX]; int fd; } sub[64];
    int nsub = 0;
    FILE *mi = fopen("/proc/self/mountinfo", "re");
    char line[4096];
    while (mi && fgets(line, sizeof(line), mi) && nsub < 64) {
        char mp[PATH_MAX];
        if (sscanf(line, "%*s %*s %*s %*s %4095s", mp) != 1) continue;
        unescape_mountinfo(mp);
        if (strncmp(mp, "/sys/", 5)) continue;
        int dup = 0;
        for (int i = 0; i < nsub; i++)
            if (!strcmp(sub[i].path, mp)) dup = 1;   /* stacked mounts: the top one is what is seen */
        if (dup) continue;
        int fd = open(mp, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) continue;
        snprintf(sub[nsub].path, sizeof(sub[nsub].path), "%s", mp);
        sub[nsub].fd = fd;
        nsub++;
    }
    if (mi) fclose(mi);

    /*
     * A sysfs mounted in this network namespace shows its interfaces under
     * /sys/class/net. It is stacked on the old /sys rather than replacing it
     * (as `ip netns exec` does): mounts that are still attached underneath
     * can be bound back, a detached one cannot.
     */
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) < 0) {
        int e = errno;
        fprintf(stderr, "bpfcctl: cannot mount sysfs for the namespace: %s\n", strerror(e));
        for (int i = 0; i < nsub; i++) close(sub[i].fd);
        return -e;
    }
    for (int i = 0; i < nsub; i++) {
        char src[64];
        snprintf(src, sizeof(src), "/proc/self/fd/%d", sub[i].fd);
        if (mount(src, sub[i].path, NULL, MS_BIND, NULL) < 0 && !strncmp(sub[i].path, "/sys/fs/bpf", 11))
            fprintf(stderr, "bpfcctl: warning: cannot keep %s mounted: %s\n", sub[i].path, strerror(errno));
        close(sub[i].fd);
    }
    return 0;
}
