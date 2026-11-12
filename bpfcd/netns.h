/*
 * Finding the network namespace a bpfcd instance manages.
 *
 * Copyright (C) 2026
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef BPFC_NETNS_H
#define BPFC_NETNS_H

#include <stdint.h>
#include <limits.h>
#include "common.h"

/*
 * A located namespace. Exactly one way of finding it applies, by priority:
 *
 *   netns_veth = <host veth>   the namespace holding that veth's peer
 *   netns_path = <file>        a namespace file; symlinks (and chains of them)
 *                              are followed again on every check
 *   (neither)                  /run/netns/<name>, as `ip netns add` creates
 *
 * "witness" is a path that refers to the namespace from outside bpfcd: the
 * namespace file itself, or for a veth a /run/netns entry or /proc/<pid>/ns/net
 * of a process inside it. While bpfcd is inside a namespace it keeps it alive,
 * so the witness is how bpfcd notices the namespace has been given up by
 * everything else.
 */
struct netns_loc {
    int fd;                     /* open namespace (CLOEXEC), -1 when not found */
    uint64_t dev, ino;          /* namespace identity */
    char witness[PATH_MAX];
    int veth_ifindex;           /* veth mode: host veth's ifindex and its peer's nsid */
    int veth_nsid;
    char desc[512];             /* what was found, or why nothing was */
};

/*
 * Opens a socket for rtnetlink requests in the current namespace. Call it in
 * the namespace where netns_veth lives (where bpfcd starts); the socket stays
 * bound to that namespace after setns().
 */
int netns_host_socket(void);

/*
 * Locates the namespace cfg points at. host_rtnl is needed for netns_veth.
 * Returns 0 with loc->fd open, -ENOENT when it does not exist (yet), or
 * another -errno for a setting that cannot work (loc->desc says why).
 */
int netns_locate(const struct config *cfg, int host_rtnl, struct netns_loc *loc);

/*
 * Cheap re-check of a located namespace: 0 while cfg still leads to the same
 * namespace, 1 when it now leads elsewhere or nowhere (call netns_locate
 * again). Path mode stats the path, which re-follows its symlinks; veth mode
 * re-reads the veth's peer nsid and checks that the witness still refers to
 * the namespace (looking for another witness when it does not).
 */
int netns_changed(const struct config *cfg, int host_rtnl, struct netns_loc *loc);

void netns_loc_close(struct netns_loc *loc);

/* Identity of the namespace an fd or a path refers to. Returns 0 or -errno. */
int netns_fd_identity(int fd, uint64_t *dev, uint64_t *ino);
int netns_path_identity(const char *path, uint64_t *dev, uint64_t *ino);

/*
 * Enters the namespace for the rest of the process, like `ip netns exec`:
 * setns(), then a private mount namespace with /sys remounted for the new
 * network namespace (so /sys/class/net shows its interfaces) and every bpffs
 * mount below /sys bound back, so pinned maps stay reachable. Returns 0 or
 * -errno (with a message on stderr).
 */
int netns_enter_for_exec(int nsfd);

#endif
