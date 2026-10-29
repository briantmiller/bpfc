# Running bpfcd in a container

`bpfc-container` provides `/usr/sbin/bpfcd-entrypoint`, which starts bpfcd as the container's main process (PID 1) with no systemd. Neither `bpfc` nor `bpfc-container` requires systemd.

## Run

To manage the host's interfaces the container shares the host network namespace and the host's bpffs:

```bash
podman run -d --name bpfcd \
  --network host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/bpfc/interfaces.d:/etc/bpfc/interfaces.d:ro \
  -v bpfc-state:/run/bpfc \
  localhost/bpfcd
```

| Option | Why |
| --- | --- |
| `--network host` | bpfcd attaches programs to the interfaces it can see. Without it, it manages only the container's own interfaces. |
| `--privileged` | The simplest setup that works. See "Fewer privileges" below. |
| `-v /sys/fs/bpf:/sys/fs/bpf` | Pinned maps (NAT state, counters) live on the host and survive container restarts. Without it the entrypoint mounts a private bpffs and maps are lost on restart. |
| `-v .../interfaces.d:...:ro` | Your program files, same layout as on a host. |
| `-v bpfc-state:/run/bpfc` | Keeps bpfcd's state across restarts so it adopts running programs instead of reinstalling them, and removes programs whose files were deleted while it was down. |

Programs stay attached when the container stops, as with the systemd service. Set `-e BPFCD_REMOVE_ON_STOP=yes` to detach them on stop.

## Operate

```bash
podman exec bpfcd bpfcctl                      # status
podman exec bpfcd bpfcctl show eth0 ingress 100
podman exec bpfcd bpfcctl reload               # rescan and report failures
podman kill --signal HUP bpfcd                 # same rescan, no report
podman logs -f bpfcd                           # bpfcd's log
podman stop bpfcd                              # SIGTERM: clean stop
```

The image also runs other commands in place of the daemon, for example `podman run --rm ... localhost/bpfcd bpfcd --test` to check a configuration, or `... localhost/bpfcd sh`.

## Configure

`/etc/bpfc/bpfc.conf` is read if you mount one. Any setting can also be given as an environment variable named `BPFCD_` plus the setting in capitals, which overrides the file:

| Variable | Setting |
| --- | --- |
| `BPFCD_ON_EXTERNAL_CHANGE` | `reinstall` or `log` |
| `BPFCD_REMOVE_ON_STOP` | `yes` or `no` |
| `BPFCD_REINSTALL_LIMIT` | reinstalls per program per minute |
| `BPFCD_MAP_DIR` | pinned map directory (must be on bpffs) |
| `BPFCD_CONFIG_DIR` | program directory |
| `BPFCD_STATE_DIR` | state directory |
| `BPFCD_LOG_LEVEL` | `error`, `warning`, `info`, `debug` |
| `BPFCD_COMPILE_TIMEOUT` | seconds per bpfc run |

`bpfcctl` reads the same variables, so `podman exec` finds a relocated state directory. `BPFCD_SKIP_CHECKS=1` skips the entrypoint's privilege checks.

## Fewer privileges

bpfcd needs `CAP_NET_ADMIN` and `CAP_BPF` (kernel 5.8 or later; otherwise `CAP_SYS_ADMIN`). `debug-log` needs `CAP_PERFMON`. `bpfcctl show --bytecode` needs `CAP_SYS_ADMIN`. The entrypoint checks these at start and names what is missing.

```bash
podman run -d --name bpfcd --network host \
  --cap-add NET_ADMIN --cap-add BPF --cap-add PERFMON \
  -v /sys/fs/bpf:/sys/fs/bpf ... localhost/bpfcd
```

Capabilities may not be enough on their own. The runtime's default seccomp profile and SELinux (`container_t`) can also block the `bpf()` system call. Validate this variant on your hosts before using it; if loads fail with "Operation not permitted", add `--security-opt label=type:spc_t` or return to `--privileged`.

## Kubernetes / OpenShift

Run it as a DaemonSet with `hostNetwork: true`, a `privileged` security context, and `hostPath` volumes for `/sys/fs/bpf` and the state directory. Deliver the program files from a ConfigMap. A ConfigMap's keys cannot contain `/`, so lay out the `<iface>/<direction>/<priority>.bpfc` tree with `items` entries whose `path` is, for example, `eth0/ingress/100.bpfc`. bpfcd does not watch for ConfigMap updates; send it SIGHUP (for example from a sidecar or `kubectl exec ... bpfcctl reload`) after a change.
