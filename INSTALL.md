# Building and installing bpfc

- [Requirements](#requirements)
- [Building](#building)
- [Running from the source tree](#running-from-the-source-tree)
- [make install](#make-install)
- [RPM packages (RHEL 9/10)](#rpm-packages-rhel-910)
- [Debian packages (Debian, Ubuntu)](#debian-packages-debian-ubuntu)
- [Static binaries](#static-binaries)
- [After installing](#after-installing)
- [Containers](#containers)

## Requirements

**To build:** `gcc` (or another C compiler: `make CC=clang`), `make` and the kernel headers (`kernel-headers` on RHEL). bpfc is plain C with no library dependencies besides libc. It doesn't use LLVM, clang or libbpf.

**To build RPMs:** `rpm-build` and `systemd-rpm-macros`, plus `glibc-static` for a static build.

```bash
dnf install gcc make kernel-headers rpm-build systemd-rpm-macros
```

**To build .deb packages:** see [Debian packages](#debian-packages-debian-ubuntu).

**To run:**

| | |
| :--- | :--- |
| Packaged for | RHEL 9 and RHEL 10 (RPM); Debian 12+ and Ubuntu 22.04+ (.deb) |
| Kernel | 4.18 or later for TC programs (the RHEL 8 verifier). Some commands need newer kernels: `start-loop`/`loop` 5.3+; ring buffers (`ringbuf-map`, `log`) 5.8+ |
| XDP programs (`-d xdp`) | kernel 5.18+ or RHEL 9.2+ |
| Privileges | root, or `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` (`CAP_BPF` on newer kernels) |
| Maps | a bpffs mounted at `/sys/fs/bpf` (the default on RHEL), or another directory with `-m` |
| bpfc-programs tools | `bash` 4.4+, `gawk` and coreutils |

If the kernel headers at build time are 5.16 or later (RHEL 9 backports this), `bpfc -I` also prints how many instructions the verifier processed (`verified=`), which the `verifier-budget` test uses. The Makefile detects this by itself.

## Building

```bash
make                # bpfc, bpfcd/bpfcd, bpfcd/bpfcctl, frontends/acl
make clean
```

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `CC` | `gcc` | C compiler |
| `CFLAGS` | `-O2 -g` | compiler flags (warnings are added on top) |
| `LDFLAGS` | | linker flags |
| `STATIC` | `0` | `STATIC=1` links every binary statically ([below](#static-binaries)) |
| `VERSION`, `RELEASE` | from the Makefile | version and RPM release, e.g. `make rpm RELEASE=8` |

## Running from the source tree

No installation is needed to try bpfc: run `./bpfc` from the tree. The bpfc-programs tools also run in place. For example, `programs/dataplane/bpfc-dataplane-gen` finds `programs/dataplane/profiles/` next to it. Point them at your build with `--bpfc ./bpfc` or `BPFC_BIN=./bpfc` when bpfc isn't on your `PATH`.

## make install

```bash
make install                         # everything: bpfc, bpfcd, bpfcctl, frontends, docs, and the programs
make install-core                    # only what goes in the bpfc package
make install-container               # only what goes in bpfc-container
make install-programs                # only what goes in bpfc-programs (everything under programs/)
make install DESTDIR=/tmp/stage      # stage into a directory (for packaging)
make install PREFIX=/usr/local
```

| Variable | Default |
| :--- | :--- |
| `DESTDIR` | (empty) |
| `PREFIX` | `/usr` |
| `SBINDIR` | `$(PREFIX)/sbin` |
| `MANDIR` | `$(PREFIX)/share/man` |
| `DATADIR` | `$(PREFIX)/share` |
| `DOCDIR` | `$(PREFIX)/share/doc/bpfc` |
| `PROGRAMS_DOCDIR` | `$(PREFIX)/share/doc/bpfc-programs` |
| `CONTAINER_DOCDIR` | `$(PREFIX)/share/doc/bpfc-container` |
| `LIBEXECDIR` | `$(PREFIX)/libexec` |
| `SYSCONFDIR` | `/etc` |
| `UNITDIR` | `$(PREFIX)/lib/systemd/system` |
| `SYSUSERSDIR` | `$(PREFIX)/lib/sysusers.d` |
| `LOCALSTATEDIR` | `/var/lib` |

What goes where (with the defaults):

| Path | Contents |
| :--- | :--- |
| `/usr/sbin/bpfc`, `bpfcd`, `bpfcctl` | the compiler, the daemon and its status tool |
| `/usr/sbin/bpfcd-entrypoint` | runs bpfcd as a container's PID 1 |
| `/usr/libexec/bpfc/frontends/acl` | the Cisco IOS access-list frontend |
| `/etc/bpfc/bpfc.conf` | bpfcd's settings (`bpfc.conf(5)`) |
| `/etc/bpfc/interfaces.d/` | program files bpfcd keeps attached |
| `/etc/bpfc/netns/` | per-namespace settings and programs |
| `/etc/bpfc/include/` | include files (`include x.bpfc;`), e.g. `dedup-iface.bpfc` |
| `/etc/bpfc/frontends/`, `/etc/bpfc/acl.d/` | local frontends; shared ACL definitions (object groups) |
| `/var/lib/bpfc/interfaces.d/` | programs written through the REST API |
| `/usr/lib/systemd/system/bpfcd.service`, `bpfcd-netns@.service` | systemd units |
| `/usr/lib/sysusers.d/bpfc.conf` | the `bpfc` group (REST socket access) |
| `/usr/share/man/man8/`, `man5/` | `bpfc(8)`, `bpfcd(8)`, `bpfcctl(8)`, `bpfc.conf(5)` |
| `/usr/share/doc/bpfc/` | README, guides and `examples/` (`xdp`, `tc`, `flow`, `acl`, `interfaces.d`) |

`make install-programs` installs whatever `programs/` holds, one subfolder per program. Nothing has to be listed in the Makefile or the spec when a program is added:

| In `programs/<name>/` | Installed to |
| :--- | :--- |
| executable files | `/usr/sbin/` |
| `profiles/*.profile` | `/usr/share/bpfc/<name>/profiles/`, with `/etc/bpfc/<name>/profiles.d/` created for local profiles |
| `*.md` | `/usr/share/doc/bpfc-programs/<name>/` |
| `examples/` | `/usr/share/doc/bpfc-programs/<name>/examples/` |
| `include/*.bpfc` | `/etc/bpfc/include/` (configuration files) |

## RPM packages (RHEL 9/10)

```bash
make rpm                                      # binary and source RPMs in ./rpmbuild
make srpm                                     # the source RPM only
make dist                                     # the source tarball, bpfc-<version>.tar.gz
make rpm RPMBUILD_OPTS="--with static"        # statically linked binaries
make rpm RELEASE=8                            # another release number
```

`make rpm` prints the paths of the RPMs it built. There are three packages:

| Package | Contents | Requires |
| :--- | :--- | :--- |
| `bpfc` | bpfc, bpfcd, bpfcctl, the ACL frontend, the systemd units, man pages, docs and examples | |
| `bpfc-container` | `bpfcd-entrypoint`, to run bpfcd as a container's PID 1 without systemd | `bpfc` of the same build |
| `bpfc-programs` | the included programs: dataplane, ECMP, linkcap, dedup, flowmon, portscan-guard, with their status tools, profiles, include files, design notes and examples | `bpfc` of the same build, `bash`, `gawk`, coreutils |

```bash
dnf install ./rpmbuild/RPMS/*/bpfc-[0-9]*.rpm ./rpmbuild/RPMS/*/bpfc-programs-*.rpm
```

Neither `bpfc` nor `bpfc-container` requires systemd. The unit files simply go unused in a container.

## Debian packages (Debian, Ubuntu)

```bash
apt install build-essential debhelper pkgconf systemd-dev   # Debian 12 / Ubuntu 22.04: systemd in place of systemd-dev
make deb                                       # binary and source packages in ./debbuild
make deb DEBBUILD_OPTS=-b                      # binary packages only
DEB_BUILD_PROFILES=pkg.bpfc.static make deb    # statically linked binaries
DEB_BUILD_OPTIONS=nocheck make deb             # skip the compile tests run during the build
```

`make deb` builds from the source tarball (`make dist`), as `make rpm` does, and prints the paths of the packages it built. The three packages match the RPMs: `bpfc` (architecture-specific), and `bpfc-container` and `bpfc-programs` (architecture `all`). `bpfc-programs` depends on `bpfc` of the same build and on `gawk`.

```bash
apt install ./debbuild/bpfc_*.deb ./debbuild/bpfc-programs_*.deb     # apt resolves the dependencies
```

The packaging is in `debian/` and also builds with the usual Debian tools in an unpacked tree (`dpkg-buildpackage -us -uc -b`, `sbuild`, `pbuilder`). The version in `debian/changelog` must match `VERSION` in the Makefile: after changing `VERSION`, add a changelog entry (`dch -v <version>-1`), or `make deb` stops with a message saying so. The Debian revision (`-1`) is separate from the RPM `RELEASE`.

Differences from the RPMs, following Debian conventions:

- `bpfcd.service` isn't enabled on installation (`systemctl enable --now bpfcd`, as on RHEL). Once it's enabled, an upgrade restarts it, along with any running `bpfcd-netns@` instances. Their programs are adopted, not reinstalled.
- The `bpfc` group is created in `postinst` with `groupadd --system`. Removing or purging the package leaves the group, as is usual on Debian.
- Example programs under `/usr/share/doc` stay uncompressed, so they can be copied into `/etc/bpfc` as they are. The Markdown guides are compressed (`README.md.gz`).
- Purging removes the configuration files the packages installed (`bpfc.conf`, the include files), but not your own program files in `/etc/bpfc/interfaces.d`, nor programs written through the REST API in `/var/lib/bpfc`.

## Static binaries

`make STATIC=1` (or `make rpm RPMBUILD_OPTS="--with static"`, which needs `glibc-static`, or `DEB_BUILD_PROFILES=pkg.bpfc.static make deb`) links every binary statically. The binaries then run in images whose libc doesn't match the build host, or that have none (minimal or distroless containers).

## After installing

```bash
systemctl enable --now bpfcd                    # keep /etc/bpfc/interfaces.d attached
systemctl enable --now bpfcd-netns@<name>       # the same for network namespace <name>
usermod -aG bpfc <user>                         # access to the REST socket, if you enable it
```

See [README.md](README.md#bpfcd-keeping-programs-attached) for how bpfcd works, and `bpfcd(8)`, `bpfcctl(8)` and `bpfc.conf(5)` for the details.

## Containers

The `bpfc-container` package runs bpfcd as a container's main process. [dist/container/README.md](dist/container/README.md) has an example Containerfile, the `podman run` options it needs, and the `BPFCD_*` environment variables that replace `bpfc.conf`.

To test the build, see [TESTING.md](TESTING.md).
