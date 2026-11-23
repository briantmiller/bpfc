# Testing bpfc

The tests live in `tests/`. One runner, `tests/run-tests.sh` (or `./test.sh`, which calls it), runs any set of suites and prints a pass/fail/skip total for each one. The `make check*` targets use the same runner.

- [Quick reference](#quick-reference)
- [Running the suites](#running-the-suites)
- [Compile tests (no root)](#compile-tests-no-root)
- [Kernel and network tests (root)](#kernel-and-network-tests-root)
- [Tools the suites need](#tools-the-suites-need)
- [Coverage](#coverage)
- [Fuzzing](#fuzzing)
- [Tuning and test hooks](#tuning-and-test-hooks)
- [Writing a new suite](#writing-a-new-suite)

## Quick reference

| Command | Root | What it runs |
| :--- | :--- | :--- |
| `make check-compile` | no | `compile`: every field and command compiles, and bad programs get clear errors |
| `make check` | yes | compile, preprocessor, stack, keys, bpfcd, netns, rest, xdp, xdp-examples, tc-examples, flow-examples, acl, frontends, dedup, ecmp, container, install |
| `make check-dataplane` | yes | `verifier-budget`, `dataplane`, `dataplane-udp` |
| `make check-ecmp` | yes | `ecmp` |
| `make check-linkcap` | yes | `linkcap` |
| `make check-all` / `./test.sh` | yes | every suite, pytest included (about an hour) |
| `./test.sh <suite> ...` | depends | only the named suites, e.g. `./test.sh compile nat` |
| `make coverage` | yes | the suites against a gcov build of `bpfc`, with a coverage report |
| `make fuzz` | no | the REST API's HTTP and JSON parsers under ASan/UBSan |

Build first (`make`). Run the tests from the repository root.

## Running the suites

```bash
./test.sh                     # every suite (root; about an hour)
./test.sh compile keys        # only these
./test.sh -f                  # print failures only, plus the summary
./test.sh -v nat              # each suite's full output
./test.sh -l /tmp/logs bpfcd  # keep the logs in /tmp/logs
./test.sh -t 600 dataplane    # time limit per suite in seconds (default 1800)
make check TESTFLAGS=-f       # pass runner flags through make
```

At the end the runner prints a table with each suite's pass, fail and skip counts, how long it took and why it was skipped (if it was). It exits non-zero if anything failed. Logs go to `/tmp/bpfc-tests.*` unless you pass `-l`.

A suite **skips** rather than fails when it isn't run as root or the system lacks something it needs: a tool, kernel MPLS routing, or scapy. A suite that exits non-zero without printing a FAIL line counts as one failure, and so does a suite that runs past its time limit, so a crash is never counted as success. Each suite runs in its own process group, which is killed afterwards, so leftover helpers such as `nc`, `iperf3` or `tcpdump` can't hang the runner.

Most suites create network namespaces, veth pairs and pinned maps with names of their own (`bpfct*`, `bnt-*`, `brt-*`, ...) and remove them afterwards. Run them on a test machine or VM, not on a router in service.

## Compile tests (no root)

These compile programs but don't attach them, so they need no root and no network.

| Suite | What it checks |
| :--- | :--- |
| `compile` | Every field and command compiles. Hex and decimal values give the same code. Invalid programs are refused with a clear message. The few commands that create maps need root (CAP_BPF) even to compile; that section runs only as root. |
| `preprocessor` | `include`, `const`, `define`, `repeat` and `when`: what `bpfc -E` expands each to, and the error messages. A last check that loads a program into the kernel needs root. |
| `stack` | The stack layout: variables take as many slots as the program declares, and instructions fit their scratch space into what is left. The kernel tests need root. |
| `install` | What `make install` puts where, in a scratch `DESTDIR`: binaries, man pages, docs, and everything under `programs/`. As root, it also runs the installed dataplane generator against the installed profiles. When `rpmbuild` is installed, it builds the RPMs and checks their file lists and dependencies. |

## Kernel and network tests (root)

These attach programs to real interfaces inside network namespaces and send traffic through them.

### Compiler and language

| Suite | What it checks |
| :--- | :--- |
| `bpfc` | The core commands on a live path: ARP replies, `calc` (including 64-bit constants), `clone`, GRE encap/decap, `fib-lookup`, byte insertion and removal, and more. |
| `util` | The command-line tool itself: `get time`, `get random`, `-I` (attach info), `-T` (check only), `-D` (delete one priority), `-c` (clear), and replacing a filter someone else attached. |
| `loops` | Runtime loops (`start-loop` / `loop` and the loop register) on a routed path. |
| `keys` | Flow keys and the commands built on them: `hash`, `pack`, `unpack`, `flow-key`, `seen`, `over-rate`, `count`, `prefix-map`/`in`, the tcpdump-style matches, `set src-port`/`dst-port`, and `bpfc -H`/`-K`/`-V`/`-w`/`-x`. Every key a program computes from a packet is compared with the one `bpfc -H` computes from the same values, so the two can't drift apart. |
| `nat` | The NAT examples: the README's long-hand ICMP/TCP/UDP NAT, run as printed there, plus `nat-pack.bpfc` and the port-translating `nat-pat.bpfc`. |
| `mpls` | MPLS pseudowire encapsulation and decapsulation between two CE hosts. Needs kernel MPLS routing (`mpls_router`). |
| `mpls-xdp` | The same pseudowire programs, attached as XDP programs (`test-mpls.sh -x`). |
| `frag` | `ip-frag` / `ip-defrag` at several fragment sizes: three ordinary pings for each size, then the loss under load (100 parallel pings), which must stay below `STRESS_MAX_LOSS`. |
| `mpls-frag` | Fragmentation inside the MPLS pseudowire. Needs `mpls_router`. |
| `throttle` | Byte counting in a map under iperf load, with fragmentation in the path. |
| `cve-2026-98432` | `dist/examples/cve-2026-98432.bpfc`: crafted frames (scapy) and real handshakes that carry IP options must be filtered exactly as intended. Needs python3-scapy. |
| `pytest` | `tests/test_bpfc.py`, about 60 packet-level tests: scapy builds a packet, it's sent through a bpfc program, and tcpdump captures what arrives. Covers IPv6, VLAN/QinQ, MPLS, GRE, ARP, checksums and resizing. Needs pytest and scapy. |
| `verifier-budget` | Loads every program the dataplane generator makes (each profile, and the extremes of its structural settings) and fails if one uses more than `BUDGET_PCT` percent (default 85) of the verifier's 1,000,000-instruction limit. Needs kernel 5.16+ (it skips on older ones). |

### XDP and the examples

| Suite | What it checks |
| :--- | :--- |
| `xdp` | `bpfc -d xdp` (generic mode): actions, checksum-aware rewrites, VLAN tags, resizing, and refusing commands that need an skb. Also bpfcd's `interfaces.d/<if>/xdp.bpfc`. |
| `xdp-examples` | Each file in `dist/examples/xdp` (the README's XDP examples), run as it is, and the `fib-lookup` options they rely on. It also checks that the README shows each file exactly as it is. |
| `tc-examples` | Each file in `dist/examples/tc` (the README's TC examples), run as it is, with the same check that the README matches the files. |
| `flow-examples` | The flow-tracking examples in `dist/examples/flow` (see [doc/flow-tracking.md](doc/flow-tracking.md)), with packets built by `tests/keys-send.py`. The NAT examples are tested in `nat`. |

### bpfcd, frontends and packaging

| Suite | What it checks |
| :--- | :--- |
| `bpfcd` | bpfcd and bpfcctl against a throwaway config tree: install, reload, change detection, templates (`%all%`, `%<kind>%`), exclusions, failures, external changes and adoption, checking the kernel with `tc` after each scenario. Creates veth pairs `bpfctA`/`bpfctB`. |
| `netns` | `bpfcd -n`, `bpfcctl -n` and the `-n` option of the bpfc-programs tools: namespaces by name, `netns_path` and `netns_veth`, and namespaces that appear late, move or are deleted. |
| `rest` | The REST API: socket ownership and permissions, every resource and method, `bpfc -T` checks, dry runs and rollbacks, `rest_dir` layering, reloads and restarts, a namespace instance, protocol errors and limits, and a short sanitizer fuzz run. Creates a temporary user and group. |
| `container` | `bpfcd-entrypoint` as PID 1 in a new PID and mount namespace, chrooted into a root filesystem with no systemd: only busybox plus `make install`. With `RPMS="bpfc-*.rpm bpfc-container-*.rpm"`, the image is built from packages instead. |
| `acl` | The Cisco IOS access-list frontend. Every kind of entry is sent packets that should and should not match, and the entry's own hit counter must show exactly the packets it matched: first match wins, and the implicit deny comes last. |
| `frontends` | The frontend mechanism, using a made-up type `upper`: bpfc runs the translator, and bpfcd handles such files like `.bpfc` ones (change detection through `depends`, conflicts, `on-failure`, meta lines, `bpfcctl show --source`). |

### Included programs

| Suite | What it checks |
| :--- | :--- |
| `dedup` | `dedup-iface.bpfc` and `dedup-global.bpfc` on `lo` in a new network and mount namespace, with crafted frames (`tests/dedup-send.py`), and `bpfc-dedup` reading the maps. |
| `flowmon` | The flow monitor on both hooks of `lo`. Crafted TCP segments (`tests/flowmon-send.py`) check how retransmissions, loss and reordering are classified, and `bpfc-flows` reads the maps. |
| `linkcap` | Per-neighbor loss and capacity, end to end: an Ethernet path, one through a rate-limited, lossy emulator (`tests/link-emulator.py`), and a point-to-point raw-IP path over tun devices. Multipoint GRE is only compiled. |
| `ecmp` | The bandwidth-aware ECMP layer on a router with three Ethernet members and a tunnel: the generator, flow placement per mode (l4, l3, l3+tos, l3-sym), fragments, that packets are forwarded as a router would forward them, load-based moves and policies, and `bpfc-ecmp-status`. |
| `dataplane` | The FEC / INT / ARQ dataplane between two namespaces over a Layer-2 link. Loss is added by a bpfc program ahead of the dataplane, and a middle namespace adds 400 ms each way for the satellite (`geo`) profile tests. `tests/udp-verify.py` checks that every delivered datagram arrives intact. |
| `dataplane-udp` | The dataplane's UDP carriers: `--carrier udp` through a router that NATs one site (carrier-grade NAT, the peer address learned), and `--carrier udp-inline` over a private routed WAN. |

## Tools the suites need

Every suite needs `bash`, iproute2 (`ip`, `tc`) and a built tree. A suite that's missing a tool it needs skips and names the tool in the summary. The exception is `dataplane`, which stops with an error.

| Tool (RHEL package) | Needed by |
| :--- | :--- |
| `python3` | acl, keys, flow-examples, xdp, xdp-examples, tc-examples, dedup, flowmon, linkcap, ecmp, rest, dataplane, dataplane-udp |
| `python3-scapy` | cve-2026-98432, pytest |
| `python3-pytest` | pytest |
| `tcpdump` | bpfc, nat, xdp, xdp-examples, tc-examples, pytest (optional in dataplane-udp, linkcap) |
| `nc` / `ncat` (nmap-ncat) | bpfc, nat, loops, xdp, xdp-examples, dataplane, dataplane-udp |
| `iperf` | frag, throttle |
| `iperf3` | dataplane |
| `ethtool` | frag, mpls, mpls-frag, throttle, xdp, xdp-examples, tc-examples, dataplane, dataplane-udp |
| `nft` (nftables) | dataplane-udp |
| `nstat` (iproute) | xdp-examples |
| `gawk` | ecmp |
| `curl` | rest |
| `unshare`, `nsenter`, `setpriv` (util-linux) | netns, container, dedup, flowmon, install |
| `busybox` | container |
| `rpmbuild` (rpm-build) | install (optional: the RPM checks) |
| kernel MPLS (`modprobe mpls_router mpls_iptunnel`) | mpls, mpls-xdp, mpls-frag |
| `gcovr` (`pip install gcovr`) | `make coverage` |
| `clang` or `gcc` with ASan/UBSan (libasan, libubsan) | `make fuzz`, and the short fuzz run in `rest` |

On RHEL 9/10, this installs most of them:

```bash
dnf install python3 python3-scapy python3-pytest tcpdump nmap-ncat iperf iperf3 ethtool nftables \
            gawk curl util-linux busybox rpm-build libasan libubsan
```

(Some of them, such as `python3-scapy` and `iperf`, come from EPEL.)

## Coverage

```bash
make coverage                                  # root; every suite, with the minimums
make coverage COVERAGE_SUITES="compile keys"   # only these suites; no minimum
make coverage COVERAGE_MIN_LINES=95            # a different minimum (percent)
```

`make coverage` builds `bpfc` with gcov, runs the suites against it, writes the report and then rebuilds the normal `bpfc`:

- `coverage/index.html`: a line-by-line report of `bpfc.c`
- `coverage/summary.txt`: line, function and branch totals
- `coverage/coverage.json`: a gcovr tracefile. Runs from other machines (say, a host with MPLS routing or `rpmbuild`) can be merged with `gcovr --add-tracefile a.json --add-tracefile b.json --html-details merged.html`.

It fails when a suite fails, or when a full run drops below `COVERAGE_MIN_LINES` or `COVERAGE_MIN_BRANCHES` (percent; the defaults are set in the Makefile). The minimums apply only to a full run, so with `COVERAGE_SUITES` they default to 0. It needs `gcovr` and, for most suites, root.

Coverage is measured for `bpfc.c` only for now; bpfcd and the frontends come later.

## Fuzzing

```bash
make fuzz                      # 200000 iterations
make fuzz FUZZ_ITERS=5000000
```

`make fuzz` builds `tests/fuzz-rest` with AddressSanitizer and UndefinedBehaviorSanitizer and feeds the REST API's HTTP and JSON parsers random and mutated input. It needs no root.

## Tuning and test hooks

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `TESTFLAGS` | | Runner flags for the `make check*` targets, e.g. `TESTFLAGS=-f` |
| `BUDGET_PCT` | 85 | `verifier-budget`: fail above this share of the verifier's 1,000,000-instruction limit |
| `STRESS_MAX_LOSS` | 100 | `frag`, `mpls-frag`: the most loss allowed under load, in hundredths of a percent (100 = 1 %) |
| `RPMS` | | `container`: build the test image from these RPMs instead of `make install` |
| `BPFC_TEST_NO_BUFFER_MAPS=1` | | Test hook for bpfc itself: `del-bytes` takes its unrolled fallback, as when its buffer map can't be created |

Some suites take their own flags when run directly. For example, `bash tests/test-bpfcd.sh -d -k` shows the daemon log on failure and keeps the temporary directory, and `bash tests/test-dataplane.sh -k` keeps its namespaces afterwards. The header comment of each `tests/test-*.sh` lists its flags and draws its topology.

## Writing a new suite

- Name it `tests/test-<suite>.sh`. The runner then finds it as `./test.sh <suite>`. Add it to `ALL` in `tests/run-tests.sh`, and to a `make check*` target if it belongs there.
- `source tests/lib.sh` for `test_pass`, `test_fail`, `test_skip`, `check <name> <command...>`, `require_root <suite>`, `require_cmds <suite> <command...>` and `tests_exit`.
- A result is any output line that ends in PASS, FAIL or SKIP. End the suite with `tests_exit`, so failures from checks run in the background (`&`) count too.
- Put a header comment at the top: what the suite tests, how to run it, what it needs, and its topology.
