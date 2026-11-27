VERSION   ?= 0.1.1
RELEASE   ?= 7

CC        ?= gcc
CFLAGS    ?= -O2 -g
WARN       = -Wall -Wextra
# bpf_prog_info.verified_insns (kernel headers 5.16+, backported to RHEL 9)
FEATURES  := $(shell printf '#include <linux/bpf.h>\nint x = sizeof(((struct bpf_prog_info *)0)->verified_insns);\n' | \
               $(CC) -x c -c -o /dev/null - 2>/dev/null && echo -DBPFC_HAVE_VERIFIED_INSNS)
LDFLAGS   ?=
# STATIC=1 links the binaries statically, so they run regardless of the
# libc in the image (minimal or distroless containers). Kept separate from
# LDFLAGS because rpmbuild passes LDFLAGS on the command line.
STATIC    ?= 0
ifeq ($(STATIC),1)
STATIC_LDFLAGS = -static
endif

PREFIX    ?= /usr
SBINDIR   ?= $(PREFIX)/sbin
MANDIR    ?= $(PREFIX)/share/man
DATADIR   ?= $(PREFIX)/share
DOCDIR    ?= $(PREFIX)/share/doc/bpfc
CONTAINER_DOCDIR ?= $(PREFIX)/share/doc/bpfc-container
PROGRAMS_DOCDIR ?= $(PREFIX)/share/doc/bpfc-programs
SYSCONFDIR ?= /etc
UNITDIR   ?= $(PREFIX)/lib/systemd/system
LIBEXECDIR ?= $(PREFIX)/libexec
DESTDIR   ?=

TARGET     = bpfc
DAEMON     = bpfcd/bpfcd
CTL        = bpfcd/bpfcctl
# Frontends: programs that turn other file types (20.acl) into bpfc
FRONTENDS  = frontends/acl
COMMON_SRC = bpfcd/common.c bpfcd/netns.c bpfcd/json.c bpfcd/acl.c
COMMON_HDR = bpfcd/common.h bpfcd/netns.h bpfcd/json.h bpfcd/acl.h
# The REST API's HTTP server: bpfcd only.
HTTP_SRC   = bpfcd/http.c
HTTP_HDR   = bpfcd/http.h
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
LOCALSTATEDIR ?= /var/lib
DAEMON_CFLAGS = $(WARN) -Wno-format-truncation -DBPFC_VERSION='"$(VERSION)"'

# Everything that goes into the source tarball used by `make rpm`.
DIST_FILES = Makefile LICENSE README.md INSTALL.md TESTING.md bpfc.8 bpfc.c test.sh tests doc \
             bpfcd/*.c bpfcd/*.h dist programs frontends/*.c

RPMTOP     = $(CURDIR)/rpmbuild
RPMBUILD_OPTS ?=
TARBALL    = bpfc-$(VERSION).tar.gz

.PHONY: coverage fuzz check-compile check-dataplane check-ecmp check-linkcap check-all all clean install install-core install-container install-programs dist rpm srpm deb apk arch openwrt-feed check

all: $(TARGET) $(DAEMON) $(CTL) $(FRONTENDS)

frontends/acl: frontends/acl.c
	$(CC) $(CFLAGS) $(WARN) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ frontends/acl.c

$(TARGET): bpfc.c
	$(CC) $(CFLAGS) $(WARN) $(FEATURES) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfc.c

$(DAEMON): bpfcd/bpfcd.c $(COMMON_SRC) $(COMMON_HDR) $(HTTP_SRC) $(HTTP_HDR)
	$(CC) $(CFLAGS) $(DAEMON_CFLAGS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfcd/bpfcd.c $(COMMON_SRC) $(HTTP_SRC)

$(CTL): bpfcd/bpfcctl.c $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(DAEMON_CFLAGS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfcd/bpfcctl.c $(COMMON_SRC)

# install = install-core (the bpfc package) + install-container
# (bpfc-container) + install-programs (bpfc-programs), so packaging can
# install each package's files on their own (debian/rules does).
install: install-core install-container install-programs

install-core: all
	install -D -m 0755 $(TARGET) $(DESTDIR)$(SBINDIR)/bpfc
	install -D -m 0755 $(DAEMON) $(DESTDIR)$(SBINDIR)/bpfcd
	install -D -m 0755 $(CTL) $(DESTDIR)$(SBINDIR)/bpfcctl
	install -D -m 0755 frontends/acl $(DESTDIR)$(LIBEXECDIR)/bpfc/frontends/acl
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/frontends
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/acl.d
	install -D -m 0644 bpfc.8 $(DESTDIR)$(MANDIR)/man8/bpfc.8
	install -D -m 0644 dist/bpfcd.8 $(DESTDIR)$(MANDIR)/man8/bpfcd.8
	install -D -m 0644 dist/bpfcctl.8 $(DESTDIR)$(MANDIR)/man8/bpfcctl.8
	install -D -m 0644 dist/bpfc.conf.5 $(DESTDIR)$(MANDIR)/man5/bpfc.conf.5
	install -D -m 0644 dist/bpfcd.service $(DESTDIR)$(UNITDIR)/bpfcd.service
	install -D -m 0644 dist/bpfcd-netns@.service $(DESTDIR)$(UNITDIR)/bpfcd-netns@.service
	install -D -m 0644 dist/bpfc.conf $(DESTDIR)$(SYSCONFDIR)/bpfc/bpfc.conf
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/interfaces.d
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/netns
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/include
	install -d -m 0755 $(DESTDIR)$(LOCALSTATEDIR)/bpfc/interfaces.d
	install -d -m 0755 $(DESTDIR)$(LOCALSTATEDIR)/bpfc/netns
	install -D -m 0644 dist/bpfc.sysusers $(DESTDIR)$(SYSUSERSDIR)/bpfc.conf
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/ingress
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/egress
	install -m 0644 dist/examples/interfaces.d/eth0/ingress/*.bpfc $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/ingress/
	install -m 0644 dist/examples/interfaces.d/eth0/egress/*.bpfc $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/egress/
	install -m 0644 dist/examples/cve-2026-98432.bpfc $(DESTDIR)$(DOCDIR)/examples/
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/xdp
	install -m 0644 dist/examples/xdp/*.bpfc $(DESTDIR)$(DOCDIR)/examples/xdp/
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/tc
	install -m 0644 dist/examples/tc/*.bpfc $(DESTDIR)$(DOCDIR)/examples/tc/
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/flow
	install -m 0644 dist/examples/flow/*.bpfc $(DESTDIR)$(DOCDIR)/examples/flow/
	install -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -m 0644 doc/flow-tracking.md $(DESTDIR)$(DOCDIR)/flow-tracking.md
	install -m 0644 doc/firewall.md $(DESTDIR)$(DOCDIR)/firewall.md
	install -m 0644 doc/language.md $(DESTDIR)$(DOCDIR)/language.md
	install -m 0644 INSTALL.md TESTING.md $(DESTDIR)$(DOCDIR)/
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/acl/acl.d
	install -m 0644 dist/examples/acl/*.acl $(DESTDIR)$(DOCDIR)/examples/acl/
	install -m 0644 dist/examples/acl/acl.d/*.acl $(DESTDIR)$(DOCDIR)/examples/acl/acl.d/

install-container:
	install -D -m 0755 dist/container/bpfcd-entrypoint $(DESTDIR)$(SBINDIR)/bpfcd-entrypoint
	install -D -m 0644 dist/container/README.md $(DESTDIR)$(CONTAINER_DOCDIR)/README.md
	install -D -m 0644 dist/container/Containerfile $(DESTDIR)$(CONTAINER_DOCDIR)/Containerfile

# The bpfc-programs package: everything under programs/, one subfolder per
# program, picked up by what it contains (nothing to list here or in the
# spec when a program is added):
#   programs/<name>/<executable file>    -> SBINDIR
#   programs/<name>/profiles/*.profile   -> DATADIR/bpfc/<name>/profiles, and
#                                           SYSCONFDIR/bpfc/<name>/profiles.d
#                                           is created for local profiles
#   programs/<name>/*.md                 -> PROGRAMS_DOCDIR/<name>/
#   programs/<name>/examples/            -> PROGRAMS_DOCDIR/<name>/examples/
#   programs/<name>/include/*.bpfc       -> SYSCONFDIR/bpfc/include/ (bpfc's
#                                           include path; config files)
# A tool that names /usr/share/bpfc/<name>/ is told where DATADIR put it.
# PROGRAMS_FILELIST, when set, receives the RPM %files entries for what was
# installed outside DATADIR/bpfc and PROGRAMS_DOCDIR (the spec uses it).
PROGRAMS_FILELIST ?=

install-programs:
	@set -e; \
	list='$(PROGRAMS_FILELIST)'; [ -z "$$list" ] || : > "$$list"; \
	install -d -m 0755 $(DESTDIR)$(SBINDIR) $(DESTDIR)$(DATADIR)/bpfc $(DESTDIR)$(PROGRAMS_DOCDIR); \
	for dir in programs/*/; do \
		[ -d "$$dir" ] || continue; \
		dir=$${dir%/}; name=$${dir#programs/}; \
		for f in "$$dir"/*; do \
			[ -f "$$f" ] || continue; \
			case $$f in \
			*.md) install -D -m 0644 "$$f" "$(DESTDIR)$(PROGRAMS_DOCDIR)/$$name/$${f##*/}"; continue ;; \
			esac; \
			[ -x "$$f" ] || continue; \
			dst="$(DESTDIR)$(SBINDIR)/$${f##*/}"; \
			if [ '$(DATADIR)' != /usr/share ] && grep -q "/usr/share/bpfc/$$name/" "$$f"; then \
				sed "s,/usr/share/bpfc/$$name/,$(DATADIR)/bpfc/$$name/,g" "$$f" > "$$dst"; \
				chmod 0755 "$$dst"; \
			else \
				install -m 0755 "$$f" "$$dst"; \
			fi; \
			[ -z "$$list" ] || echo "$(SBINDIR)/$${f##*/}" >> "$$list"; \
		done; \
		if ls "$$dir"/profiles/*.profile >/dev/null 2>&1; then \
			install -d -m 0755 "$(DESTDIR)$(DATADIR)/bpfc/$$name/profiles" "$(DESTDIR)$(SYSCONFDIR)/bpfc/$$name/profiles.d"; \
			install -m 0644 "$$dir"/profiles/*.profile "$(DESTDIR)$(DATADIR)/bpfc/$$name/profiles/"; \
			[ -z "$$list" ] || printf '%%dir %s\n' "$(SYSCONFDIR)/bpfc/$$name" "$(SYSCONFDIR)/bpfc/$$name/profiles.d" >> "$$list"; \
		fi; \
		for f in "$$dir"/include/*.bpfc; do \
			[ -f "$$f" ] || continue; \
			install -D -m 0644 "$$f" "$(DESTDIR)$(SYSCONFDIR)/bpfc/include/$${f##*/}"; \
			[ -z "$$list" ] || echo "%config(noreplace) $(SYSCONFDIR)/bpfc/include/$${f##*/}" >> "$$list"; \
		done; \
		if [ -d "$$dir/examples" ]; then \
			(cd "$$dir" && find examples -type f) | while IFS= read -r f; do \
				install -D -m 0644 "$$dir/$$f" "$(DESTDIR)$(PROGRAMS_DOCDIR)/$$name/$$f"; \
			done; \
		fi; \
	done

dist: $(TARBALL)

# Always rebuilt so the tarball never lags behind the sources.
.PHONY: $(TARBALL)
$(TARBALL):
	tar -czf $@ --owner=0 --group=0 --sort=name \
	    --transform 's,^,bpfc-$(VERSION)/,' $(DIST_FILES)

# Builds binary and source RPMs into ./rpmbuild (RHEL 9/10: dnf install rpm-build gcc make systemd-rpm-macros).
rpm: $(TARBALL)
	@command -v rpmbuild >/dev/null || { echo "rpmbuild not found: dnf install rpm-build"; exit 1; }
	mkdir -p $(RPMTOP)/SOURCES $(RPMTOP)/SPECS
	cp $(TARBALL) $(RPMTOP)/SOURCES/
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@RELEASE@/$(RELEASE)/g' dist/bpfc.spec.in > $(RPMTOP)/SPECS/bpfc.spec
	rpmbuild $(RPMBUILD_OPTS) --define "_topdir $(RPMTOP)" -ba $(RPMTOP)/SPECS/bpfc.spec
	@echo; echo "RPMs:"; find $(RPMTOP)/RPMS $(RPMTOP)/SRPMS -name '*.rpm' -printf '  %p\n'

srpm: $(TARBALL)
	mkdir -p $(RPMTOP)/SOURCES $(RPMTOP)/SPECS
	cp $(TARBALL) $(RPMTOP)/SOURCES/
	sed -e 's/@VERSION@/$(VERSION)/g' -e 's/@RELEASE@/$(RELEASE)/g' dist/bpfc.spec.in > $(RPMTOP)/SPECS/bpfc.spec
	rpmbuild $(RPMBUILD_OPTS) --define "_topdir $(RPMTOP)" -bs $(RPMTOP)/SPECS/bpfc.spec

# Builds .deb packages, and the source package, into ./debbuild (Debian 12+,
# Ubuntu 22.04+: apt install build-essential debhelper pkgconf systemd-dev,
# or systemd in place of systemd-dev before Debian 13). The upstream version
# in debian/changelog must be $(VERSION).
#   DEBBUILD_OPTS=-b                      binary packages only
#   DEB_BUILD_PROFILES=pkg.bpfc.static    statically linked binaries
#   DEB_BUILD_OPTIONS=nocheck             skip the compile tests
DEBTOP     = $(CURDIR)/debbuild
DEBBUILD_OPTS ?=
deb: $(TARBALL)
	@command -v dpkg-buildpackage >/dev/null || { echo "dpkg-buildpackage not found: apt install dpkg-dev debhelper"; exit 1; }
	@v=$$(dpkg-parsechangelog -l debian/changelog -S Version | sed 's/-[^-]*$$//'); \
	[ "$$v" = "$(VERSION)" ] || { echo "debian/changelog is at $$v, the Makefile at $(VERSION): add an entry (dch -v $(VERSION)-1)"; exit 1; }
	rm -rf $(DEBTOP) && mkdir -p $(DEBTOP)
	cp $(TARBALL) $(DEBTOP)/bpfc_$(VERSION).orig.tar.gz
	tar -xzf $(TARBALL) -C $(DEBTOP)
	cp -r debian $(DEBTOP)/bpfc-$(VERSION)/
	# Without this make's variables: DEBTOP=... given here would reach the
	# package's own `make clean` and delete the build directory.
	cd $(DEBTOP)/bpfc-$(VERSION) && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL dpkg-buildpackage -us -uc $(DEBBUILD_OPTS)
	@echo; echo "Packages:"; find $(DEBTOP) -maxdepth 1 -name '*.deb' -printf '  %p\n'

# Building in a container (make apk, make arch): the build's files are handed
# back to the user who ran make, also when the build fails. With podman the
# container's root is that user (rootless) or root (sudo), so 0:0 is right.
CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
CONTAINER_OWNER = $(if $(findstring podman,$(CONTAINER_ENGINE)),0:0,$(shell id -u):$(shell id -g))

# Alpine packages (.apk) into ./apkbuild/packages, with abuild: on Alpine
# itself (apk add alpine-sdk linux-headers bash coreutils; a user in the
# abuild group with a key from abuild-keygen -a), or anywhere else in an
# $(ALPINE_IMAGE) container run with podman or docker. The container signs
# with APK_KEY, or else a throwaway key; the public key is copied next to
# the packages (apk add --allow-untrusted for a throwaway one).
#   APK_KEY=dir/name.rsa  sign with this abuild key (dir/name.rsa.pub next to it)
#   APK_STATIC=1          statically linked binaries (musl)
#   ALPINE_IMAGE=...      another Alpine release
APKTOP     = $(CURDIR)/apkbuild
ALPINE_IMAGE ?= docker.io/library/alpine:3.22
APK_STATIC ?= 0
APK_KEY    ?=
ifneq ($(APK_KEY),)
APK_KEY_MOUNT = -v $(abspath $(dir $(APK_KEY))):/keys:ro,Z
APK_KEY_SETUP = mkdir -p /root/.abuild && cp /keys/$(notdir $(APK_KEY)) /keys/$(notdir $(APK_KEY)).pub /root/.abuild/ && \
	cp /keys/$(notdir $(APK_KEY)).pub /etc/apk/keys/ && \
	echo PACKAGER_PRIVKEY=/root/.abuild/$(notdir $(APK_KEY)) > /root/.abuild/abuild.conf
else
# Not abuild-keygen -i: that copies the key with doas or sudo, even as root,
# and the alpine image has neither.
APK_KEY_SETUP = abuild-keygen -a -n -q && mkdir -p /etc/apk/keys && cp /root/.abuild/*.rsa.pub /etc/apk/keys/
endif
apk: $(TARBALL)
	rm -rf $(APKTOP) && mkdir -p $(APKTOP)/src $(APKTOP)/packages
	sed -e 's/@VERSION@/$(VERSION)/g' dist/alpine/APKBUILD.in > $(APKTOP)/src/APKBUILD
	cp $(TARBALL) dist/alpine/bpfcd.initd dist/alpine/bpfcd.confd dist/alpine/bpfc.pre-install $(APKTOP)/src/
	cd $(APKTOP)/src && printf 'sha512sums="\n%s\n"\n' "$$(sha512sum $(TARBALL) bpfcd.initd bpfcd.confd)" >> APKBUILD
	@if command -v abuild >/dev/null; then \
		cd $(APKTOP)/src && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL BPFC_STATIC=$(APK_STATIC) REPODEST=$(APKTOP)/packages abuild -r; \
	elif [ -n "$(CONTAINER_ENGINE)" ]; then \
		$(CONTAINER_ENGINE) run --rm -v $(APKTOP):/work:Z $(APK_KEY_MOUNT) -e BPFC_STATIC=$(APK_STATIC) $(ALPINE_IMAGE) sh -euc '\
			trap "chown -R $(CONTAINER_OWNER) /work" EXIT; \
			export ABUILD_USERDIR=/root/.abuild; \
			apk add -q alpine-sdk linux-headers bash coreutils; \
			$(APK_KEY_SETUP); \
			cd /work/src && REPODEST=/work/packages abuild -F -r; \
			cp /root/.abuild/*.rsa.pub /work/packages/'; \
	else \
		echo "neither abuild nor podman/docker found: run make apk on Alpine, or install podman"; exit 1; \
	fi
	@echo; echo "Packages:"; find $(APKTOP)/packages -name '*.apk' -printf '  %p\n'

# Arch Linux packages (.pkg.tar.zst) into ./archbuild, with makepkg: on Arch
# itself (pacman -S base-devel linux-api-headers; not as root), or anywhere
# else in an $(ARCH_IMAGE) container run with podman or docker.
#   ARCH_STATIC=1    statically linked binaries
#   MAKEPKG_OPTS=... more makepkg options (--nocheck, ...)
ARCHTOP    = $(CURDIR)/archbuild
ARCH_IMAGE ?= docker.io/library/archlinux:base-devel
ARCH_STATIC ?= 0
MAKEPKG_OPTS ?=
arch: $(TARBALL)
	rm -rf $(ARCHTOP) && mkdir -p $(ARCHTOP)
	cp $(TARBALL) $(ARCHTOP)/
	backup=$$(for f in programs/*/include/*.bpfc; do [ -f "$$f" ] && printf "'etc/bpfc/include/%s' " "$${f##*/}"; done); \
	sed -e 's/@VERSION@/$(VERSION)/g' -e "s|@PROGRAMS_BACKUP@|$${backup% }|" \
	    -e "s/@SHA256@/'$$(sha256sum $(TARBALL) | cut -d' ' -f1)'/" dist/arch/PKGBUILD.in > $(ARCHTOP)/PKGBUILD
	@if command -v makepkg >/dev/null && [ "$$(id -u)" -ne 0 ]; then \
		cd $(ARCHTOP) && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL BPFC_STATIC=$(ARCH_STATIC) makepkg -f $(MAKEPKG_OPTS); \
	elif [ -n "$(CONTAINER_ENGINE)" ]; then \
		$(CONTAINER_ENGINE) run --rm -v $(ARCHTOP):/work:Z -e BPFC_STATIC=$(ARCH_STATIC) $(ARCH_IMAGE) bash -euc '\
			trap "chown -R $(CONTAINER_OWNER) /work" EXIT; \
			pacman -Syu --noconfirm --needed linux-api-headers >/dev/null; \
			useradd -m build && chown -R build /work; \
			su build -c "cd /work && BPFC_STATIC=$(ARCH_STATIC) makepkg -f $(MAKEPKG_OPTS)"'; \
	else \
		echo "makepkg (not as root) or podman/docker needed: run make arch on Arch as a user, or install podman"; exit 1; \
	fi
	@echo; echo "Packages:"; find $(ARCHTOP) -maxdepth 1 -name '*.pkg.tar*' -printf '  %p\n'

# A self-contained OpenWrt feed in ./openwrt-feed: dist/openwrt/bpfc with the
# source tarball unpacked into its src/ folder, for builds that only see the
# feed (the openwrt/gh-action-sdk action, a copy on another machine).
#   ./scripts/feeds: src-link bpfc $(CURDIR)/openwrt-feed
FEEDTOP    = $(CURDIR)/openwrt-feed
openwrt-feed: $(TARBALL)
	rm -rf $(FEEDTOP) && mkdir -p $(FEEDTOP)
	cp -r dist/openwrt/bpfc $(FEEDTOP)/
	mkdir -p $(FEEDTOP)/bpfc/src
	tar -xzf $(TARBALL) -C $(FEEDTOP)/bpfc/src --strip-components=1 --exclude='*/dist/openwrt'
	@echo "Feed: $(FEEDTOP) (package bpfc)"

# Integration test for bpfcd/bpfcctl (needs root; creates and deletes veth pairs).
# Test suites via tests/run-tests.sh, which totals pass/fail/skip at the end.
# TESTFLAGS=-f prints failures only; -v prints full suite output.
TESTFLAGS ?=

check: all
	bash tests/run-tests.sh $(TESTFLAGS) compile preprocessor stack keys bpfcd netns rest xdp xdp-examples tc-examples flow-examples acl frontends dedup portscan ecmp container install

# Compile-only checks of every field and command and of the error messages;
# needs no root (the few commands that create maps are skipped without it).
check-compile: $(TARGET)
	bash tests/run-tests.sh $(TESTFLAGS) compile

check-ecmp: $(TARGET)
	bash tests/run-tests.sh $(TESTFLAGS) ecmp

check-linkcap: $(TARGET)
	bash tests/run-tests.sh $(TESTFLAGS) linkcap

check-dataplane: $(TARGET)
	bash tests/run-tests.sh $(TESTFLAGS) verifier-budget dataplane dataplane-udp

# Every suite, including the network suites and pytest (root; about an hour).
check-all: all
	bash tests/run-tests.sh $(TESTFLAGS)

# bpfc.c's test coverage: a gcov build of bpfc, the suites (all, or
# COVERAGE_SUITES), a report in coverage/ (index.html, summary.txt,
# coverage.json), then the normal bpfc again. Fails when a suite fails or
# coverage drops below the minimums, which apply to a full run only (as
# root; 97.4 % lines, 81.8 % branches measured on a 6.18 kernel).
# Needs gcovr (pip install gcovr) and, for most suites, root.
COVERAGE_SUITES ?=
COVERAGE_MIN_LINES ?= $(if $(COVERAGE_SUITES),0,97)
COVERAGE_MIN_BRANCHES ?= $(if $(COVERAGE_SUITES),0,81)
coverage: $(DAEMON) $(CTL) $(FRONTENDS)
	rm -rf coverage $(TARGET)
	mkdir -p coverage && chmod 1777 coverage
	$(CC) -O0 -g --coverage $(WARN) $(FEATURES) -c -o coverage/bpfc.o bpfc.c
	$(CC) --coverage $(LDFLAGS) -o $(TARGET) coverage/bpfc.o
	COVERAGE_SUITES='$(COVERAGE_SUITES)' COVERAGE_MIN_LINES='$(COVERAGE_MIN_LINES)' \
	COVERAGE_MIN_BRANCHES='$(COVERAGE_MIN_BRANCHES)' TESTFLAGS='$(TESTFLAGS)' bash tests/coverage.sh

# Feeds the HTTP and JSON parsers random and mutated input under ASan/UBSan.
FUZZ_ITERS ?= 200000
fuzz:
	$(CC) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all $(DAEMON_CFLAGS) -Ibpfcd \
	    -o tests/fuzz-rest tests/fuzz-rest.c bpfcd/http.c bpfcd/json.c bpfcd/common.c
	./tests/fuzz-rest $(FUZZ_ITERS)

clean:
	rm -f $(TARGET) $(DAEMON) $(CTL) $(FRONTENDS) output.bpf $(TARBALL) tests/fuzz-rest
	rm -rf $(RPMTOP) $(DEBTOP) $(APKTOP) $(ARCHTOP) $(FEEDTOP) .dist coverage
