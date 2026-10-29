VERSION   ?= 0.1.1
RELEASE   ?= 2

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
DOCDIR    ?= $(PREFIX)/share/doc/bpfc
CONTAINER_DOCDIR ?= $(PREFIX)/share/doc/bpfc-container
SYSCONFDIR ?= /etc
UNITDIR   ?= $(PREFIX)/lib/systemd/system
DESTDIR   ?=

TARGET     = bpfc
DAEMON     = bpfcd/bpfcd
CTL        = bpfcd/bpfcctl
COMMON_SRC = bpfcd/common.c
COMMON_HDR = bpfcd/common.h
DAEMON_CFLAGS = $(WARN) -Wno-format-truncation -DBPFC_VERSION='"$(VERSION)"'

# Everything that goes into the source tarball used by `make rpm`.
DIST_FILES = Makefile LICENSE README.md bpfc.8 bpfc.c test.sh tests \
             bpfcd/*.c bpfcd/*.h dist dataplane

RPMTOP     = $(CURDIR)/rpmbuild
RPMBUILD_OPTS ?=
TARBALL    = bpfc-$(VERSION).tar.gz

.PHONY: check-dataplane all clean install dist rpm srpm check

all: $(TARGET) $(DAEMON) $(CTL)

$(TARGET): bpfc.c
	$(CC) $(CFLAGS) $(WARN) $(FEATURES) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfc.c

$(DAEMON): bpfcd/bpfcd.c $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(DAEMON_CFLAGS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfcd/bpfcd.c $(COMMON_SRC)

$(CTL): bpfcd/bpfcctl.c $(COMMON_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS) $(DAEMON_CFLAGS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ bpfcd/bpfcctl.c $(COMMON_SRC)

install: all
	install -D -m 0755 $(TARGET) $(DESTDIR)$(SBINDIR)/bpfc
	install -D -m 0755 $(DAEMON) $(DESTDIR)$(SBINDIR)/bpfcd
	install -D -m 0755 $(CTL) $(DESTDIR)$(SBINDIR)/bpfcctl
	install -D -m 0644 bpfc.8 $(DESTDIR)$(MANDIR)/man8/bpfc.8
	install -D -m 0644 dist/bpfcd.8 $(DESTDIR)$(MANDIR)/man8/bpfcd.8
	install -D -m 0644 dist/bpfcctl.8 $(DESTDIR)$(MANDIR)/man8/bpfcctl.8
	install -D -m 0644 dist/bpfc.conf.5 $(DESTDIR)$(MANDIR)/man5/bpfc.conf.5
	install -D -m 0644 dist/bpfcd.service $(DESTDIR)$(UNITDIR)/bpfcd.service
	install -D -m 0644 dist/bpfc.conf $(DESTDIR)$(SYSCONFDIR)/bpfc/bpfc.conf
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/bpfc/interfaces.d
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/ingress
	install -d -m 0755 $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/egress
	install -m 0644 dist/examples/interfaces.d/eth0/ingress/*.bpfc $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/ingress/
	install -m 0644 dist/examples/interfaces.d/eth0/egress/*.bpfc $(DESTDIR)$(DOCDIR)/examples/interfaces.d/eth0/egress/
	install -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -D -m 0755 dist/container/bpfcd-entrypoint $(DESTDIR)$(SBINDIR)/bpfcd-entrypoint
	install -D -m 0644 dist/container/README.md $(DESTDIR)$(CONTAINER_DOCDIR)/README.md
	install -D -m 0644 dist/container/Containerfile $(DESTDIR)$(CONTAINER_DOCDIR)/Containerfile

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

# Integration test for bpfcd/bpfcctl (needs root; creates and deletes veth pairs).
check: all
	bash tests/test-bpfcd.sh
	bash tests/test-container.sh

check-dataplane: $(TARGET)
	bash tests/test-dataplane.sh

clean:
	rm -f $(TARGET) $(DAEMON) $(CTL) output.bpf $(TARBALL)
	rm -rf $(RPMTOP) .dist
