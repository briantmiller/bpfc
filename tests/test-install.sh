#!/bin/bash
#
# test-install.sh - what `make install` and the RPM put where.
#
# Installs into a scratch DESTDIR and checks the binaries, the dataplane
# generator and status tool, every built-in profile, and the docs. As root,
# the installed generator is run with a mount namespace that puts the
# scratch /usr/share in place, so its default profile path is what gets
# tested. When rpmbuild is installed, `make rpm` is built and the file lists
# of bpfc and bpfc-scripts checked too (on a system whose rpm database doesn't list the build
# dependencies, such as Debian or Ubuntu, with --nodeps).
#
#   INSTALL_RPM=0   skip the RPM build

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh

T=$(mktemp -d)
cleanup() { rm -rf "$T"; rm -f "$TESTS_FAILED_FILE"; }
trap cleanup EXIT
R=$T/root

make -s all >/dev/null 2>&1 || { test_fail "build"; tests_exit; }
if ! make -s install DESTDIR="$R" > "$T/install.log" 2>&1; then
	test_fail "make install"; sed 's/^/    /' "$T/install.log"; tests_exit
fi

for f in bpfc bpfcd bpfcctl bpfcd-entrypoint bpfc-dataplane-gen bpfc-dataplane-status; do
	check "installed /usr/sbin/$f, executable" test -x "$R/usr/sbin/$f"
done
missing=
for p in dataplane/profiles/*.profile; do
	[ -f "$R/usr/share/bpfc/dataplane/profiles/$(basename "$p")" ] || missing="$missing $(basename "$p")"
done
check "every built-in profile installed in /usr/share/bpfc/dataplane/profiles${missing:+ (missing:$missing)}" [ -z "$missing" ]
check "local profile directory /etc/bpfc/dataplane/profiles.d" test -d "$R/etc/bpfc/dataplane/profiles.d"
check "XDP examples in the bpfc docs" eval \
	'test -f "$R/usr/share/doc/bpfc/examples/xdp/router.bpfc" && test -f "$R/usr/share/doc/bpfc/examples/xdp/ip-lib.bpfc"'
check "dataplane DESIGN.md and examples in the bpfc-scripts docs" eval \
	'test -f "$R/usr/share/doc/bpfc-scripts/dataplane/DESIGN.md" && ls "$R"/usr/share/doc/bpfc-scripts/dataplane/examples/interfaces.d/eth0/ingress/*.bpfc >/dev/null'
check "installed generator is the source one (default DATADIR)" cmp -s dataplane/bpfc-dataplane-gen "$R/usr/sbin/bpfc-dataplane-gen"
check "installed generator lists the profiles from the installed directory" eval \
	'"$R/usr/sbin/bpfc-dataplane-gen" --profile-dir "$R/usr/share/bpfc/dataplane/profiles" --list-profiles | grep -q "^leo "'

# Another DATADIR: the generator is told where its profiles went.
make -s install DESTDIR="$T/alt" PREFIX=/opt/bpfc >/dev/null 2>&1
check "DATADIR=/opt/bpfc/share: generator looks there" \
	grep -q '^PROFILE_DIRS=(.* /opt/bpfc/share/bpfc/dataplane/profiles ' "$T/alt/opt/bpfc/sbin/bpfc-dataplane-gen"

# The default path, for real: the scratch /usr/share mounted over the host's.
if [ "$(id -u)" -eq 0 ] && command -v unshare >/dev/null; then
	mkdir -p "$T/out"
	if unshare -m sh -c "mount --bind '$R/usr/share' /usr/share && \
	    '$R/usr/sbin/bpfc-dataplane-gen' --list-profiles > '$T/list' && \
	    '$R/usr/sbin/bpfc-dataplane-gen' -i lo -o '$T/out' --profile leo > /dev/null" 2> "$T/ns.err"; then
		check "installed generator finds the built-in profiles by default" eval \
			'[ "$(grep -c /usr/share/bpfc/dataplane/profiles/ "$T/list")" -eq "$(ls dataplane/profiles/*.profile | wc -l)" ]'
		check "installed generator writes a leo dataplane" eval \
			'grep -q "profile=leo" "$T/out/lo/egress/100.bpfc" && ls "$T"/out/lo/ingress/*.bpfc | wc -l | grep -qx 4'
	else
		test_fail "installed generator in a mount namespace"; sed 's/^/    /' "$T/ns.err"
	fi
else
	test_skip "installed generator with its default profile path (needs root and unshare)"
fi

# The RPM.
if [ "${INSTALL_RPM:-1}" = 0 ]; then
	test_skip "RPM contents (INSTALL_RPM=0)"
elif ! command -v rpmbuild >/dev/null; then
	test_skip "RPM contents (no rpmbuild: dnf install rpm-build)"
else
	opts=
	rpm -q rpm >/dev/null 2>&1 || opts=--nodeps   # rpm db doesn't know the host's packages
	had_tarball=; ls bpfc-*.tar.gz >/dev/null 2>&1 && had_tarball=1
	if make -s rpm RPMTOP="$T/rpmbuild" RPMBUILD_OPTS="$opts --quiet" > "$T/rpm.log" 2>&1; then
		rpmf=$(find "$T/rpmbuild/RPMS" -name 'bpfc-[0-9]*.rpm' | head -1)
		srpmf=$(find "$T/rpmbuild/RPMS" -name 'bpfc-scripts-[0-9]*.noarch.rpm' | head -1)
		rpm -qlp "$rpmf" > "$T/core" 2>/dev/null
		rpm -qlp "$srpmf" > "$T/files" 2>/dev/null
		rpm -qRp "$srpmf" > "$T/requires" 2>/dev/null
		check "bpfc-scripts is a noarch package" test -n "$srpmf"
		for f in /usr/sbin/bpfc-dataplane-gen /usr/sbin/bpfc-dataplane-status \
		         /etc/bpfc/dataplane/profiles.d /usr/share/doc/bpfc-scripts/dataplane/DESIGN.md; do
			check "bpfc-scripts has $f" grep -qx "$f" "$T/files"
		done
		check "bpfc itself has no dataplane files" eval '! grep -q dataplane "$T/core"'
		check "bpfc itself has the binaries" eval 'grep -qx /usr/sbin/bpfc "$T/core" && grep -qx /usr/sbin/bpfcd "$T/core"'
		missing=
		for p in dataplane/profiles/*.profile; do
			grep -qx "/usr/share/bpfc/dataplane/profiles/$(basename "$p")" "$T/files" || missing="$missing $(basename "$p")"
		done
		check "bpfc-scripts has every built-in profile${missing:+ (missing:$missing)}" [ -z "$missing" ]
		check "bpfc-scripts requires bpfc of the same build, bash and gawk" eval \
			'grep -qx "bpfc = $(rpm -qp --qf "%{VERSION}-%{RELEASE}" "$rpmf")" "$T/requires" && grep -qx bash "$T/requires" && grep -qx gawk "$T/requires"'
	else
		test_fail "make rpm"; tail -20 "$T/rpm.log" | sed 's/^/    /'
	fi
	[ -n "$had_tarball" ] || rm -f bpfc-*.tar.gz
fi

tests_exit
