#!/bin/bash
#
# test-install.sh - what `make install` and the RPM put where.
#
# Installs into a scratch DESTDIR and checks the binaries, the docs and
# everything under programs/ (each program's executables, profiles, design
# notes and examples, found the same way the Makefile finds them). As root,
# the installed generator is run with a mount namespace that puts the
# scratch /usr/share in place, so its default profile path is what gets
# tested. When rpmbuild is installed, `make rpm` is built and the file lists
# of bpfc and bpfc-programs checked too (on a system whose rpm database doesn't list the build
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

for f in bpfc bpfcd bpfcctl bpfcd-entrypoint; do
	check "installed /usr/sbin/$f, executable" test -x "$R/usr/sbin/$f"
done

# What programs/ holds, by the Makefile's rules: executables, profiles,
# *.md and examples/ of each programs/<name>/.
PROGRAMS=; PROG_TOOLS=; PROG_PROFILES=; PROG_DOCS=
for d in programs/*/; do
	d=${d%/}; n=${d#programs/}; PROGRAMS="$PROGRAMS $n"
	for f in "$d"/*; do
		[ -f "$f" ] || continue
		case $f in *.md) PROG_DOCS="$PROG_DOCS $n/${f##*/}"; continue ;; esac
		[ -x "$f" ] && PROG_TOOLS="$PROG_TOOLS ${f##*/}"
	done
	for f in "$d"/profiles/*.profile; do
		[ -f "$f" ] && PROG_PROFILES="$PROG_PROFILES $n/profiles/${f##*/}"
	done
done
for n in dataplane ecmp flowmon; do
	check "programs/$n is there" test -d "programs/$n"
done
for f in bpfc-dataplane-gen bpfc-dataplane-status bpfc-ecmp-gen bpfc-ecmp-status bpfc-flows; do
	check "programs/ has the tool $f" eval 'case " $PROG_TOOLS " in *" $f "*) true ;; *) false ;; esac'
done
for f in $PROG_TOOLS; do
	check "installed /usr/sbin/$f, executable" test -x "$R/usr/sbin/$f"
done
for n in $PROGRAMS; do
	ls "programs/$n"/profiles/*.profile >/dev/null 2>&1 || continue
	missing=
	for p in "programs/$n"/profiles/*.profile; do
		[ -f "$R/usr/share/bpfc/$n/profiles/$(basename "$p")" ] || missing="$missing $(basename "$p")"
	done
	check "every built-in profile installed in /usr/share/bpfc/$n/profiles${missing:+ (missing:$missing)}" [ -z "$missing" ]
	check "local profile directory /etc/bpfc/$n/profiles.d" test -d "$R/etc/bpfc/$n/profiles.d"
done
for f in $PROG_DOCS; do
	check "$f in the bpfc-programs docs" test -f "$R/usr/share/doc/bpfc-programs/$f"
done
for n in $PROGRAMS; do
	[ -d "programs/$n/examples" ] || continue
	check "programs/$n/examples in the bpfc-programs docs, complete" eval \
		'[ "$(cd "programs/$n" && find examples -type f | sort)" = "$(cd "$R/usr/share/doc/bpfc-programs/$n" && find examples -type f | sort)" ]'
done

# A program added to programs/ is installed without touching the Makefile.
mkdir -p "$T/src" && tar -cf - --exclude=rpmbuild --exclude='bpfc-*.tar.gz' . | tar -xf - -C "$T/src"
mkdir -p "$T/src/programs/zz-new/profiles" "$T/src/programs/zz-new/examples/interfaces.d/eth0/ingress"
printf '#!/bin/bash\nPROFILES=/usr/share/bpfc/zz-new/profiles\n' > "$T/src/programs/zz-new/bpfc-zz-new"
chmod 0755 "$T/src/programs/zz-new/bpfc-zz-new"
echo "not a tool" > "$T/src/programs/zz-new/notes.txt"
echo "# zz-new" > "$T/src/programs/zz-new/DESIGN.md"
echo "x" > "$T/src/programs/zz-new/profiles/one.profile"
echo "pass" > "$T/src/programs/zz-new/examples/interfaces.d/eth0/ingress/10.bpfc"
make -s -C "$T/src" install-programs DESTDIR="$T/new" PROGRAMS_FILELIST="$T/new.files" > "$T/new.log" 2>&1
N=$T/new
check "new program: its tool is installed, other files are not" eval \
	'test -x "$N/usr/sbin/bpfc-zz-new" && cmp -s "$T/src/programs/zz-new/bpfc-zz-new" "$N/usr/sbin/bpfc-zz-new" && ! test -e "$N/usr/sbin/notes.txt"'
check "new program: profile, profiles.d, DESIGN.md and example installed" eval \
	'test -f "$N/usr/share/bpfc/zz-new/profiles/one.profile" && test -d "$N/etc/bpfc/zz-new/profiles.d" &&
	 test -f "$N/usr/share/doc/bpfc-programs/zz-new/DESIGN.md" &&
	 test -f "$N/usr/share/doc/bpfc-programs/zz-new/examples/interfaces.d/eth0/ingress/10.bpfc"'
check "new program: in the RPM file list" eval \
	'grep -qx /usr/sbin/bpfc-zz-new "$T/new.files" && grep -qx "%dir /etc/bpfc/zz-new/profiles.d" "$T/new.files"'
check "RPM file list: every tool, and no profiles.d for a program without profiles" eval \
	'for f in $PROG_TOOLS; do grep -qx "/usr/sbin/$f" "$T/new.files" || exit 1; done; ! grep -q flowmon "$T/new.files"'
make -s -C "$T/src" install-programs DESTDIR="$T/new-alt" PREFIX=/opt/bpfc >/dev/null 2>&1
check "new program: told where DATADIR put its files" \
	grep -qx 'PROFILES=/opt/bpfc/share/bpfc/zz-new/profiles' "$T/new-alt/opt/bpfc/sbin/bpfc-zz-new"

check "REST program directories /var/lib/bpfc/interfaces.d and netns" eval \
	'test -d "$R/var/lib/bpfc/interfaces.d" && test -d "$R/var/lib/bpfc/netns"'
check "sysusers.d declares the bpfc group" grep -q '^g bpfc' "$R/usr/lib/sysusers.d/bpfc.conf"
check "XDP and TC examples in the bpfc docs" eval \
	'test -f "$R/usr/share/doc/bpfc/examples/xdp/router.bpfc" && test -f "$R/usr/share/doc/bpfc/examples/xdp/ip-lib.bpfc" && test -f "$R/usr/share/doc/bpfc/examples/tc/policer.bpfc"'
check "installed generator is the source one (default DATADIR)" cmp -s programs/dataplane/bpfc-dataplane-gen "$R/usr/sbin/bpfc-dataplane-gen"
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
			'[ "$(grep -c /usr/share/bpfc/dataplane/profiles/ "$T/list")" -eq "$(ls programs/dataplane/profiles/*.profile | wc -l)" ]'
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
		srpmf=$(find "$T/rpmbuild/RPMS" -name 'bpfc-programs-[0-9]*.noarch.rpm' | head -1)
		rpm -qlp "$rpmf" > "$T/core" 2>/dev/null
		rpm -qlp "$srpmf" > "$T/files" 2>/dev/null
		rpm -qRp "$srpmf" > "$T/requires" 2>/dev/null
		check "bpfc-programs is a noarch package" test -n "$srpmf"
		check "no bpfc-scripts package is built" eval '[ -z "$(find "$T/rpmbuild/RPMS" -name "bpfc-scripts-*")" ]'
		for f in $PROG_TOOLS; do
			check "bpfc-programs has /usr/sbin/$f" grep -qx "/usr/sbin/$f" "$T/files"
			check "bpfc itself does not have $f" eval '! grep -qx "/usr/sbin/$f" "$T/core"'
		done
		for f in $PROG_DOCS; do
			check "bpfc-programs has /usr/share/doc/bpfc-programs/$f" grep -qx "/usr/share/doc/bpfc-programs/$f" "$T/files"
		done
		for n in $PROGRAMS; do
			[ -d "programs/$n/examples" ] || continue
			missing=
			while IFS= read -r f; do
				grep -qxF "/usr/share/doc/bpfc-programs/$n/$f" "$T/files" || missing="$missing $f"
			done < <(cd "programs/$n" && find examples -type f)
			check "bpfc-programs has every example of $n${missing:+ (missing:$missing)}" [ -z "$missing" ]
		done
		check "bpfc itself has no files of a program" eval '! grep -qE "dataplane|ecmp|flowmon|bpfc-programs" "$T/core"'
		check "bpfc itself has the binaries" eval 'grep -qx /usr/sbin/bpfc "$T/core" && grep -qx /usr/sbin/bpfcd "$T/core"'
		check "bpfc owns /var/lib/bpfc/interfaces.d and the sysusers file" eval \
			'grep -qx /var/lib/bpfc/interfaces.d "$T/core" && grep -qx /usr/lib/sysusers.d/bpfc.conf "$T/core"'
		rpm -qp --scripts "$rpmf" > "$T/scripts" 2>/dev/null
		check "bpfc creates the bpfc group before installing" grep -q 'groupadd -r bpfc' "$T/scripts"
		missing=
		for p in $PROG_PROFILES; do
			grep -qx "/usr/share/bpfc/$p" "$T/files" || missing="$missing $p"
		done
		check "bpfc-programs has every built-in profile${missing:+ (missing:$missing)}" [ -z "$missing" ]
		for n in $PROGRAMS; do
			ls "programs/$n"/profiles/*.profile >/dev/null 2>&1 || continue
			check "bpfc-programs has /etc/bpfc/$n/profiles.d" grep -qx "/etc/bpfc/$n/profiles.d" "$T/files"
		done
		rpm -qp --obsoletes "$srpmf" > "$T/obsoletes" 2>/dev/null; rpm -qp --provides "$srpmf" > "$T/provides" 2>/dev/null
		check "bpfc-programs obsoletes and provides bpfc-scripts" eval \
			'grep -q "^bpfc-scripts < " "$T/obsoletes" && grep -q "^bpfc-scripts = " "$T/provides"'
		check "bpfc-programs requires bpfc of the same build, bash and gawk" eval \
			'grep -qx "bpfc = $(rpm -qp --qf "%{VERSION}-%{RELEASE}" "$rpmf")" "$T/requires" && grep -qx bash "$T/requires" && grep -qx gawk "$T/requires"'
	else
		test_fail "make rpm"; tail -20 "$T/rpm.log" | sed 's/^/    /'
	fi
	[ -n "$had_tarball" ] || rm -f bpfc-*.tar.gz
fi

tests_exit
