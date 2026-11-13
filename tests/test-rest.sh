#!/bin/bash
#
# REST API test for bpfcd (rest_socket): configuration, socket ownership and
# permissions, every resource and method, checks, dry runs and rollbacks, the
# rest_dir / config_dir layering, reloads and restarts, a network namespace
# instance, protocol errors and limits, bpfcctl status --json, bpfc -T, and a
# short sanitizer fuzz run of the parsers (make fuzz).
#
# Uses a throwaway configuration tree (BPFC_CONF_ROOT, BPFC_LIB_ROOT,
# BPFC_RUN_ROOT), veths and a namespace named brt-* (removed afterwards), a
# group brt-group and a user brt-user (removed afterwards).
#
#   bash tests/test-rest.sh [-d] [-k]     -d: show daemon logs on failure, -k: keep temp dir
#
# Must be run as root from the repository root after `make`. Needs curl,
# python3 and iproute2.

if [ "$(id -u)" != "0" ]; then echo -e "rest (needs root) \e[33mSKIP\e[0m"; exit 0; fi
DEBUG=0; KEEP=0
for a in "$@"; do [ "$a" = "-d" ] && DEBUG=1; [ "$a" = "-k" ] && KEEP=1; done

RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; NC='\e[0m'
TOP=$(cd "$(dirname "$0")/.." && pwd)
BPFC=$TOP/bpfc
BPFCD=$TOP/bpfcd/bpfcd
BPFCCTL=$TOP/bpfcd/bpfcctl
for b in "$BPFC" "$BPFCD" "$BPFCCTL"; do
	[ -x "$b" ] || { echo "$b not built; run make first"; exit 1; }
done
for t in curl python3 ip tc; do
	command -v $t >/dev/null || { echo -e "rest (not installed: $t) ${YELLOW}SKIP${NC}"; exit 0; }
done
grep -qs " /sys/fs/bpf bpf " /proc/self/mounts || mount -t bpf bpf /sys/fs/bpf

T=$(mktemp -d /tmp/bpfc-rest.XXXXXX)
chmod 755 "$T"
export BPFC_CONF_ROOT=$T/etc BPFC_RUN_ROOT=$T/run BPFC_LIB_ROOT=$T/lib
E=$T/etc
L=$T/lib/interfaces.d
SOCK=$T/run/bpfcd.sock
PASS=0; FAIL=0
PIDS=()
LOG=$T/log

cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
	for l in brt-a brt-c brt-x; do ip link del $l 2>/dev/null; done
	ip netns del brt-ns 2>/dev/null
	userdel brt-user 2>/dev/null; groupdel brt-group 2>/dev/null
	rm -rf /sys/fs/bpf/brt-maps /sys/fs/bpf/netns/brt-ns
	[ $KEEP -eq 1 ] && echo "kept $T" || rm -rf "$T"
}
trap cleanup EXIT

ok()  { echo -e "  $* ${GREEN}PASS${NC}"; PASS=$((PASS + 1)); }
bad() {
	echo -e "  $* ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
	if [ $DEBUG -eq 1 ]; then echo "---- $LOG"; tail -12 "$LOG"; echo "---- last reply"; head -c 1500 "$T/reply" 2>/dev/null; echo "----"; fi
}
check() { local n="$1"; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }
eventually() { for _ in $(seq 60); do "$@" && return 0; sleep 0.1; done; return 1; }

# req METHOD PATH [BODY]: the reply body goes to $T/reply, headers to $T/hdr; prints the status code.
req() {
	local m=$1 p=$2
	shift 2
	curl -s -o "$T/reply" -D "$T/hdr" -w '%{http_code}' --unix-socket "${RSOCK:-$SOCK}" -X "$m" \
		${1+--data-binary "$1"} "http://bpfcd$p"
}
# jq-like: py 'expression on d' reads $T/reply as JSON
py() { python3 -c "import json,sys; d=json.load(open('$T/reply')); r=($1); sys.exit(0 if r else 1)"; }
pyval() { python3 -c "import json; d=json.load(open('$T/reply')); print($1)"; }
is() { [ "$(req "$1" "$2" "${3-}")" = "$4" ]; }

prog_id() { tc filter show dev "$1" "$2" pref "$3" 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
has() { [ -n "$(prog_id "$@")" ]; }
none() { [ -z "$(prog_id "$@")" ]; }
start() {
	"$BPFCD" "$@" >> "$LOG" 2>&1 &
	LAST_PID=$!
	PIDS+=("$LAST_PID")
	eventually test -s "${STATE:-$T/run/state}"
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
logged() { grep -q -- "$1" "$LOG"; }
prog() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; }
conf() { printf 'bpfc_path = %s\n' "${BPFCPATH:-$BPFC}" > "$E/bpfc.conf"; printf '%s\n' "$@" >> "$E/bpfc.conf"; }

mkdir -p "$E/interfaces.d" "$T/run"
groupadd brt-group 2>/dev/null
useradd -M -N -G brt-group brt-user 2>/dev/null

# bpfc wrapper: real installs (not -T checks) of programs containing FAILME
# fail, as if attaching failed after the check passed.
cat > "$T/bpfc-wrap" <<EOF
#!/bin/sh
f=; prev=; for a; do [ "\$prev" = -f ] && f=\$a; prev=\$a; done
case " \$* " in *" -T "*) ;; *) [ -n "\$f" ] && grep -q FAILME "\$f" 2>/dev/null && { echo "Error: failed to attach program (test)" >&2; exit 1; } ;; esac
exec "$BPFC" "\$@"
EOF
chmod 755 "$T/bpfc-wrap"
BPFCPATH=$T/bpfc-wrap

# ------------------------------------------------------------------ bpfc -T
echo "bpfc -T"
M=/sys/fs/bpf/brt-maps; mkdir -p $M
check "accepts a valid program, attaches nothing"   eval '"$BPFC" -T -m $M "match tcp; drop" | grep -q "not attached"'
check "rejects an invalid one"                       eval '! "$BPFC" -T "match bogus" >/dev/null 2>&1'
check "creates no pinned map"                        eval '"$BPFC" -T -m $M "array-map brt_a 4" >/dev/null && [ ! -e $M/brt_a ]'
"$BPFC" -m $M "array-map brt_a 4" >/dev/null 2>&1; rm -f output.bpf
INO=$(stat -c %i $M/brt_a)
check "leaves a pinned map of another shape alone"   eval '"$BPFC" -T -m $M "array-map brt_a 8" 2>&1 | grep -q "will replace" && [ "$(stat -c %i $M/brt_a)" = "$INO" ]'
check "refuses -T with -c or -D"                     eval '! "$BPFC" -T -c -i lo 2>/dev/null'

# ------------------------------------------------------------------ configuration
echo "configuration"
conf
check "off by default (-t says so)"                  eval '"$BPFCD" -t | grep -q "rest: *off"'
conf "rest_socket = $SOCK" "rest_socket_owner = root:brt-group"
check "-t shows socket, owner and mode"              eval '"$BPFCD" -t | grep -q "rest: *$SOCK (owner root:brt-group = 0:[0-9]*, mode 0660)"'
for bad in "rest_socket = relative.sock" "rest_socket_mode = 0999" "rest_socket_mode = 01777" "rest_socket_owner = a:b:c" \
	"rest_socket_owner = :" "rest_dir = relative" "rest_socket = /$(printf 'x%.0s' $(seq 120))"; do
	conf "$bad"
	check "refused: $bad"                            eval '! "$BPFCD" -t >/dev/null 2>&1'
done
conf "rest_dir = $E/interfaces.d"
check "refused: rest_dir = config_dir"               eval '! "$BPFCD" -t >/dev/null 2>&1'
conf "rest_socket = $SOCK" "rest_socket_owner = no-such-user"
check "-t reports an unknown owner"                  eval '"$BPFCD" -t | grep -q "error: rest_socket_owner: no user"'
mkdir -p "$E/netns/brt-ns"
conf "rest_socket = $SOCK"
check "namespace fallback does not inherit the socket" eval '"$BPFCD" -n brt-ns -t | grep -q "rest: *off"'
check "namespace rest_dir default"                   eval '"$BPFCCTL" -n brt-ns env | grep -qx "BPFC_REST_DIR=.$T/lib/netns/brt-ns/interfaces.d."'
check "BPFCD_REST_SOCKET turns it on"                eval 'BPFCD_REST_SOCKET=/run/x.sock "$BPFCD" -n brt-ns -t | grep -q "rest: */run/x.sock"'
rmdir "$E/netns/brt-ns"

# ------------------------------------------------------------------ socket
echo "socket"
ip link add brt-a type veth peer name brt-b
ip link add brt-c type veth peer name brt-d
for l in brt-a brt-b brt-c brt-d; do ip link set $l up; done
prog "$E/interfaces.d/brt-a/ingress/10.bpfc" 'match tcp; match tcp-dst 23; drop'
conf
start; P=$LAST_PID
check "no socket while rest_socket is unset"         eval 'sleep 0.3; [ ! -e $SOCK ]'
stop $P
conf "rest_socket = $SOCK" "rest_socket_owner = root:brt-group"
start; P=$LAST_PID
check "socket created, root:brt-group, mode 0660"    eventually eval '[ "$(stat -c "%U:%G %a %F" $SOCK 2>/dev/null)" = "root:brt-group 660 socket" ]'
check "rest_dir created"                             test -d "$L"
check "a member of the group can connect"            eval '[ "$(su -s /bin/sh brt-user -c "curl -s -o /dev/null -w %{http_code} --unix-socket $SOCK http://x/")" = 200 ]'
check "...and write (read/write for every client)"   eval '[ "$(su -s /bin/sh brt-user -c "curl -s -o /dev/null -w %{http_code} -X POST --data-binary @- --unix-socket $SOCK http://x/interfaces/brt-a/egress/9" <<< "[\"match udp; drop\"]")" = 201 ]'
check "...logged with its uid"                       eval 'logged "rest: POST /interfaces/brt-a/egress/9 from uid $(id -u brt-user) pid [0-9]*: 201"'
check "anyone else is refused by the socket mode"    eval '! su -s /bin/sh nobody -c "curl -s --unix-socket $SOCK http://x/" >/dev/null 2>&1'
is DELETE /interfaces/brt-a/egress/9 "" 200

# ------------------------------------------------------------------ reading
echo "reading"
check "GET / is 200 JSON"                            eval '[ "$(req GET /)" = 200 ] && grep -qi "^content-type: application/json" $T/hdr'
check "...daemon, summary, programs"                 py 'd["bpfcd"]["running"] and d["bpfcd"]["rest_socket"] == "'"$SOCK"'" and d["summary"]["installed"] >= 1'
check "...the program as in the state file"          py 'any(p["interface"]=="brt-a" and p["priority"]==10 and p["status"]=="installed" and p["source"]=="config" and p["prog_id"]=='"$(prog_id brt-a ingress 10)"' for p in d["programs"])'
check "HEAD / sends no body"                         eval '[ "$(curl -s -I --unix-socket $SOCK http://x/ | head -1 | tr -d "\r")" = "HTTP/1.1 200 OK" ]'
check "GET /interfaces lists interfaces"             eval '[ "$(req GET /interfaces)" = 200 ] && py "any(i[\"name\"]==\"brt-a\" and i[\"present\"] and i[\"programs\"]==1 and i[\"files\"]==1 for i in d[\"interfaces\"])"'
check "GET /interfaces/brt-a: details"               eval '[ "$(req GET /interfaces/brt-a)" = 200 ] && py "d[\"present\"] and d[\"kind\"]==\"veth\" and d[\"up\"] and d[\"mtu\"]>0 and len(d[\"mac\"])==17"'
check "...programs and files"                        py 'len(d["programs"])==1 and d["files"][0]["source"]=="config" and d["files"][0]["priority"]==10'
check "GET /interfaces/brt-a/ingress"                eval '[ "$(req GET /interfaces/brt-a/ingress)" = 200 ] && py "d[\"direction\"]==\"ingress\" and len(d[\"programs\"])==1"'
check "GET /interfaces/brt-a/egress: none"           eval '[ "$(req GET /interfaces/brt-a/egress)" = 200 ] && py "d[\"programs\"]==[] and d[\"files\"]==[]"'
check "GET a file: lines as a JSON array"            eval '[ "$(req GET /interfaces/brt-a/ingress/10)" = 200 ] && py "d==[\"match tcp; match tcp-dst 23; drop\"]"'
check "...where it came from (headers)"              eval 'grep -qi "^x-bpfc-source: config" $T/hdr && grep -qi "^x-bpfc-file: $E/interfaces.d/brt-a/ingress/10.bpfc" $T/hdr'
check "GET a missing file: 404"                      is GET /interfaces/brt-a/ingress/11 "" 404
check "GET of an absent interface: present false"    eval '[ "$(req GET /interfaces/brt-none)" = 200 ] && py "not d[\"present\"] and d[\"programs\"]==[]"'

# ------------------------------------------------------------------ writing
echo "writing"
check "POST a new file: 201"                         is POST /interfaces/brt-c/egress/5 '["# from REST", "match udp;", "  drop"]' 201
check "...created, checked and installed"            py 'd["ok"] and d["created"] and d["checks"][0]["ok"] and d["checks"][0]["interface"]=="brt-c" and d["programs"][0]["status"]=="installed"'
check "...in the kernel"                             has brt-c egress 5
check "...file in rest_dir, one line each, 0644"     eval '[ "$(cat $L/brt-c/egress/5.bpfc)" = "$(printf "# from REST\nmatch udp;\n  drop")" ] && [ "$(stat -c %a $L/brt-c/egress/5.bpfc)" = 644 ]'
check "...reported as source rest"                   eval 'req GET /interfaces/brt-c/egress/5 >/dev/null; grep -qi "^x-bpfc-source: rest" $T/hdr && py "d[1]==\"match udp;\""'
ID=$(prog_id brt-c egress 5)
check "POST the same again: 200, unchanged"          eval '[ "$(req POST /interfaces/brt-c/egress/5 "[\"# from REST\", \"match udp;\", \"  drop\"]")" = 200 ] && py "not d[\"created\"] and not d[\"changed\"]" && [ "$(prog_id brt-c egress 5)" = "$ID" ]'
check "PUT replaces: new program in the kernel"      eval '[ "$(req PUT /interfaces/brt-c/egress/5 "[\"match tcp; drop\"]")" = 200 ] && py "d[\"changed\"]" && [ "$(prog_id brt-c egress 5)" != "$ID" ]'
check "POST [] writes an empty (excluding) file"     eval '[ "$(req POST /interfaces/brt-c/egress/5 "[]")" = 200 ] && py "d[\"empty\"] and d[\"programs\"][0][\"status\"]==\"excluded\"" && none brt-c egress 5'
req DELETE /interfaces/brt-c/egress/5 >/dev/null
check "POST to an absent interface: 201, a note"     eval '[ "$(req POST /interfaces/brt-zz/ingress/3 "[\"drop\"]")" = 201 ] && py "\"installed when it appears\" in d[\"note\"] and d[\"programs\"][0][\"status\"]==\"pending-iface\""'
check "...a note when a more specific file wins"     eval 'prog $E/interfaces.d/brt-d/ingress/44.bpfc "drop"; [ "$(req POST "/interfaces/%25veth%25/ingress/44" "[\"drop\"]")" = 201 ] && py "not any(p[\"interface\"]==\"brt-d\" for p in d[\"programs\"])"; rc=$?; rm -r $E/interfaces.d/brt-d; req DELETE "/interfaces/%25veth%25/ingress/44" >/dev/null; [ $rc = 0 ]'
check "...installed when it appears"                 eval 'ip link add brt-zz type veth peer name brt-zy; eventually has brt-zz ingress 3'
ip link del brt-zz; req DELETE /interfaces/brt-zz/ingress/3 >/dev/null
check "XDP: POST /interfaces/brt-c/xdp"              eval '[ "$(req POST /interfaces/brt-c/xdp "[\"match tcp; drop\"]")" = 201 ] && ip link show brt-c | grep -q xdp'
check "XDP: GET and DELETE"                          eval '[ "$(req GET /interfaces/brt-c/xdp)" = 200 ] && [ "$(req DELETE /interfaces/brt-c/xdp)" = 200 ] && ! ip link show brt-c | grep -q xdp && [ ! -e $L/brt-c/xdp.bpfc ]'

echo "override and delete"
ID=$(prog_id brt-a ingress 10)
check "POST over a config file: overrides it"        eval '[ "$(req POST /interfaces/brt-a/ingress/10 "[\"match tcp; match tcp-dst 22; drop\"]")" = 201 ] && py "d[\"overrides\"]==\"$E/interfaces.d/brt-a/ingress/10.bpfc\" and d[\"programs\"][0][\"source\"]==\"rest\""'
check "...new program installed"                     eval '[ "$(prog_id brt-a ingress 10)" != "$ID" ]'
check "...config file untouched"                     eval 'grep -q "tcp-dst 23" $E/interfaces.d/brt-a/ingress/10.bpfc'
check "...interface lists the override"              eval 'req GET /interfaces/brt-a >/dev/null; py "d[\"files\"][0][\"source\"]==\"rest\" and d[\"files\"][0][\"overrides\"].endswith(\"/brt-a/ingress/10.bpfc\")"'
check "bpfcctl status marks it rest:"                eval '"$BPFCCTL" status --color=never | grep -q "brt-a .* rest:brt-a/ingress/10.bpfc"'
check "DELETE: config file applies again"            eval '[ "$(req DELETE /interfaces/brt-a/ingress/10)" = 200 ] && py "d[\"now_from\"].startswith(\"$E\") and d[\"programs\"][0][\"source\"]==\"config\""'
check "...and its program is back"                   eval 'req GET /interfaces/brt-a/ingress/10 >/dev/null; grep -qi "^x-bpfc-source: config" $T/hdr && has brt-a ingress 10'
check "...empty rest_dir directories removed"        eval '[ ! -e $L/brt-a ]'
check "DELETE a config-only file: 409"               is DELETE /interfaces/brt-a/ingress/10 "" 409
check "DELETE nothing: 404"                          is DELETE /interfaces/brt-a/ingress/99 "" 404

echo "templates"
check "POST %all% (unencoded): installs everywhere"  eval '[ "$(req POST "/interfaces/%all%/ingress/40" "[\"match udp; drop\"]")" = 201 ] && has brt-a ingress 40 && has brt-d ingress 40'
check "...%25all%25 reads the same file"             eval '[ "$(req GET "/interfaces/%25all%25/ingress/40")" = 200 ] && py "d==[\"match udp; drop\"]"'
check "...programs listed under the template"        eval 'req GET "/interfaces/%25all%25" >/dev/null; py "d[\"template\"] and any(p[\"interface\"]==\"brt-a\" for p in d[\"programs\"])"'
check "GET brt-a/ingress/40: 404 naming %all%"       eval '[ "$(req GET /interfaces/brt-a/ingress/40)" = 404 ] && grep -q "comes from .*%all%" $T/reply'
check "empty file at brt-a excludes it"              eval '[ "$(req POST /interfaces/brt-a/ingress/40 "[\"# not here\"]")" = 201 ] && none brt-a ingress 40 && has brt-d ingress 40'
check "%veth% template"                              eval '[ "$(req POST "/interfaces/%25veth%25/egress/41" "[\"match tcp; drop\"]")" = 201 ] && has brt-b egress 41'
for x in "/interfaces/brt-a/ingress/40" "/interfaces/%25all%25/ingress/40" "/interfaces/%25veth%25/egress/41"; do req DELETE "$x" >/dev/null; done
check "...all removed again"                         eval 'none brt-d ingress 40 && none brt-b egress 41 && [ -z "$(ls -A $L)" ]'

# ------------------------------------------------------------------ checks and rollback
echo "checks, dry runs and rollback"
ID=$(prog_id brt-a ingress 10)
check "invalid program: 422, nothing changes"        eval '[ "$(req POST /interfaces/brt-a/ingress/10 "[\"match nonsense\"]")" = 422 ] && py "not d[\"ok\"] and not d[\"changed\"] and \"rejected\" in d[\"error\"]"'
check "...bpfc output in the reply"                  py 'any("nonsense" in l for l in d["checks"][0]["output"])'
check "...no file, no leftovers"                     eval '[ ! -e $L/brt-a ] && [ "$(prog_id brt-a ingress 10)" = "$ID" ] && [ -z "$(find $L -name ".*")" ]'
check "verifier rejection: 422 with the reason"      eval '[ "$(req POST /interfaces/brt-c/ingress/7 "[\"start-loop; loop-reg\"]")" = 422 ] && py "d[\"error\"].startswith(\"the program was rejected on brt-c: verifier rejected\") and any(\"VERIFIER REJECTION\" in l for l in d[\"checks\"][0][\"output\"])"'
check "dry run: 200, applies_to, nothing written"    eval '[ "$(req POST "/interfaces/%25all%25/egress/50?dry-run" "[\"match tcp; drop\"]")" = 200 ] && py "d[\"dry_run\"] and \"brt-a\" in d[\"applies_to\"] and len(d[\"checks\"])==len(d[\"applies_to\"])" && [ -z "$(ls -A $L)" ] && none brt-a egress 50'
check "dry run of a bad program: 422"                eval '[ "$(req POST "/interfaces/brt-a/egress/50?dry-run=true" "[\"bogus\"]")" = 422 ] && py "d[\"dry_run\"] and not d[\"ok\"]"'
check "dry-run=false installs"                       eval '[ "$(req POST "/interfaces/brt-a/egress/50?dry-run=false" "[\"match tcp; drop\"]")" = 201 ] && has brt-a egress 50'
ID=$(prog_id brt-a egress 50)
check "install fails after the check: 422"           eval '[ "$(req POST /interfaces/brt-a/egress/50 "[\"# FAILME\", \"match udp; drop\"]")" = 422 ] && py "d[\"rolled_back\"] and d[\"failures\"][0][\"interface\"]==\"brt-a\""'
check "...the failure output in the reply"           py 'any("failed to attach" in l for l in d["failures"][0]["output"])'
check "...previous file back and reinstalled"        eval 'grep -q "match tcp" $L/brt-a/egress/50.bpfc && ! grep -q FAILME $L/brt-a/egress/50.bpfc && has brt-a egress 50 && py "d[\"programs\"][0][\"status\"]==\"installed\""'
check "...a new file that fails is removed again"    eval '[ "$(req POST /interfaces/brt-c/egress/51 "[\"# FAILME\", \"drop\"]")" = 422 ] && [ ! -e $L/brt-c/egress/51.bpfc ] && none brt-c egress 51'
check "...logged"                                    logged "rest: .*installing failed on brt-a.*the previous file is back"
req DELETE /interfaces/brt-a/egress/50 >/dev/null

# ------------------------------------------------------------------ protocol
echo "protocol"
check "unknown resource: 404"                        is GET /nothing "" 404
check "invalid interface name: 404"                  is GET "/interfaces/a%20b" "" 404
check "bad priority: 404"                            eval '[ "$(req GET /interfaces/brt-a/ingress/010)" = 404 ] && [ "$(req GET /interfaces/brt-a/ingress/70000)" = 404 ] && [ "$(req GET /interfaces/brt-a/sideways/1)" = 404 ]'
check "XDP with a priority: 404"                     is GET /interfaces/brt-a/xdp/1 "" 404
check "encoded slash: 400"                           is GET "/interfaces/brt%2fa" "" 400
check "POST / : 405 with Allow"                      eval '[ "$(req POST / "[]")" = 405 ] && grep -qi "^allow: GET, HEAD" $T/hdr'
check "PATCH a file: 405"                            eval '[ "$(req PATCH /interfaces/brt-a/ingress/10 "[]")" = 405 ] && grep -qi "^allow: GET, HEAD, POST, PUT, DELETE" $T/hdr'
check "not JSON: 400"                                is POST /interfaces/brt-a/egress/60 'match tcp; drop' 400
check "not an array of strings: 400"                 eval '[ "$(req POST /interfaces/brt-a/egress/60 "[\"a\", 1]")" = 400 ] && [ "$(req POST /interfaces/brt-a/egress/60 "{\"lines\": []}")" = 400 ]'
check "line with a newline: 400"                     eval '[ "$(req POST /interfaces/brt-a/egress/60 "[\"a\\nb\"]")" = 400 ] && grep -q "one string per line" $T/reply'
check "error replies are JSON"                       py 'd["error"]["status"] == 400 and d["error"]["message"]'
BIG=$(python3 -c 'import json; print(json.dumps(["# padding line %d" % i for i in range(4000)] + ["match tcp; drop"]))')
check "large body (Expect: 100-continue)"            eval '[ "$(req POST /interfaces/brt-a/egress/61 "$BIG")" = 201 ] && [ "$(wc -l < $L/brt-a/egress/61.bpfc)" = 4001 ]'
req DELETE /interfaces/brt-a/egress/61 >/dev/null
cat > "$T/raw.py" <<'EOF'
import socket, sys, time
P = sys.argv[1]
def req(raw, timeout=15):
    s = socket.socket(socket.AF_UNIX); s.settimeout(timeout); s.connect(P); s.sendall(raw)
    out = b''
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out.split(b'\r\n', 1)[0].decode(errors='replace')
which = sys.argv[2]
if which == 'nolen': print(req(b"POST /interfaces/x/egress/1 HTTP/1.1\r\n\r\n"))
if which == 'chunked': print(req(b"POST /interfaces/x/egress/1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
if which == 'big': print(req(b"POST /interfaces/x/egress/1 HTTP/1.1\r\nContent-Length: 2000000\r\n\r\n" + b"x" * 65536))
if which == 'hdr': print(req(b"GET / HTTP/1.1\r\nX-Pad: " + b"a" * 20000 + b"\r\n\r\n"))
if which == 'garbage': print(req(b"\x00\x01\x02 nonsense\r\n\r\n"))
if which == 'v2': print(req(b"GET / HTTP/2.0\r\n\r\n"))
if which == 'http10': print(req(b"GET / HTTP/1.0\r\n\r\n"))
if which == 'slow':
    t = time.time(); r = req(b"GET / HTTP/1.1\r\n"); print(r, int(time.time() - t))
if which == 'many':
    socks = []
    for i in range(33):
        s = socket.socket(socket.AF_UNIX); s.connect(P); socks.append(s)
    time.sleep(0.5)
    print(req(b"GET / HTTP/1.1\r\n\r\n", 3))
    for s in socks: s.close()
    time.sleep(0.5)
    print(req(b"GET / HTTP/1.1\r\n\r\n", 3))
EOF
raw() { python3 "$T/raw.py" "$SOCK" "$1"; }
check "POST without Content-Length: 411"             eval '[ "$(raw nolen)" = "HTTP/1.1 411 Length Required" ]'
check "chunked body: 501"                            eval '[ "$(raw chunked)" = "HTTP/1.1 501 Not Implemented" ]'
check "body over 1 MiB: 413"                         eval '[ "$(raw big)" = "HTTP/1.1 413 Content Too Large" ]'
check "headers over 16 KiB: 431"                     eval '[ "$(raw hdr)" = "HTTP/1.1 431 Request Header Fields Too Large" ]'
check "garbage: 400"                                 eval '[ "$(raw garbage)" = "HTTP/1.1 400 Bad Request" ]'
check "HTTP/2.0: 505"                                eval '[ "$(raw v2)" = "HTTP/1.1 505 HTTP Version Not Supported" ]'
check "HTTP/1.0 works"                               eval '[ "$(raw http10)" = "HTTP/1.1 200 OK" ]'
check "incomplete request: 408 after 10 s"           eval '[ "$(raw slow)" = "HTTP/1.1 408 Request Timeout 10" ]'
check "33rd connection: 503, then fine again"        eval '[ "$(raw many | tr "\n" "|")" = "HTTP/1.1 503 Service Unavailable|HTTP/1.1 200 OK|" ]'
check "bpfcd still running"                          kill -0 $P

# ------------------------------------------------------------------ bpfcctl
echo "bpfcctl"
req GET / >/dev/null
check "status --json: same programs as GET /"        eval '"$BPFCCTL" status --json > $T/ctl.json && python3 -c "
import json; a=json.load(open(\"$T/ctl.json\")); b=json.load(open(\"$T/reply\"))
k=lambda d: sorted((p[\"interface\"],p[\"direction\"],p[\"priority\"] or 0,p[\"prog_id\"] or 0) for p in d[\"programs\"])
assert k(a)==k(b) and a[\"bpfcd\"][\"rest_dir\"]==b[\"bpfcd\"][\"rest_dir\"]"'
check "...with kernel checks"                        eval 'python3 -c "import json; a=json.load(open(\"$T/ctl.json\")); assert all(p[\"kernel\"]==\"ok\" for p in a[\"programs\"] if p[\"status\"]==\"installed\")"'
check "status -j -a lists unmanaged filters"         eval 'tc qdisc add dev brt-d clsact 2>/dev/null; "$BPFC" -i brt-d -p 77 "drop" >/dev/null; "$BPFCCTL" status -j -a | python3 -c "import json,sys; a=json.load(sys.stdin); assert any(u[\"interface\"]==\"brt-d\" and u[\"priority\"]==77 for u in a[\"unmanaged\"])"'
"$BPFC" -i brt-d -p 77 -D >/dev/null 2>&1
check "status --json exit status as text status"     eval '"$BPFCCTL" status -j >/dev/null; [ $? = 0 ]'
check "env: BPFC_REST_DIR and BPFC_REST_SOCKET"      eval '"$BPFCCTL" env | grep -qx "BPFC_REST_DIR=.$L." && "$BPFCCTL" env | grep -qx "BPFC_REST_SOCKET=.$SOCK."'
check "--json only for status"                       eval '! "$BPFCCTL" show -j brt-a ingress 10 >/dev/null 2>&1'

# ------------------------------------------------------------------ reload and restart
echo "reload and restart"
req POST /interfaces/brt-c/ingress/12 '["match tcp; drop"]' >/dev/null
ID=$(prog_id brt-c ingress 12)
conf "rest_socket = $SOCK" "rest_socket_owner = brt-user:brt-group" "rest_socket_mode = 0600"
check "reload: new owner and mode"                   eval 'kill -HUP $P; eventually eval "[ \"\$(stat -c \"%U:%G %a\" $SOCK)\" = \"brt-user:brt-group 600\" ]"'
conf "rest_socket = $SOCK" "rest_socket_owner = nobody-here"
check "reload with an unknown owner keeps the socket" eval 'kill -HUP $P; eventually logged "still serving $SOCK as before" && [ "$(req GET /)" = 200 ]'
conf
check "reload without rest_socket: socket gone"      eval 'kill -HUP $P; eventually eval "[ ! -e $SOCK ]"'
check "...but rest_dir programs stay installed"      eval 'sleep 0.3; [ "$(prog_id brt-c ingress 12)" = "$ID" ]'
conf "rest_socket = $SOCK"
check "reload with rest_socket: serving again"       eval 'kill -HUP $P; eventually eval "[ \"\$(req GET /)\" = 200 ]"'
stop $P
check "stop removes the socket"                      eval '[ ! -e $SOCK ]'
check "a stale socket file is replaced"              eval 'python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.bind(\"$SOCK\")"; [ -S $SOCK ]'
start; P=$LAST_PID
check "...and the restarted bpfcd serves"            eventually eval '[ "$(req GET /)" = 200 ]'
check "rest_dir programs adopted, not reinstalled"   eval '[ "$(prog_id brt-c ingress 12)" = "$ID" ] && logged "adopted"'
stop $P
touch "$T/run/not-a-socket"
conf "rest_socket = $T/run/not-a-socket"
start; P=$LAST_PID
check "a regular file at the path is not replaced"   eval 'eventually logged "not-a-socket exists and is not a socket" && [ -f $T/run/not-a-socket ]'
check "...bpfcd runs on without the API"             eval 'kill -0 $P && has brt-c ingress 12'
stop $P
rm -rf "$L/brt-c"

# ------------------------------------------------------------------ network namespace
echo "network namespace"
ip netns add brt-ns
ip link add brt-x type veth peer name brt-y netns brt-ns
ip -n brt-ns link set brt-y up
NSOCK=$T/run/netns/brt-ns/bpfcd.sock
mkdir -p "$E/netns/brt-ns"
printf 'bpfc_path = %s\nrest_socket = %s\n' "$BPFC" "$NSOCK" > "$E/netns/brt-ns/bpfc.conf"
STATE=$T/run/netns/brt-ns/state start -n brt-ns; PN=$LAST_PID
check "instance serves its own socket"               eventually eval '[ "$(RSOCK=$NSOCK req GET /)" = 200 ] && py "d[\"bpfcd\"][\"netns\"]==\"brt-ns\""'
check "...sees the namespace's interfaces"           eval 'RSOCK=$NSOCK req GET /interfaces >/dev/null; py "any(i[\"name\"]==\"brt-y\" and i[\"present\"] for i in d[\"interfaces\"]) and not any(i[\"name\"]==\"brt-a\" for i in d[\"interfaces\"])"'
check "POST installs inside the namespace"           eval '[ "$(RSOCK=$NSOCK req POST /interfaces/brt-y/ingress/8 "[\"match tcp; drop\"]")" = 201 ] && [ -n "$(ip netns exec brt-ns tc filter show dev brt-y ingress pref 8)" ]'
check "...file in the namespace's rest_dir"          test -f "$T/lib/netns/brt-ns/interfaces.d/brt-y/ingress/8.bpfc"
check "...checked inside it (interface present)"     py 'd["checks"][0]["interface"]=="brt-y"'
check "bpfcctl -n shows it as rest:"                 eval '"$BPFCCTL" -n brt-ns status --color=never | grep -q "brt-y .* rest:brt-y/ingress/8.bpfc"'
stop $PN

# ------------------------------------------------------------------ fuzz
echo "fuzz"
if printf 'int main(void){return 0;}\n' | ${CC:-cc} -fsanitize=address,undefined -x c -o "$T/asan-probe" - 2>/dev/null; then
	check "HTTP and JSON parsers under ASan/UBSan"   eval 'make -s -C "$TOP" fuzz FUZZ_ITERS=50000 > $T/fuzz.log 2>&1 && grep -q "without a fault" $T/fuzz.log'
else
	echo -e "  HTTP and JSON parsers under ASan/UBSan (no sanitizer runtime) ${YELLOW}SKIP${NC}"
fi

echo
echo "rest: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
