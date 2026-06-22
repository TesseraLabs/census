#!/usr/bin/env bash
# Integration harness for `census apply` (provisioning-apply, task 7).
# Runs INSIDE a root Linux container (debian-based rust image). Builds the
# release binary, then exercises create/idempotent/sudo-revoke/delete against
# real shadow-utils + visudo and asserts the on-disk result.
#
# Run from the host via container-run.sh (do not run on the host — it mutates
# /etc/passwd etc.). Safe only in a throwaway container.
set -u

export CARGO_TARGET_DIR=/tmp/ct      # keep linux build off the mounted host target/
CENSUS=/tmp/ct/release/census
ROOT=/tmp/census-it
STORE="$ROOT/roles"
DECL="$ROOT/declaration.toml"
MANAGED="$ROOT/managed.toml"
SUDOERS=/etc/sudoers.d
RB="$ROOT/rollback"

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
no()   { echo "  FAIL: $1"; fail=$((fail+1)); }
assert()      { if eval "$2"; then ok "$1"; else no "$1 [cmd: $2]"; fi; }
assert_not()  { if eval "$2"; then no "$1 (expected false) [cmd: $2]"; else ok "$1"; fi; }

echo "== build =="
( cd /work && cargo build --release --locked ) || { echo "BUILD FAILED"; exit 2; }

mkdir -p "$STORE" "$RB"

write_store() {
  # $1 = oper sudo_role line ("" to omit)
  local operline="$1"
  cat > "$STORE/oper.toml" <<EOF
role = "oper"
version = 1
os = "linux"
name = "Operator"
level = 5
[payload]
groups = ["staff"]
$operline
EOF
  cat > "$STORE/serv.toml" <<EOF
role = "serv"
version = 1
os = "linux"
name = "Service"
level = 3
[payload]
groups = ["staff"]
EOF
}

write_decl() {
  # $1 = include serv? (yes/no)
  local serv="$1"
  cat > "$DECL" <<EOF
version = $2
role_store = "$STORE"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "oper"
uid = 9010
EOF
  if [ "$serv" = "yes" ]; then
    cat >> "$DECL" <<EOF
[[role_account]]
role = "serv"
uid = 9020
EOF
  fi
}

run_apply() {
  "$CENSUS" apply --declaration "$DECL" --managed "$MANAGED" \
    --trust-fs --i-understand-no-rescue 2>&1
}

# groups needed by roles must pre-exist (Census manages accounts, not base groups
# in this slice; useradd -G requires the group to exist)
groupadd -f staff

echo "== scenario 1: CREATE (oper w/ sudo, serv w/o) =="
write_store 'sudo_role = "ops"'
write_decl yes 1
echo ":: $(run_apply)"
assert     "oper account exists"           "getent passwd oper >/dev/null"
assert     "oper uid is 9010"              "[ \"\$(id -u oper)\" = 9010 ]"
assert     "oper shell is /bin/bash"       "getent passwd oper | grep -q ':/bin/bash$'"
assert     "oper password locked (!)"      "getent shadow oper | cut -d: -f2 | grep -q '^!'"
assert     "oper in group staff"           "id -nG oper | grep -qw staff"
assert_not "oper has authorized_keys"      "test -e /var/lib/census/home/oper/.ssh/authorized_keys"
assert     "serv account exists"           "getent passwd serv >/dev/null"
assert     "census-oper sudoers present"   "test -f $SUDOERS/census-oper"
assert     "census-oper passes visudo"     "visudo -c -f $SUDOERS/census-oper >/dev/null 2>&1"
assert     "census-serv sudoers absent"    "! test -f $SUDOERS/census-serv"
assert     "managed.toml lists oper"       "grep -q 'name = \"oper\"' $MANAGED"

echo "== scenario 2: IDEMPOTENT re-apply =="
out2="$(run_apply)"; echo ":: $out2"
assert     "second apply is no-op"         "echo \"\$out2\" | grep -qiE 'no changes|plan is empty|0 mutation'"

echo "== scenario 3: UPDATE — revoke oper sudo (sudo-only change) =="
write_store ''                 # oper loses sudo_role
write_decl yes 2               # bump version
echo ":: $(run_apply)"
assert     "census-oper sudoers removed"   "! test -f $SUDOERS/census-oper"
assert     "oper account still exists"     "getent passwd oper >/dev/null"

echo "== scenario 4: DELETE — drop serv from declaration =="
write_decl no 3
echo ":: $(run_apply)"
assert_not "serv account removed"          "getent passwd serv >/dev/null"
assert     "oper account retained"         "getent passwd oper >/dev/null"

echo "== scenario 5: UNREACHABILITY (non-root su into oper) =="
# create an unprivileged probe user; su to a locked account must fail
id probe >/dev/null 2>&1 || useradd -m -s /bin/bash probe
assert_not "non-root su - oper succeeds"   "su probe -c 'su - oper -c true' >/dev/null 2>&1"

echo "== scenario 6-8: MANAGED trust (Ed25519 signature, openssl-signed → dalek-verified) =="
# Proves cross-impl interop: openssl signs, census (ed25519-dalek) verifies.
MROOT="$ROOT/m"; MSTORE="$MROOT/roles"; MMAN="$MROOT/managed.toml"
mkdir -p "$MSTORE" /etc/census /var/lib/census
rm -f /var/lib/census/declaration.version
cat > "$MSTORE/audit.toml" <<EOF
role = "audit"
version = 1
os = "linux"
name = "Audit"
level = 1
[payload]
groups = ["staff"]
EOF
openssl genpkey -algorithm ed25519 -out "$MROOT/priv.pem" 2>/dev/null
# trust-anchor = hex of the 32-byte raw Ed25519 public key (last 32 bytes of SPKI DER)
openssl pkey -in "$MROOT/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n' > /etc/census/trust.pub

build_unsigned() { # $1=outfile $2=version
  cat > "$1" <<EOF
version = $2
role_store = "$MSTORE"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "audit"
uid = 9030
EOF
}
sign_decl() { # $1=unsigned-in $2=signed-out ; signs raw bytes; signature line is PREPENDED
  # as a top-level key (before any [table]) so it stays valid TOML and census strips
  # this first line back to the exact signed bytes.
  local sig; openssl pkeyutl -sign -inkey "$MROOT/priv.pem" -rawin -in "$1" -out "$MROOT/sig.bin" 2>/dev/null
  sig=$(od -An -tx1 "$MROOT/sig.bin" | tr -d ' \n')
  { printf 'signature = "%s"\n' "$sig"; cat "$1"; } > "$2"
}
apply_managed() { "$CENSUS" apply --declaration "$1" --managed "$MMAN" --i-understand-no-rescue 2>&1; }

echo "-- 6: valid signed declaration (no --trust-fs) applies --"
build_unsigned "$MROOT/d10" 10
sign_decl "$MROOT/d10" "$MROOT/d10.signed"
out6="$(apply_managed "$MROOT/d10.signed")"; echo ":: $out6"
assert     "signed managed apply creates audit"  "getent passwd audit >/dev/null"
assert     "persisted version is 10"             "[ \"\$(cat /var/lib/census/declaration.version)\" = 10 ]"

echo "-- 7: unsigned declaration without --trust-fs is refused --"
out7="$(apply_managed "$MROOT/d10" 2>&1)"; rc7=$?
assert     "unsigned managed apply fails"        "[ $rc7 -ne 0 ]"
assert     "unsigned apply names missing sig"    "echo \"\$out7\" | grep -qiE 'signature|trust|refus|error'"

echo "-- 8: rollback (lower version, validly signed) is refused --"
build_unsigned "$MROOT/d5" 5
sign_decl "$MROOT/d5" "$MROOT/d5.signed"
out8="$(apply_managed "$MROOT/d5.signed" 2>&1)"; rc8=$?
assert     "rollback to version 5 fails"         "[ $rc8 -ne 0 ]"
assert     "persisted version still 10"          "[ \"\$(cat /var/lib/census/declaration.version)\" = 10 ]"

echo "== scenario 9-13: DOCTOR + STATUS (read-only diagnostics) =="
# Isolate doctor on the managed state $MMAN (audit). Remove the scenario 1-5
# census-marked account so it isn't seen as an orphan marker against $MMAN.
userdel -r oper 2>/dev/null || true
doctor() { "$CENSUS" doctor --managed "$MMAN" 2>&1; }

echo "-- 9: doctor clean on managed state → exit 0 --"
out9="$(doctor)"; rc9=$?; echo ":: $out9"
assert     "doctor clean exits 0"          "[ $rc9 -eq 0 ]"

echo "-- 10: unlocked password → doctor Error (non-zero) --"
passwd -d audit >/dev/null 2>&1            # clear password (now login-capable w/o auth)
doctor >/dev/null 2>&1; rc10=$?
assert     "doctor flags unlocked pw"      "[ $rc10 -ne 0 ]"
passwd -l audit >/dev/null 2>&1            # restore lock

echo "-- 11: authorized_keys present → doctor Error --"
mkdir -p /var/lib/census/home/audit/.ssh && echo "ssh-ed25519 AAAA test" > /var/lib/census/home/audit/.ssh/authorized_keys
doctor >/dev/null 2>&1; rc11=$?
assert     "doctor flags authorized_keys"  "[ $rc11 -ne 0 ]"
rm -rf /var/lib/census/home/audit/.ssh

echo "-- 12: GECOS-spoof (census marker on non-registry account) → doctor Error --"
useradd -M -s /usr/sbin/nologin -c "census-role-ghost" ghost 2>/dev/null
doctor >/dev/null 2>&1; rc12=$?
assert     "doctor flags GECOS spoof"      "[ $rc12 -ne 0 ]"
userdel ghost 2>/dev/null || true

echo "-- 13: doctor clean again after restore; status exits 0 --"
doctor >/dev/null 2>&1; rc13=$?
assert     "doctor clean after restore"    "[ $rc13 -eq 0 ]"
"$CENSUS" status --managed "$MMAN" >/dev/null 2>&1; rcs=$?
assert     "status exits 0"                "[ $rcs -eq 0 ]"
assert     "status prints audit + version" "\"$CENSUS\" status --managed \"$MMAN\" 2>&1 | grep -qE 'audit|version|10'"

echo "== scenario 14-18: GROUP provisioning (create / pin-gid / orphan-delete / foreign-safe) =="
GROOT="$ROOT/g"; GSTORE="$GROOT/roles"; GMAN="$GROOT/managed.toml"
mkdir -p "$GSTORE"
g_decl() { # $1=version $2=group-line-for-role ("" none) $3=group-block ("" none)
  cat > "$GSTORE/gtest.toml" <<EOF
role = "gtest"
version = 1
os = "linux"
name = "GroupTest"
level = 1
[payload]
groups = [$2]
EOF
  cat > "$GROOT/decl.toml" <<EOF
version = $1
role_store = "$GSTORE"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
$3
[[role_account]]
role = "gtest"
uid = 9040
EOF
}
g_apply() { "$CENSUS" apply --declaration "$GROOT/decl.toml" --managed "$GMAN" --trust-fs --i-understand-no-rescue 2>&1; }

echo "-- 14: create new group with pinned GID + member account --"
g_decl 1 '"census-grp"' $'[[group]]\nname = "census-grp"\ngid = 8500'
echo ":: $(g_apply)"
assert     "census-grp group created"      "getent group census-grp >/dev/null"
assert     "census-grp has pinned gid 8500" "[ \"\$(getent group census-grp | cut -d: -f3)\" = 8500 ]"
assert     "gtest is member of census-grp"  "id -nG gtest | grep -qw census-grp"

echo "-- 15: orphan managed group is deleted when no longer referenced --"
g_decl 2 '' ''                              # role drops group, block removed
echo ":: $(g_apply)"
assert     "orphan census-grp removed"      "! getent group census-grp >/dev/null"
assert     "gtest account retained"         "getent passwd gtest >/dev/null"

echo "-- 16: pre-existing FOREIGN group is adopted-as-member but never deleted --"
groupadd foreign-grp                        # created OUTSIDE census
g_decl 3 '"foreign-grp"' ''
echo ":: $(g_apply)"
assert     "gtest member of foreign-grp"    "id -nG gtest | grep -qw foreign-grp"
assert     "foreign-grp not a managed group" "! grep -q 'name = \"foreign-grp\"' $GMAN"

echo "-- 17: foreign group survives unreference (Census never deletes it) --"
g_decl 4 '' ''
echo ":: $(g_apply)"
assert     "foreign-grp still exists"       "getent group foreign-grp >/dev/null"

echo "-- 18: doctor clean on group state --"
# Isolate: remove census-marked accounts from other managed states (audit from sc.6)
# so doctor --managed $GMAN sees only gtest as census-marked.
userdel -r audit 2>/dev/null || true
"$CENSUS" doctor --managed "$GMAN" >/dev/null 2>&1; rcgd=$?
assert     "doctor clean on group state"    "[ $rcgd -eq 0 ]"

echo "== scenario 19-21: LIVE-RECONCILE (defer userdel on live session; §12) =="
# Isolated subtree so live-reconcile never collides with earlier managed state.
# `lr` references ONLY the managed group census-lr (gid-pinned 8600) so the block
# is self-contained — no base-group prerequisites. Standalone (--trust-fs) never
# persists a version floor, so versions can be reused/rewound freely here.
LROOT="$ROOT/lr"; LSTORE="$LROOT/roles"; LMAN="$LROOT/managed.toml"
mkdir -p "$LSTORE"
l_store() {
  cat > "$LSTORE/lr.toml" <<EOF
role = "lr"
version = 1
os = "linux"
name = "LiveReconcile"
level = 1
[payload]
groups = ["census-lr"]
EOF
}
l_decl() { # $1=version $2=include-lr? (yes/no)
  cat > "$LROOT/decl.toml" <<EOF
version = $1
role_store = "$LSTORE"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
EOF
  if [ "$2" = "yes" ]; then
    # Declare the group ONLY alongside its member account, so dropping lr makes
    # census-lr a true orphan (not still-required) — exercising the H1 path where
    # the group is retained BECAUSE its deferred member holds a live session.
    cat >> "$LROOT/decl.toml" <<EOF
[[group]]
name = "census-lr"
gid = 8600
[[role_account]]
role = "lr"
uid = 9050
EOF
  fi
}
l_apply() { "$CENSUS" apply --declaration "$LROOT/decl.toml" --managed "$LMAN" \
  --trust-fs --i-understand-no-rescue --sessions-file "$LROOT/sessions.json" 2>&1; }
l_store

echo "-- 19: live session defers userdel AND its group --"
# First apply with NO sessions file present → account+group created normally.
rm -f "$LROOT/sessions.json"
l_decl 1 yes
echo ":: $(l_apply)"
assert     "lr account created"             "getent passwd lr >/dev/null"
assert     "lr uid is 9050"                 "[ \"\$(id -u lr)\" = 9050 ]"
assert     "census-lr group created"        "getent group census-lr >/dev/null"
assert     "census-lr has pinned gid 8600"  "[ \"\$(getent group census-lr | cut -d: -f3)\" = 8600 ]"
assert     "managed.toml lists lr"          "grep -q 'name = \"lr\"' $LMAN"
assert     "managed.toml lists census-lr"   "grep -q 'name = \"census-lr\"' $LMAN"
# Now lr has a live session → dropping it must defer both the userdel and the group.
echo '[{"pam_user":"lr","uid":9050}]' > "$LROOT/sessions.json"
l_decl 2 no
out19="$(l_apply)"; rc19=$?; echo ":: $out19"
assert     "lr account retained"            "getent passwd lr >/dev/null"
assert     "census-lr group retained"       "getent group census-lr >/dev/null"
assert     "managed.toml still lists lr"        "grep -q 'name = \"lr\"' $LMAN"
assert     "managed.toml still lists census-lr" "grep -q 'name = \"census-lr\"' $LMAN"
assert     "apply exit code is 3 (deferred)"    "[ $rc19 -eq 3 ]"
assert     "output mentions deferred"           "echo \"\$out19\" | grep -qi deferred"

echo "-- 20: re-apply after session ends completes the delete --"
rm -f "$LROOT/sessions.json"                # file absent ⇒ no live sessions (standalone)
l_decl 3 no
out20="$(l_apply)"; rc20=$?; echo ":: $out20"
assert_not "lr account now deleted"         "getent passwd lr >/dev/null"
assert_not "census-lr group now deleted"    "getent group census-lr >/dev/null"
assert     "apply exit code is 0"           "[ $rc20 -eq 0 ]"

echo "-- 21: corrupt sessions registry + destructive plan fails closed --"
# Recreate lr + census-lr (no sessions file → normal create).
rm -f "$LROOT/sessions.json"
l_decl 4 yes
echo ":: $(l_apply)"
assert     "lr recreated"                   "getent passwd lr >/dev/null"
# Corrupt registry + a plan that DROPS lr (destructive) → hard fail-closed.
printf '%s' '[{not valid json' > "$LROOT/sessions.json"
l_decl 5 no
out21="$(l_apply)"; rc21=$?; echo ":: $out21"
assert     "corrupt registry + destructive plan fails" "[ $rc21 -ne 0 ] && [ $rc21 -ne 3 ]"
assert     "lr account untouched by fail-closed"       "getent passwd lr >/dev/null"
assert     "output names trust/registry/error"         "echo \"\$out21\" | grep -qiE 'registr|session|error|trust'"

echo "== scenario 22-24: PERMISSION CATALOG (permissions[] → expanded groups + concrete sudoers) =="
# Isolated subtree. Roles carry `permissions = [...]` (catalog ids), NOT raw
# groups/sudo_role; `census apply --catalog-dir /work/share/permissions` expands
# them per OS target. Container is debian/bookworm → resolves linux + linux-debian
# + linux-debian-12 layers. Real catalog facts asserted on (from share/permissions):
#   network-admin → groups=[netdev], sudo=[/usr/sbin/ip,/usr/bin/nmcli]
#                   (+ debian-12 delta: /usr/sbin/netplan apply)
#   log-read      → groups=[adm,systemd-journal], no sudo
CROOT="$ROOT/cat"; CSTORE="$CROOT/roles"; CMAN="$CROOT/managed.toml"
mkdir -p "$CSTORE"
# Catalog-expanded groups must pre-exist (Census manages member accounts, not the
# base groups the catalog references; useradd -G requires them present).
groupadd -f netdev; groupadd -f adm; groupadd -f systemd-journal
c_store() { # $1 = permissions array contents (e.g. '"network-admin", "log-read"')
  cat > "$CSTORE/netop.toml" <<EOF
role = "netop"
version = 1
os = "linux"
name = "NetOperator"
level = 5
[payload]
permissions = [$1]
EOF
}
c_decl() { # $1 = version
  cat > "$CROOT/decl.toml" <<EOF
version = $1
role_store = "$CSTORE"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "netop"
uid = 9060
EOF
}
c_apply() { "$CENSUS" apply --declaration "$CROOT/decl.toml" --managed "$CMAN" --trust-fs --i-understand-no-rescue --catalog-dir /work/share/permissions 2>&1; }

echo "-- 22: permission-authored role materializes catalog-expanded groups + concrete sudoers --"
c_store '"network-admin", "log-read"'
c_decl 1
echo ":: $(c_apply)"
assert     "netop account exists"               "getent passwd netop >/dev/null"
assert     "netop in group netdev (network-admin)"        "id -nG netop | grep -qw netdev"
assert     "netop in group adm (log-read)"                "id -nG netop | grep -qw adm"
assert     "netop in group systemd-journal (log-read)"    "id -nG netop | grep -qw systemd-journal"
assert     "census-netop sudoers present"       "test -f $SUDOERS/census-netop"
assert     "census-netop passes visudo"         "visudo -c -f $SUDOERS/census-netop >/dev/null 2>&1"
assert     "sudoers has concrete /usr/sbin/ip"  "grep -q '/usr/sbin/ip' $SUDOERS/census-netop"
assert     "sudoers has NOPASSWD"               "grep -q 'NOPASSWD' $SUDOERS/census-netop"
assert     "managed.toml lists netop"           "grep -q 'name = \"netop\"' $CMAN"
assert     "managed.toml records sudo_commands" "grep -q 'sudo_commands' $CMAN"

echo "-- 23: IDEMPOTENT re-apply (no changes) --"
out23="$(c_apply)"; echo ":: $out23"
assert     "second catalog apply is no-op"      "echo \"\$out23\" | grep -qiE 'no changes|plan is empty|0 mutation'"

echo "-- 24: REVOCATION rewrites sudoers (drop network-admin) --"
c_store '"log-read"'                             # network-admin removed; only log-read (no sudo)
c_decl 2                                         # bump version
echo ":: $(c_apply)"
# log-read declares no sudo, so the fragment may be removed entirely; either way the
# revoked permission's concrete command must be gone — proving permission revocation
# rewrites the concrete command set, not just group membership.
assert_not "revoked /usr/sbin/ip absent from sudoers" "test -f $SUDOERS/census-netop && grep -q '/usr/sbin/ip' $SUDOERS/census-netop"
assert     "netop account retained"             "getent passwd netop >/dev/null"

echo "== scenario 25-27: CATALOG COVERAGE (read-only audit of live privileged surface vs catalog) =="
# `census catalog coverage` enumerates the live privileged surface (sudo binaries,
# config files, systemd units, groups, capability files, setuid bits) and reports
# what the shipped catalog (/work/share/permissions) does NOT cover. Read-only —
# mutates nothing. Prefer cheap classes (group, sudo_bin) over the full setuid walk
# of / so the run stays fast and deterministic. Exit codes: 0 normal; 4 when
# --min-coverage threshold is not met; 1 on scan/catalog error or unknown --class.
COV() { "$CENSUS" catalog coverage --catalog-dir /work/share/permissions "$@" 2>&1; }

echo "-- 25: coverage runs read-only and reports a summary --"
out25="$(COV --class group,sudo_bin)"; rc25=$?; echo ":: $out25"
assert     "coverage exits 0"                   "[ $rc25 -eq 0 ]"
assert     "coverage prints a summary"          "echo \"\$out25\" | grep -qiE 'coverage|covered|%'"
assert     "coverage mentions group class"      "echo \"\$out25\" | grep -qiE 'group'"
assert     "coverage mentions sudo_bin class"   "echo \"\$out25\" | grep -qiE 'sudo_bin'"

echo "-- 26: --min-coverage 100 gate trips (real surface is never fully covered) --"
out26="$(COV --class sudo_bin --min-coverage 100)"; rc26=$?; echo ":: $out26"
assert     "below-threshold exits 4 (not error 1)" "[ $rc26 -eq 4 ]"

echo "-- 27: --json emits machine-readable output; unknown class errors --"
out27="$(COV --class group --json)"; rc27=$?; echo ":: $out27"
assert     "json coverage exits 0"              "[ $rc27 -eq 0 ]"
assert     "json starts with { or ["           "echo \"\$out27\" | grep -qE '^[[:space:]]*[\\{\\[]'"
assert     "json has overall_pct"              "echo \"\$out27\" | grep -q 'overall_pct'"
assert     "json has by_class"                 "echo \"\$out27\" | grep -q 'by_class'"
COV --class bogus >/dev/null 2>&1; rc27b=$?
assert     "unknown class rejected (non-zero)" "[ $rc27b -ne 0 ]"
out27c="$(COV --class group --min-coverage 0)"; rc27c=$?
assert     "min-coverage 0 always met (exit 0)" "[ $rc27c -eq 0 ]"

echo "== RESULT: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
