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

echo "== RESULT: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
