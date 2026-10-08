#!/usr/bin/env bash
# Negative controls. Each mutation must FAIL the named check. A control that
# passes means the check was not asking the question.
set -uo pipefail
cd "$(dirname "$0")"

declare -a RESULT

run() {
  local name=$1 check=$2
  if nix build --no-link ".#checks.x86_64-linux.$check" > /tmp/nc.log 2>&1; then
    RESULT+=("BROKEN-CONTROL $name: $check still passed")
  else
    RESULT+=("ok $name: $check failed as it must")
  fi
}

# From HEAD, NOT from the index. An earlier version staged each mutation and
# then checked out the index, so every revert restored the PREVIOUS mutation and
# the poison accumulated into a commit. Tracked modifications are visible to a
# dirty flake build without staging, so nothing here stages anything.
revert() { git checkout HEAD -- flake.nix portero; }

fingerprint() { git hash-object flake.nix portero/*.py portero/*.sh | sha256sum; }
BEFORE=$(fingerprint)

# 1. the shipped tree loses a module: packaging must fail, unit suites must not
sed -i '\|cp ${./portero/pending.py}|d' flake.nix
run "module missing from porteroSrc" packaging
if nix build --no-link .#checks.x86_64-linux.mint > /dev/null 2>&1; then
  RESULT+=("ok   and the mint unit suite stayed green, which is the gap")
else
  RESULT+=("BROKEN-CONTROL the unit suite also failed, so it is not the gap")
fi
revert

# 2. the public intake half gains a mailer
sed -i 's/^from budget import Budget$/from budget import Budget\nimport mailer/' portero/intake.py
run "intake imports the mailer" packaging
revert

# 3. the rate limit goes back to one whole-endpoint budget that counts GETs
sed -i 's/PORTERO_GET_FLOOD", "600"/PORTERO_GET_FLOOD", "20"/' portero/redeem.py
sed -i 's/FLOOD\[method\]/FLOOD["GET"]/' portero/redeem.py
run "GETs spend the POST budget again" redeem
revert

# 4. the cap trigger stops being created
sed -i 's|^CREATE TRIGGER intake_cap BEFORE INSERT ON intake$|SELECT 1;\n-- disabled|' portero/pending.py
python3 - <<'PY'
import pathlib
p = pathlib.Path("portero/pending.py")
s = p.read_text()
start = s.index("def cap_trigger(cap):")
end = s.index("def connect(path, cap):")
s = s[:start] + 'def cap_trigger(cap):\n    return "DROP TRIGGER IF EXISTS intake_cap;"\n\n\n' + s[end:]
p.write_text(s)
PY
run "no cap on the intake table" pending
run "  and the endpoint check notices too" intake
revert

# 5. mint stops authenticating the row before mailing it
python3 - <<'PY'
import pathlib
p = pathlib.Path("portero/mint.py")
s = p.read_text()
s = s.replace("    if not invites.decision_ok(SIGNING_KEY, mac_fields(row), row[\"mac\"]):",
              "    if False:")
p.write_text(s)
PY
run "send trusts a rewritten row" mint
revert

# 6. a duplicate address answers differently from a new one
python3 - <<'PY'
import pathlib
p = pathlib.Path("portero/intake.py")
s = p.read_text()
s = s.replace("""    if accepted and EMAIL_RE.fullmatch(email) and len(email) <= MAX_EMAIL:""",
              """    if not EMAIL_RE.fullmatch(email):
        return page("No", "<p>That is not an email address.</p>", status=400)
    if accepted and EMAIL_RE.fullmatch(email) and len(email) <= MAX_EMAIL:""")
p.write_text(s)
PY
run "malformed address is distinguishable" intake
revert

# 7. the public half grows a read path
python3 - <<'PY'
import pathlib
p = pathlib.Path("portero/intake.py")
s = p.read_text()
s = s.replace('''@app.get("/intake")
def form():''', '''@app.get("/intake/all")
def leak():
    rows = STORE._db.execute("SELECT email FROM intake").fetchall()
    return Response("\\n".join(r[0] for r in rows), mimetype="text/plain")


@app.get("/intake")
def form():''')
p.write_text(s)
PY
run "the public half can read the table back" intake
revert

if [ "$(fingerprint)" = "$BEFORE" ]; then
  RESULT+=("ok the tree is byte-identical to HEAD after every revert")
else
  RESULT+=("BROKEN-CONTROL the tree did not come back: a mutation survived")
fi

printf '%s\n' "${RESULT[@]}"
grep -q BROKEN-CONTROL <(printf '%s\n' "${RESULT[@]}") && exit 1
exit 0
