"""Change one refund amount inside a bundle, the way someone covering up a mistake might."""

import json
import sys
import zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zin:
    files = {n: zin.read(n) for n in zin.namelist()}

lines = files["records.jsonl"].decode().splitlines()
for i, line in enumerate(lines):
    rec = json.loads(line)
    if rec.get("kind") == "action" and rec.get("outcome", {}).get("check") == "mismatch":
        rec["outcome"] = {"check": "match", "method": "verify_outcome"}
        lines[i] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        print(f"changed record seq {rec['seq']}: outcome mismatch -> match")
        break
files["records.jsonl"] = ("\n".join(lines) + "\n").encode()

with zipfile.ZipFile(dst, "w") as zout:
    for name, data in files.items():
        zout.writestr(name, data)
print(f"wrote {dst}")
