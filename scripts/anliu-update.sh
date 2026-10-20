#!/bin/sh
# Update the vendored AnLiu copy (roadmap 1.7): copy the upstream files,
# apply NPF's patches, record what was copied.
#
#   scripts/anliu-update.sh [UPSTREAM_DIR] [REV]
#
# UPSTREAM_DIR  the public repository's checkout (default ../AnLiu_github);
#               it is only read, never changed
# REV           a commit there; default: its working tree as it is
#
# Patches: third_party/anliu/patches/*.patch, applied in name order
# with patch -p1 inside the copy (paths a/anliu.c, b/anliu.c). A patch that
# no longer applies stops the update: the copy is left as upstream has it,
# fix or drop the patch and run again. Then build and run the tests.
set -eu
cd "$(dirname "$0")/.."
UP=${1:-../AnLiu_github}
REV=${2:-}
DST=third_party/anliu
[ -f "$UP/anliu.c" ] || { echo "no AnLiu checkout at $UP"; exit 2; }

# 1. the upstream files
if [ -n "$REV" ]; then
    for f in anliu.c anliu.h LICENSE; do git -C "$UP" show "$REV:$f" > "$DST/$f"; done
    from=$(git -C "$UP" rev-parse "$REV")
else
    for f in anliu.c anliu.h LICENSE; do cp "$UP/$f" "$DST/$f"; done
    from=$(git -C "$UP" rev-parse HEAD)
    if [ -n "$(git -C "$UP" status --porcelain -- anliu.c anliu.h)" ]; then
        from="$from + working tree of $(date +%F)"
    fi
fi
hc=$(sha256sum < "$DST/anliu.c" | cut -d' ' -f1)
hh=$(sha256sum < "$DST/anliu.h" | cut -d' ' -f1)

# 2. NPF's patches
applied=""
for p in "$DST"/patches/*.patch; do
    [ -f "$p" ] || continue
    if ! patch -p1 -d "$DST" --forward --quiet < "$p"; then
        echo "patch $(basename "$p") does not apply to $from; the copy is upstream's as is"
        exit 1
    fi
    applied="${applied:+$applied }$(basename "$p")"
done

# 3. the record (UPSTREAM.md table rows)
python3 - "$DST/UPSTREAM.md" "$from" "$hc" "$hh" "$applied" <<'PY'
import re, sys, datetime
path, src, hc, hh, applied = sys.argv[1:]
s = open(path).read()
rows = {
    "上游提交": "`%s`" % src,
    "复制日期": datetime.date.today().isoformat(),
    "`anliu.c` SHA-256": "`%s`（上游文件，打补丁前）" % hc,
    "`anliu.h` SHA-256": "`%s`（上游文件，打补丁前）" % hh,
    "补丁": applied or "无",
}
for k, v in rows.items():
    pat = re.compile(r"^\| %s \|.*\|$" % re.escape(k), re.M)
    line = "| %s | %s |" % (k, v)
    if pat.search(s):
        s = pat.sub(lambda m: line, s, count=1)
    else:   # a new row after the last one of the table
        s = re.sub(r"(\n\|[^\n]*\|\n)(?!\|)", lambda m: m.group(1) + line + "\n", s, count=1)
open(path, "w").write(s)
PY
echo "AnLiu from $from"
echo "  anliu.c $hc"
echo "  anliu.h $hh"
echo "  patches: ${applied:-none}"
echo "now: build and run the tests (ctest)"
