#!/bin/sh
# The shared library exports exactly the functions of src/api/npf.def (the
# Windows DLL's exports): an NPF_API function missing there is missing from
# libnpf.dll only, which no Linux build notices.
#   scripts/exports-check.sh libnpf.so npf.def
set -eu
so=$1
def=$2
tmp=${TMPDIR:-/tmp}/npf-exports.$$
trap 'rm -f "$tmp.so" "$tmp.def"' EXIT
nm -D --defined-only "$so" | awk '$2 == "T" { print $3 }' | sort > "$tmp.so"
sed -n 's/^[[:space:]]*\(npf_[A-Za-z0-9_]*\).*/\1/p' "$def" | sort > "$tmp.def"
if ! cmp -s "$tmp.so" "$tmp.def"; then
    echo "the library's exports (<) and npf.def (>) differ:"
    diff "$tmp.so" "$tmp.def" || true
    exit 1
fi
echo "PASS $(wc -l < "$tmp.def") exports, as npf.def"
