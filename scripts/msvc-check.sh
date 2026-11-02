#!/bin/sh
# libnpf with MSVC (cl.exe), from WSL: the working tree copied to a Windows
# directory, built there with CMake and Ninja in the Visual Studio
# environment (/W4 /WX: a warning fails it), then tests/msvc/smoke.c built
# against npf.dll and run, and tests/msvc/loop_hup.c (the event loop on
# WSAPoll) and tests/msvc/file_acl.c (a secret's permissions) against npf_common.
#   scripts/msvc-check.sh            (in libnpf's tree)
# NPF_VCVARS: the vcvars64.bat to use (default: the newest Visual Studio with
# the C++ tools, by vswhere); NPF_MSVC_DIR: the Windows directory (default
# %USERPROFILE%\npf-msvc). Exit 0 passed, 1 failed, 2 no MSVC here.
set -u
lib=$(cd "$(dirname "$0")/.." && pwd)
command -v cmd.exe > /dev/null 2>&1 && command -v wslpath > /dev/null 2>&1 \
    || { echo "msvc-check: not WSL (no cmd.exe)"; exit 2; }
vcvars=${NPF_VCVARS:-}
if [ -z "$vcvars" ]; then
    vswhere="/mnt/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
    [ -x "$vswhere" ] || { echo "msvc-check: no Visual Studio (vswhere)"; exit 2; }
    vs=$("$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
         -property installationPath | tr -d '\r')
    [ -n "$vs" ] || { echo "msvc-check: no Visual Studio with the C++ tools"; exit 2; }
    vcvars="$vs\\VC\\Auxiliary\\Build\\vcvars64.bat"
fi
win=${NPF_MSVC_DIR:-$(cd /mnt/c && cmd.exe /c 'echo %USERPROFILE%' | tr -d '\r')\\npf-msvc}
dst=$(wslpath -u "$win")
mkdir -p "$dst" || exit 1
rm -rf "${dst:?}/src" "${dst:?}/build"
mkdir -p "$dst/src"
git -C "$lib" ls-files -co --exclude-standard -z | (cd "$lib" && tar --null -T - -cf -) | tar -x -C "$dst/src" || exit 1
cat > "$dst/check.bat" <<EOF
@echo off
chcp 65001 > nul
call "$vcvars" > nul || exit /b 1
cd /d "$win"
cmake -G Ninja -S src -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_C_FLAGS=/WX || exit /b 1
cmake --build build -- -k 0 || exit /b 1
cl /nologo /W4 /WX /utf-8 /Isrc\\include src\\tests\\msvc\\smoke.c /Febuild\\smoke.exe /Fobuild\\ build\\npf.lib || exit /b 1
copy /y build\\bin\\npf.dll build\\ > nul
dumpbin /nologo /exports build\\bin\\npf.dll > build\\exports.txt || exit /b 1
build\\smoke.exe || exit /b 1
cl /nologo /MD /W4 /WX /utf-8 /Isrc\\include src\\tests\\msvc\\loop_hup.c /Febuild\\loop_hup.exe /Fobuild\\ build\\npf_common.lib build\\monocypher.lib build\\npf_mbedtls.lib build\\anliu.lib ws2_32.lib iphlpapi.lib bcrypt.lib winmm.lib advapi32.lib || exit /b 1
build\\loop_hup.exe || exit /b 1
cl /nologo /MD /W4 /WX /utf-8 /Isrc\\include src\\tests\\msvc\\file_acl.c /Febuild\\file_acl.exe /Fobuild\\ build\\npf_common.lib build\\monocypher.lib build\\npf_mbedtls.lib build\\anliu.lib ws2_32.lib iphlpapi.lib bcrypt.lib winmm.lib advapi32.lib || exit /b 1
build\\file_acl.exe
EOF
printf 'msvc-check: %s, in %s\n' "$vcvars" "$win"
(cd "$dst" && cmd.exe /c check.bat) > "$dst/check.log" 2>&1
rc=$?
grep -aE "warning C|error C|error LNK|PASS|FAIL|SKIP|smoke:" "$dst/check.log" | sed 's/\r$//'
[ $rc -eq 0 ] || { printf 'msvc-check: failed (log: %s\\check.log)\n' "$win"; exit 1; }
def=$(awk '/^EXPORTS/{e=1;next} e&&NF{print $1}' "$lib/src/api/npf.def" | sort)
dll=$(tr -d '\r' < "$dst/build/exports.txt" | awk '$1~/^[0-9]+$/&&$4~/^npf_/{print $4}' | sort)
[ "$def" = "$dll" ] || { echo "msvc-check: npf.dll's exports differ from npf.def:"; printf '%s\n' "$def" > "$dst/def.txt"
    printf '%s\n' "$dll" | diff "$dst/def.txt" -; exit 1; }
echo "msvc-check: passed ($(printf '%s\n' "$dll" | wc -l) exports, as npf.def)"
