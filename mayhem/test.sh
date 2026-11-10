#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for hydra's helper library and the pw-inspector tool, run from
# the NORMAL-flags binaries that mayhem/build.sh built (mayhem/out-normal/kat, mayhem/out-normal/pw-inspector).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT=mayhem/out-normal/kat
PWI=mayhem/out-normal/pw-inspector
for b in "$KAT" "$PWI"; do
  [ -x "$b" ] || { echo "missing $b: mayhem/build.sh did not produce it" >&2; emit_ctrf "hydra-kat" 0 1 0; exit 1; }
done

passed=0
failed=0

# kat prints "ok   <name>" / "FAIL <name>" per known-answer check and exits non-zero on any failure
out=$("$KAT" 2>&1)
rc=$?
echo "$out"
p=$(printf '%s\n' "$out" | grep -c '^ok  ')
f=$(printf '%s\n' "$out" | grep -c '^FAIL ')
passed=$((passed + p))
failed=$((failed + f))
if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then failed=$((failed + 1)); fi
if [ "$p" -lt 16 ]; then failed=$((failed + 1)); fi # a kat run that ran fewer checks than it has is a no-op

# pw-inspector: input -> exact filtered output and exit status (= number of passwords kept)
res=$(printf 'abc\nabcd1\nABCdef12\nxyz\n' | "$PWI" -m 5 -c 2 -l -u -n)
rc=$?
if [ "$res" = $'abcd1\nABCdef12' ] && [ "$rc" -eq 2 ]; then passed=$((passed + 1)); else echo "FAIL: pw-inspector -m 5 -c 2: got '$res' rc=$rc"; failed=$((failed + 1)); fi

res=$(printf 'abc\nabcd1\nABCdef12\nxyz\n' | "$PWI" -M 4 -l)
rc=$?
if [ "$res" = $'abc\nxyz' ] && [ "$rc" -eq 2 ]; then passed=$((passed + 1)); else echo "FAIL: pw-inspector -M 4: got '$res' rc=$rc"; failed=$((failed + 1)); fi

emit_ctrf "hydra-kat" "$passed" "$failed" 0
