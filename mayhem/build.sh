#!/usr/bin/env bash
#
# mayhem/build.sh — build hydra's fuzz harnesses, their standalone reproducer and the test oracle.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; re-runnable and offline.
# hydra's own ./configure rewrites tracked files (Makefile, Makefile.in), so the sources are compiled
# directly into gitignored build dirs under mayhem/ with the defines hydra's Makefile would pick for
# the libraries this image has (OpenSSL, PCRE2, zlib).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"

DEFS="-D_GNU_SOURCE -fcommon -w -DLIBOPENSSL -DHAVE_PCRE -DHAVE_MATH_H -DHAVE_ZLIB"
LIBS="-lssl -lcrypto -lpcre2-8 -lz -lm"
SRCS="$(ls hydra-*.c | grep -v "^hydra-pcnfs.c$") bfg.c crc32.c d3des.c hmacmd5.c ntlm.c sasl.c"

# build_objs <dir> <compiler> <flags...>: compile every hydra source (and hydra.c with its main
# renamed, so the harnesses can link its globals and restore reader) into <dir>.
build_objs() {
  local dir="$1" cc="$2"; shift 2
  mkdir -p "$dir"
  printf '%s\n' $SRCS | xargs -P "$MAYHEM_JOBS" -I{} "$cc" "$@" $DEFS -I. -c {} -o "$dir/{}.o"
  "$cc" "$@" $DEFS -I. -Dmain=hydra_main -c hydra.c -o "$dir/hydra.c.o"
  # hydra-pcnfs.c casts a char buffer to a struct (UBSan "alignment"; harmless on x86): that one
  # check is off for that file only.
  "$cc" "$@" -fno-sanitize=alignment $DEFS -I. -c hydra-pcnfs.c -o "$dir/hydra-pcnfs.c.o"
}

# 1) libFuzzer flavour: the project compiled with sanitizers + sancov, linked into fuzz_helpers.
build_objs mayhem/out-fuzz "$CC" -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/out-fuzz/lsan_off.o
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $DEFS -I. -c mayhem/fuzz_helpers.c -o mayhem/out-fuzz/fuzz_helpers.o
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/out-fuzz/standalone_main.o
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE mayhem/out-fuzz/fuzz_helpers.o mayhem/out-fuzz/lsan_off.o \
    mayhem/out-fuzz/hydra*.o mayhem/out-fuzz/{bfg,crc32,d3des,hmacmd5,ntlm,sasl}.c.o $LIBS -o "$SRC/fuzz_helpers"
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS mayhem/out-fuzz/standalone_main.o mayhem/out-fuzz/fuzz_helpers.o mayhem/out-fuzz/lsan_off.o \
    mayhem/out-fuzz/hydra*.o mayhem/out-fuzz/{bfg,crc32,d3des,hmacmd5,ntlm,sasl}.c.o $LIBS -o "$SRC/fuzz_helpers-standalone"

# 2) AFL flavour (these targets exit(), so each input is its own process): afl-clang-fast for the
# project and the harnesses alike.
build_objs mayhem/out-afl afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/out-afl/lsan_off.o
for t in fuzz_service fuzz_restore; do
  afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $DEFS -I. -c "mayhem/$t.c" -o "mayhem/out-afl/$t.o"
  afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS "mayhem/out-afl/$t.o" mayhem/out-afl/lsan_off.o \
      mayhem/out-afl/hydra*.o mayhem/out-afl/{bfg,crc32,d3des,hmacmd5,ntlm,sasl}.c.o $LIBS -o "$SRC/$t"
done
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -D_GNU_SOURCE -w pw-inspector.c mayhem/out-afl/lsan_off.o -o "$SRC/pw_inspector"

# 3) The test oracle: the same sources with the project's normal flags (no sanitizers, no sancov).
build_objs mayhem/out-normal "$CC" -O2 $COVERAGE_FLAGS
"$CC" -O2 $COVERAGE_FLAGS $DEFS -I. -c mayhem/kat.c -o mayhem/out-normal/kat.o
"$CC" -O2 $COVERAGE_FLAGS mayhem/out-normal/kat.o mayhem/out-normal/hydra*.o \
    mayhem/out-normal/{bfg,crc32,d3des,hmacmd5,ntlm,sasl}.c.o $LIBS -o mayhem/out-normal/kat
"$CC" -O2 $COVERAGE_FLAGS -D_GNU_SOURCE -w pw-inspector.c -o mayhem/out-normal/pw-inspector
