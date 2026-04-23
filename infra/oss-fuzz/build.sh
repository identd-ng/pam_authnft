#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# OSS-Fuzz build script for pam_authnft.
#
# Environment variables provided by the OSS-Fuzz base-builder image:
#   CC, CXX        — compiler (clang); use $CC for all C compilation
#   CFLAGS         — sanitizer + fuzzer flags set by the build infrastructure
#   LIB_FUZZING_ENGINE — -fsanitize=fuzzer or equivalent
#   OUT            — destination for final fuzz-target binaries
#   SRC            — source root; pam_authnft is at $SRC/pam_authnft
#   WORK           — scratch space for build artefacts

cd "$SRC/pam_authnft"

COMMON="-Iinclude -D_GNU_SOURCE -DFUZZ_BUILD"
PKGCF="$(pkg-config --cflags libnftables libseccomp libsystemd pam libcap)"
PKGLD="$(pkg-config --libs   libnftables libseccomp libsystemd pam libcap)"

mkdir -p "$WORK/obj"

# Compile every source file with the OSS-Fuzz-supplied CFLAGS (which include
# the chosen sanitizer) and -DFUZZ_BUILD so validate_fragment_content is
# visible to the fuzz_fragment harness.
for f in src/*.c; do
    $CC $CFLAGS $COMMON $PKGCF \
        -fPIC -c "$f" -o "$WORK/obj/$(basename "${f%.c}").o"
done

# fuzz_username: exercises util_is_valid_username and util_normalize_ip.
# Both functions accept arbitrary strings with no I/O or PAM context.
$CC $CFLAGS $COMMON $PKGCF \
    fuzz/fuzz_username.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_username"

# fuzz_fragment: exercises validate_fragment_content (verb/include scanner).
# Uses memfd_create to present fuzz bytes as a file path without disk writes.
$CC $CFLAGS $COMMON $PKGCF \
    fuzz/fuzz_fragment.c "$WORK"/obj/*.o \
    $LIB_FUZZING_ENGINE $PKGLD \
    -o "$OUT/fuzz_fragment"
