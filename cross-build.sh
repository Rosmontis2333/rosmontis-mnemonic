#!/bin/sh
set -eu
cd "$(dirname "$0")"
ZIG=${ZIG:-zig}
DEST=${DEST:-dist}
mkdir -p "$DEST"
TARGET=$1
MAIN=main.c
NAME=rosmontis-mnemonic
if [ "${2:-app}" = selftest ]; then MAIN=tests/selftest.c; NAME=rosmontis-selftest; fi
case "$TARGET" in
  *windows*) PLATFORM=platform_windows.c; EXT=.exe; THREADS=-lbcrypt ;;
  *linux*) PLATFORM=platform_posix.c; EXT=; THREADS=-pthread ;;
  *) exit 2 ;;
esac
"$ZIG" cc -target "$TARGET" -O2 -DROSMONTIS_PROGRESS -DSECP256K1_STATIC -I . -I vendor -I vendor/secp256k1-0.8.0/include -I argon2/include -I argon2/src "$MAIN" sha2.c wallet.c keccak.c vendor/ripemd160.c vendor/secp256k1-0.8.0/src/secp256k1.c vendor/secp256k1-0.8.0/src/precomputed_ecmult.c vendor/secp256k1-0.8.0/src/precomputed_ecmult_gen.c "$PLATFORM" argon2/src/argon2.c argon2/src/core.c argon2/src/encoding.c argon2/src/ref.c argon2/src/thread.c argon2/src/blake2/blake2b.c $THREADS -o "$DEST/$NAME-$TARGET$EXT"
