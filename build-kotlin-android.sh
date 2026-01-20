#!/bin/bash
set -euo pipefail

# Name of the Rust crate / resulting library (libdkls.so)
PACKAGE=dkls

# Android module where generated Kotlin + .so will live
ANDROID_MODULE=kotlin

# Where to put generated Kotlin sources
KOTLIN_OUT_DIR="$ANDROID_MODULE/src/main/java"

# Where to put Android .so libraries (per-ABI subdirs)
JNILIBS_OUT_DIR="$ANDROID_MODULE/src/main/jniLibs"

# ABIs we build (must match the cargo-ndk -t args below)
ANDROID_ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

echo "==> Ensuring Rust Android targets are installed"
RUST_TARGETS=(aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android)
for t in "${RUST_TARGETS[@]}"; do
  rustup target add "$t"
done

echo "==> Building Rust library for Android with cargo-ndk"
cd rust
cargo ndk \
  -t armeabi-v7a \
  -t arm64-v8a \
  -t x86 \
  -t x86_64 \
  -o "../$JNILIBS_OUT_DIR" \
  build --release
cd ..

echo "==> Cleaning old generated Kotlin bindings"
rm -rf "$KOTLIN_OUT_DIR/uniffi" 2>/dev/null || true

echo "==> Locating an Android .so for bindgen metadata"
LIB_PATH=""
for abi in "${ANDROID_ABIS[@]}"; do
  candidate="$JNILIBS_OUT_DIR/$abi/lib${PACKAGE}.so"
  if [[ -f "$candidate" ]]; then
    LIB_PATH="$candidate"
    break
  fi
done

if [[ -z "$LIB_PATH" ]]; then
  echo "ERROR: Could not find any built lib${PACKAGE}.so under $JNILIBS_OUT_DIR" >&2
  exit 1
fi

echo "==> Generating Kotlin bindings with uniffi-bindgen"
cd rust
uniffi-bindgen generate \
  --library "../$LIB_PATH" \
  --language kotlin \
  --out-dir "../$KOTLIN_OUT_DIR"
cd ..

echo "==> Done."
echo "Kotlin bindings generated into: $KOTLIN_OUT_DIR"
echo "Android .so libraries generated into: $JNILIBS_OUT_DIR"
