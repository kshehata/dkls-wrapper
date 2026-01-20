#!/bin/bash
set -euo pipefail

PACKAGE=dkls

KOTLIN_DIR=kotlin
KOTLIN_OUT_DIR="$KOTLIN_DIR/src/main/kotlin"
NATIVE_OUT_DIR="$KOTLIN_DIR/src/main/resources/native"

echo "==> Building Rust shared library for host"
cd rust
cargo build --release
cd ..

# Pick library name by platform
UNAME="$(uname -s)"
case "$UNAME" in
  MINGW*|MSYS*|CYGWIN*)
    LIB_FILE="${PACKAGE}.dll"
    ;;
  Darwin*)
    LIB_FILE="lib${PACKAGE}.dylib"
    ;;
  Linux*)
    LIB_FILE="lib${PACKAGE}.so"
    ;;
  *)
    echo "Unsupported OS from uname: $UNAME" >&2
    exit 1
    ;;
esac

# You must point this to the actual produced file on your OS.
# Common Linux output: rust/target/release/libdkls.so
LIB_PATH="rust/target/release/$LIB_FILE"

echo "==> Copying native library into Kotlin resources: $LIB_PATH"
mkdir -p "$NATIVE_OUT_DIR"
cp -f "$LIB_PATH" "$NATIVE_OUT_DIR/"

echo "==> Cleaning old generated Kotlin bindings"
rm -rf "$KOTLIN_OUT_DIR/uniffi" 2>/dev/null || true

echo "==> Generating Kotlin bindings with uniffi-bindgen"
cd rust
uniffi-bindgen generate \
  --library "../$LIB_PATH" \
  --language kotlin \
  --out-dir "../$KOTLIN_OUT_DIR"
cd ..

echo "==> Done"
echo "Kotlin bindings: $KOTLIN_OUT_DIR"
echo "Native library: $NATIVE_OUT_DIR/$LIB_FILE"
