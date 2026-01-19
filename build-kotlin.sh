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

# You must point this to the actual produced file on your OS.
# Common Linux output: rust/target/release/libdkls.so
LIB_PATH="rust/target/release/lib${PACKAGE}.so"

echo "==> Copying native library into Kotlin resources"
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
echo "Native library:  $NATIVE_OUT_DIR"
