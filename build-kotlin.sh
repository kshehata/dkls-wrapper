#! /bin/bash

set -e

# TODO: pass these in from build env

# Name of the Rust crate / resulting library (libdkls.so)
PACKAGE=dkls

# Android module where generated Kotlin + .so will live
ANDROID_MODULE=kotlin

# Where to put generated Kotlin sources
KOTLIN_OUT_DIR=$ANDROID_MODULE/src/main/java

# Where to put Android .so libraries (per-ABI subdirs)
JNILIBS_OUT_DIR=$ANDROID_MODULE/src/main/jniLibs

# Android Rust targets (for cargo-ndk)
ANDROID_TARGETS=(
  aarch64-linux-android    # arm64-v8a
  armv7-linux-androideabi  # armeabi-v7a
  x86_64-linux-android     # x86_64
  i686-linux-android       # x86
)

echo "==> Ensuring Rust Android targets are installed"
for t in "${ANDROID_TARGETS[@]}"; do
  rustup target add "$t"
done

echo "==> Building Rust library for Android with cargo-ndk"
cd rust

# Make sure cargo-ndk is installed:
#   cargo install cargo-ndk
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

echo "==> Generating Kotlin bindings with uniffi-bindgen (proc-macro mode)"
# We point uniffi-bindgen at one of the built Android libraries.
# Any of the ABI .so files is fine; uniffi just needs metadata.
LIB_PATH="../$JNILIBS_OUT_DIR/arm64-v8a/lib${PACKAGE}.so"

# Make sure uniffi_bindgen is installed:
#   cargo install uniffi
#   uniffi-bindgen --version
cd rust  # cd into `rust/` where Cargo.toml exists
uniffi-bindgen generate \
  --library "$LIB_PATH" \
  --language kotlin \
  --out-dir "../$KOTLIN_OUT_DIR"

echo "==> Done."
echo "Kotlin bindings generated into: $KOTLIN_OUT_DIR"
echo "Android .so libraries generated into: $JNILIBS_OUT_DIR"
echo
echo "Next steps:"
echo "  - Add the $ANDROID_MODULE module as a dependency of your app."
echo "  - Call System.loadLibrary(\"$PACKAGE\") before using the generated Kotlin classes."
