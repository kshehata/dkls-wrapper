#! /bin/bash

set -e

# TODO: pass these in from build env
PACKAGE=dkls
SWIFT_PACKAGE=DKLSLib

SIM_TARGETS=(
    aarch64-apple-ios-sim
    x86_64-apple-ios
)
SIM_UNI_TARGET="universal-ios-sim"
MAC_TARGETS=(
    aarch64-apple-darwin
    x86_64-apple-darwin
)
MAC_UNI_TARGET="universal-darwin"
IOS_TARGET="aarch64-apple-ios"

ALL_TARGETS=("${SIM_TARGETS[@]}" "${MAC_TARGETS[@]}" "${IOS_TARGET}")
ALL_UNI_TARGETS=("${SIM_UNI_TARGET}" "${MAC_UNI_TARGET}" "${IOS_TARGET}")

cd rust

# Make sure we have rust for all the targets
for t in ${ALL_TARGETS[@]}; do
    rustup target add "$t"
done

TARGET_STR=""
for t in ${ALL_TARGETS[@]}; do
    TARGET_STR="$TARGET_STR --target $t"
done
echo "Building libraries"
cargo build --lib --release $TARGET_STR


make_fat_lib() {
    local universal_name=$1
    shift
    TARGET_STR=""
    for t in $@; do
        TARGET_STR="$TARGET_STR target/$t/release/lib$PACKAGE.a"
    done
    echo "Making fat lib for $universal_name"
    echo $TARGET_STR
    rm -rf target/$universal_name
    mkdir -p target/$universal_name/release/
    lipo -create $TARGET_STR -output target/$universal_name/release/lib$PACKAGE.a
}

make_fat_lib "$SIM_UNI_TARGET" "${SIM_TARGETS[@]}"
make_fat_lib "$MAC_UNI_TARGET" "${MAC_TARGETS[@]}"

LIBS=""
for t in ${ALL_UNI_TARGETS[@]}; do
    LIBS="$LIBS -library target/$t/release/lib$PACKAGE.a -headers target/xcframework_headers"
done

echo "Generating Swift bindings"
# Only need to do this for the first target.
# You have to give it the library file and the output location.
# Then tell it explicitly to generate all 3 outputs,
# and the output names.
rm -rf target/xcframework_headers
cargo run --bin uniffi-bindgen-swift -- \
    target/${IOS_TARGET}/release/lib$PACKAGE.a \
    target/xcframework_headers \
    --swift-sources --headers --modulemap \
    --module-name "${PACKAGE}FFI" \
    --modulemap-filename module.modulemap

# HACK: make Swift classes final
sed -i '' 's/^open class /public final class /' target/xcframework_headers/*.swift
sed -i '' 's/^open func /public func /' target/xcframework_headers/*.swift

# Move the swift files to the right place
mv target/xcframework_headers/*.swift ../swift/Sources/$SWIFT_PACKAGE/

echo "Generating XCFramework"
FRAMEWORK_PATH=../swift/lib$PACKAGE-rs.xcframework
rm -rf $FRAMEWORK_PATH
xcodebuild -create-xcframework $LIBS -output $FRAMEWORK_PATH

cd ../swift
swift build
swift test
cd ..
