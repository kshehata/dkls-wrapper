#! /bin/bash

set -e

cargo swift package -n MobileTSS --xcframework-name mobile-tss-ffi -p ios macos

shopt -s extglob
cp -R swift/!(README*) MobileTSS/

sed -i '' 's/^open class /public final class /' MobileTSS/Sources/MobileTSS/mobile_tss.swift
sed -i '' 's/^open func /public func /' MobileTSS/Sources/MobileTSS/mobile_tss.swift

cd MobileTSS
swift test
