#! /bin/bash

set -e

cargo swift package -n DKLSLib --xcframework-name dkls-ffi -p ios macos

shopt -s extglob
cp -R swift/!(README*) DKLSLib/

sed -i '' 's/^open class /public final class /' DKLSLib/Sources/DKLSLib/dkls.swift
sed -i '' 's/^open func /public func /' DKLSLib/Sources/DKLSLib/dkls.swift

cd DKLSLib
swift test
