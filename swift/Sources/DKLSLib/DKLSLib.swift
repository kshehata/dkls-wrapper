// The Swift Programming Language
// https://docs.swift.org/swift-book

func swift_add(left: Int, right: Int) -> Int {
    return Int(rustAdd(left: UInt64(left), right: UInt64(right)))
}
