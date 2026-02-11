// The Swift Programming Language
// https://docs.swift.org/swift-book
import Foundation

// Extensions to add Swift protocols to the FFI types

// Note: Decodable cannot be implemented in an extension for non-final classes.
// These classes are defined as `open` in `dkls.swift`.
// To enable Decodable, either make them `final` in `dkls.swift` or implement `init(from:)` in `dkls.swift`.
// We implement Encodable here.

// MARK: - InstanceId
extension InstanceId: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: InstanceId, rhs: InstanceId) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: Data {
        return self.toBytes()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try InstanceId.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - Keyshare
extension Keyshare: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: Keyshare, rhs: Keyshare) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: NodeVerifyingKey {
        return self.vk()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try Keyshare.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - Signature
extension Signature: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: Signature, rhs: Signature) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: Data {
        return self.toBytes()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try Signature.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - NodeVerifyingKey
extension NodeVerifyingKey: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: NodeVerifyingKey, rhs: NodeVerifyingKey) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: Data {
        return self.toBytes()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try NodeVerifyingKey.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - DeviceInfo
extension DeviceInfo: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: DeviceInfo, rhs: DeviceInfo) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: NodeVerifyingKey {
        return self.vk()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try DeviceInfo.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - DeviceLocalData
extension DeviceLocalData: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: DeviceLocalData, rhs: DeviceLocalData) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: NodeVerifyingKey {
        return self.myDevice().vk()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try DeviceLocalData.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}

// MARK: - QrData
extension QrData: Equatable, Hashable, Identifiable, Codable {
    public static func == (lhs: QrData, rhs: QrData) -> Bool {
        return lhs.equals(other: rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ffiHash())
    }

    public var id: Data {
        return self.toBytes()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.toBytes())
    }

    public convenience init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let bytes = try container.decode(Data.self)
        let temp = try QrData.fromBytes(bytes: bytes)
        self.init(unsafeFromHandle: temp.uniffiCloneHandle())
    }
}
