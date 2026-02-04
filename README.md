# DKLS Wrapper Library

This library provides a cross-platform wrapper for the DKLS23 (Doerner-Kooder-Lazar-Shelat) threshold signature scheme, enabling Distributed Key Generation (DKG) and Threshold Signing on mobile and desktop platforms via Rust and UniFFI.

## Overview

The library exposes a high-level API to perform:
1.  **Distributed Key Generation (DKG)**: Securely generate a shared private key across multiple devices without any single device knowing the full key.
2.  **Threshold Signing**: Sign messages using a threshold of devices (t-of-n), producing a standard signature verifiable by the corresponding public key.

It is designed to be agnostic to the network transport layer. You must provide a bridge (implementation of `NetworkInterface`) to handle communication between devices (e.g., via MQTT, Bluetooth, WebSocket, or a relay server).

## Prerequisites

- **Rust**: Latest stable toolchain.
- **Swift/iOS**: Xcode (for macOS/iOS development).
- **Kotlin/Android**: JDK and Android SDK (for Android development).
- **UniFFI**: Used for generating bindings.

## Integration

### Rust
Add the library to your `Cargo.toml`:
```toml
[dependencies]
dkls-wrapper = { path = "../dkls-wrapper" }
```

### Swift
Include the local package in your `Package.swift` or Xcode project. The package definition is located in the root directory.

## Core Concepts

### Network Interface
The library does not handle networking directly. Instead, you must implement the `NetworkInterface` trait (Rust) or protocol (Swift/Kotlin). This interface allows the library to send and receive protocol messages.

See `rust/src/net.rs` for the definition:
```rust
// Rust Trait
pub trait NetworkInterface: Send + Sync {
    async fn send(&self, data: Vec<u8>) -> Result<(), GeneralError>;
    async fn receive(&self) -> Result<Vec<u8>, GeneralError>;
}
```

In Swift, you would implement the `NetworkInterface` protocol:
```swift
class MyNetworkBridge: NetworkInterface {
    func send(data: Data) async throws {
        // Implementation to send data to the peer
    }
    
    func receive() async throws -> Data {
        // Implementation to receive data from the peer
    }
}
```

## Usage Guide

### 1. Distributed Key Generation (DKG)

The DKG process involves connecting 2 or more devices to generate shares of a distributed key.

**Step 1: Initialize the Node**
Create a `DKGNode` with separate interfaces for setup (reliable, low-bandwidth) and execution (high-bandwidth).

```swift
let node = DKGNode(
    name: "Device A",
    instance: InstanceId(), // Shared Session ID
    threshold: 3,
    setupIf: setupBridge,   // Implements NetworkInterface
    dkgIf: dkgBridge        // Implements NetworkInterface
)
```

**Step 2: Setup Phase**
Before the DKG runs, devices need to discover each other. This is handled via `DKGSetupMessage`.
- Use `node.getQr()` to generate initialization data.
- Use `node.fromQr()` or `node.tryFromQrBytes()` on other devices to pair them.
- Register a setup listener to track connected devices:
```swift
class SetupListener: DKGSetupChangeListener {
    func onSetupChanged(setupMsg: DKGSetupMessage) {
        print("Connected devices: \(setupMsg.devices.count)")
    }
}
node.addSetupChangeListener(listener: SetupListener())
```

**Step 3: Start DKG**
Once all devices are connected (setup listener confirms), start the process:
```swift
try await node.startDkg()
```
This will trigger the protocol. Ensure your `dkgIf` network bridge is active and routing messages.

**Step 4: Get Result**
Wait for the process to complete and retrieve the `DeviceLocalData`.
```swift
let localData = try dkgNode.getLocalData()
// Save this data securely! It contains your secret key, keyshare, and device list.
// You can serialize it to bytes or a string for storage.
let bytes = localData.toBytes()
```

### 2. Threshold Signing

To sign a message, you need the `Keyshare` from the DKG step.

**Step 1: Create Sign Node**
Initialize the `SignNode` with the `DeviceLocalData` obtained from the DKG step.

```swift
let signNode = SignNode(ctx: localData)
```

**Step 2: Sign (Initiator)**
To start a signing session for a message:
```swift
let signature = try await signNode.doSignString(
    string: "Hello World", 
    netIf: myNetworkBridge
)
```

**Step 3: Join (Responder)**
To join a signing session initiated by another device (after receiving a `SignRequest` via your network):
```swift
// You must listen for "SignRequest" messages on your network.
// When one is received, parse it and join:
let signature = try await signNode.doJoinRequest(
    req: receivedSignRequest, 
    netIf: myNetworkBridge
)
```

## Building the Bindings

Scripts are provided to build the platform-specific bindings:

- **Swift**: `./build-swift.sh`
- **Kotlin**: `./build-kotlin.sh`

These scripts generate the necessary `.swift` or `.kt` files and C-compatible binaries.

## Structure

- `rust/`: Core Rust implementation.
    - `src/dkg.rs`: DKG logic and state machine.
    - `src/sign.rs`: Signing logic.
    - `src/net.rs`: Network interface definitions.
- `swift/`: Swift package and examples.
    - `Sources/CLIKeyGen`: Example CLI for DKG.
    - `Sources/CLISign`: Example CLI for Signing.
- `kotlin/`: Kotlin/Android bindings.

## Examples

Check the `swift/Sources` directory for complete implementations:
- **[CLIKeyGen](swift/Sources/CLIKeyGen/main.swift)**: A complete command-line tool demonstrating the DKG flow.
- **[CLISign](swift/Sources/CLISign/main.swift)**: A command-line tool demonstrating threshold signing.
