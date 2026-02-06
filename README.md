# DKLS Wrapper Library

This library provides a cross-platform wrapper for the [DKLS23](https://eprint.iacr.org/2023/765.pdf) threshold signature scheme, enabling distributed signature generation (DSG) for ECDSA in a $t$-of-$n$ setup. It currently relies on the [Silence Labs](https://silencelaboratories.com/) [DKLS23](https://github.com/silence-laboratories/dkls23) Rust Crate. The library is written in Rust and provides bindings via [UniFFI](https://github.com/mozilla/uniffi-rs) for Swift and Kotlin, as well as any other language supported by UniFFI (e.g. JS/WebASM should be trivial).

The wrapper is intended to be used by mobile applications (e.g. iOS and Android) to perform distributed key generation and threshold signing. As such it is opinionated about how nodes are managed and is *not* intended for general cryptographic use. The idea is that there is user overseeing and approving action, although policies can be implemented at a higher layer.

## Overview

The library exposes a high-level API to perform:
1.  **Distributed Key Generation (DKG)**: Securely generate a shared private key across multiple devices without any single device knowing the full key.
2.  **Threshold Signing**: Sign messages using a threshold of devices (t-of-n), producing a standard signature verifiable by the corresponding public key.

It is designed to be agnostic to the network transport layer. You must provide a bridge (implementation of `NetworkInterface`) to handle communication between devices (e.g., via MQTT, Bluetooth, WebSocket, or a relay server).

## Limitations

* Currently, only ECDSA signatures are generated, and ECDSA is also used as the signature type for each device/node in the system.
* The DKG process assumes one device is added at a time with user supervision. It is *not* robust to several nodes joining at the same time. While it won't result in an insecure state, it will almost certainly result in the DKG process getting stuck and needing to be restarted.
* The DKG process does not currently support removing nodes from the system.
* The DKG process is guaranteed to be secure if the verification key of all devices is verified, whether by the user or via QR code scanning, even if the network and some devices are adversarial. If not all verification keys are verified, then the process is robust to either adversarial nodes or an adversarial network, but not both. In that case, it's possible for a user to be tricked into accepting parties with incorrect verification keys.
* Channels must be free of other messages. Injection of spurious messages can result in the DKG and signature processes getting stuck. It is expected that the network bridges manage keeping channels free of other messages.

## Project Details

### Prerequisites

- **Rust**: Latest stable toolchain.
- **Swift/iOS**: Xcode (for macOS/iOS development).
- **Kotlin/Android**: JDK and Android SDK (for Android development).
- **UniFFI**: Used for generating bindings.

### Structure

- `rust/`: Core Rust implementation.
    - `src/`: core Rust source code.
        - `types.rs` and `error.rs`: Common types and error definitions used across the library.
        - `net.rs`: Network interface definitions.
        - `dkg.rs`: DKG logic and state machine.
        - `sign.rs`: Signing logic.
        - `test.rs`: Helpers for implementing tests.
    - `examples/`: Example code for using the library in a Rust CLI.
- `swift/`: Swift package and examples.
    - `Sources/DKLSLib`: Generated Swift code ends up here and should not be modified. Additional Swift-only code can also live here.
    - `Tests/DKLSLibTests`: Test code for the Swift bindings.
    - `Sources/CLICore`: Common CLI code for Swift examples, e.g. Swift MQTT interfaces.
    - `Sources/CLIKeyGen`: Example CLI for DKG.
    - `Sources/CLISign`: Example CLI for Signing.
- `kotlin/`: Kotlin/Android bindings.

### Building the Bindings

Scripts are provided to build the platform-specific bindings:

- **Swift**: `./build-swift.sh`
- **Kotlin**: `./build-kotlin.sh`

These scripts generate the necessary `.swift` or `.kt` files and C-compatible binaries.

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

## Distributed Key Generation (DKG)

The DKG process involves connecting 2 or more devices to generate shares of a distributed key. It's assumed that a user starts by configuring one device, and then adds additional devices. The process is as follows:

1. The first device determines a unique instance ID for the DKG session as well as any required parameters.
2. Devices joining the group scan a QR code from an existing device to obtain the instance ID and parameters, as well as the verification key of the device being scanned.
3. The new device then sends a joining request to the network with its verification key and the name of the device.
4. Existing devices approve the request by appending the new device's info to their list of devices and sending a setup message to the network with their complete device list, signed with their signing key.
5. Once unanimous approval is reached, devices enter a ready state from which either new devices can be added or the DKG process can begin (assuming sufficient devices are in the group).
6. Devices can also scan the QR code of other devices to verify their verification key. This produces stronger security and is recommended but not required.
7. If any device is not authorized or if the wrong device is added the protocol must be aborted and restarted.
8. Once the desired devices are in the group, the user may use any of the devices to start the DKG process. This starts the lower level DKLS library's DKG protocol on a separate channel.
9. Once the protocol completes, each device is supplied with either the resulting Keyshare which can be used for DSG or a LocalDeviceData object which includes all of the device info for reuse in future DSG sessions.
10. If there is an error in the protocol then in the Finished state attempts to retrieve the result will give the error result.

While it's possible to perform all of these steps manually, it's recommended to provide the `DKGNode` with network interfaces and let `message_loop` handle all of the messages internally. Use the DKGStateChangeListener to be informed of changes to the state machine and `DKGSetupChangeListener` for changes to the devices in the group.

**Step 1: Initial Node**
Create a `DKGNode` with the name of the current device, the desired InstanceID (can be generated from entropy), threshold, and separate interfaces for setup messages (i.e. which devices are involved) and protocol execution (i.e. running the DKG with the already established parties). We keep the two separate, as messages delivered to the DKG protocol execution engine will hang the process. In practice you could have a message type field and have everything within the same channel. That's left to implementors.

```swift
let node = DKGNode(
    name: "Device A",
    instance: InstanceId(), // Shared Session ID
    threshold: 3,
    setupIf: setupBridge,   // Implements NetworkInterface
    dkgIf: dkgBridge        // Implements NetworkInterface
)
```

Use `node.getQrBytes()` to generate the byte string to be presented via QR code, and in a separate thread call `node.messageLoop()` to handle all messages.

**Step 2: Joining a Group**

After scanning a QR code from an existing device, create a new `DKGNode` with the QR code byte data using
`DKGNode.tryFromQrBytes()`, or you can use `QrData.tryFrom(bytes)` to parse the QR data if you need the instance ID for creating a network channel and then use `DKGNode.fromQr()` to create the node. In either case, provide the name of the current device and the network interfaces to be used. Then call `node.messageLoop()` in a separate thread to handle all messages.

**Step 3: Getting Updates**

While running `messageLoop` in the background, use `addStateChangeListener` to be notified of changes to the state machine, and `addSetupChangeListener` to be notified of changes to the devices in the group. It is recommended to update the display of the user interface based on these and abort if the user doesn't recognize a device added.

The QR code should remain displayed during this setup phase. If the user scans the QR code of another device, use the `node.receiveQrBytes(bytes)` method to verify the device's info.

**Step 4: Starting DKG**

When there is unanimous approval of sufficient devices in the group, the user may start the DKG process. When the user signals readiness, the `node.startDkg()` method will begin the process. The event loop must be running to handle messages from the DKG protocol. The state change listener will be notified of the transition to the `Finished` state.

**Step 4: Get Result**

Once the state machine enters the Finished state, calling the `node.getResult()` will get the resulting keyshare or an error if the process failed. Call `node.getLocalData()` to get the `DeviceLocalData` struct, which includes all of the device infos in the group in addition to the keyshare. This can be useful for the next step of setting up a DSG node, which requires the verification keys of all devices in the group.

## Distributed Signature Generation

To sign a message, you need the `Keyshare` from the DKG step and the verification keys of all devices in the group. After creating a `SignNode` you can wait for requests to arrive or initiate a signing session (or both if you spawn a background thread).

### Creating a signature request

To request a signature from other devices, use the `doSignString` method for UTF-8 strings or `doSignBytes` for raw bytes. You must also provide the network interface to be used for communication with other devices. `SignNode` will internally handle all messages and return the resulting signature or error. As such, make this call from a background thread and not the UI thread.

### Receiving and responding to a signature request

Use `signNode.getNextReq(net_if)` to receive wait for a signature request from another device on the given network interface. This produces a `SignRequest` object with the details of the request. It's up to the higher level interface to determine whether to respond to the request or not. For example, if the VK matches a trusted device then the higher level interface may choose to accept the request without further approval. Or it may be presented to the user for approval.

If the request is accepted, use `signNode.doJoinRequest(req, net_if)` to join the signing session. This will return the resulting signature or error.

Remember to call these methods in a background thread to not hang the UI thread.

### Signature

The resulting signature object can be verified using the group's public key, and is the same as a normal ECDSA signature.

## Examples

Check the `swift/Sources` directory for complete implementations:
- **[CLIKeyGen](swift/Sources/CLIKeyGen/main.swift)**: A complete command-line tool demonstrating the DKG flow.
- **[CLISign](swift/Sources/CLISign/main.swift)**: A command-line tool demonstrating threshold signing.
