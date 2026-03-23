# DKLS Wrapper Library

This library provides a cross-platform wrapper for the
[DKLS23](https://eprint.iacr.org/2023/765.pdf) threshold signature scheme,
enabling distributed signature generation (DSG) for ECDSA in a $t$-of-$n$ setup.
It currently relies on the [Silence Labs](https://silencelaboratories.com/)
[DKLS23](https://github.com/silence-laboratories/dkls23) Rust Crate. The library
is written in Rust and provides bindings via
[UniFFI](https://github.com/mozilla/uniffi-rs) for Swift and Kotlin, as well as
any other language supported by UniFFI (e.g. JS/WebASM should be trivial).

The wrapper is intended to be used by mobile applications (e.g. iOS and Android)
to perform distributed key generation and threshold signing. As such it is
opinionated about how nodes are managed and is *not* intended for general
cryptographic use. The idea is that there is user overseeing and approving
action, although policies can be implemented at a higher layer.

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

- **Rust**: Rust 2021 Edition (last tested with Cargo 1.91.1)
- **UniFFI**: Used for generating bindings to languages other than Rust (see
  [Cargo.toml](Cargo.toml) for version).
- **Swift/iOS**:
    - Swift / Xcode
    - [cargo-swift](https://github.com/antoniusnaumann/cargo-swift) 0.10.0
    - Rust targets: `rustup target install aarch64-apple-ios-sim aarch64-apple-ios x86_64-apple-ios`
- **Kotlin/Android**:
    - JDK and Android SDK (for Android development).
    - `cargo-ndk` (TODO)
    - Rust targets: `rustup target install armv7-linux-androideabi
      aarch64-linux-android i686-linux-android 86_64-linux-android`

### Structure

- `docs/`: Look here first for any additional documentation!
- `src/`: core Rust source code.
    - `types.rs` and `error.rs`: Common types and error definitions used across the library.
    - `net.rs`: Network interface definitions.
    - `dkg.rs`: DKG logic and state machine.
    - `sign.rs`: Signing logic.
    - `test.rs`: Helpers for implementing tests.
- `swift/`: SwiftPM project file, extensions to generated code, tests. Cannot be
  built directly, must be copied into the generated Swift package.
- `examples/`
    - `rust/`: Example CLI in Rust for both DKG and signature generation.
    - `swift/`: Example CLI in Swift for both DKG and signature generation.
    - `kotlin/`: Example CLI in Kotlin for both DKG and signature generation.
- `build-swift.sh`: Script to generate Swift bindings.
- `build-kotlin.sh`: Script to generate Kotlin bindings.

## Examples

The examples demonstrate how to use the library over an MQTT connection for both
DKG and signature generation. Building the example code is generally done by
first generating the bindings for the given platform/language, and then building
the example itself. The examples should be cross-compatible, that is you should
be able to run a DKG with devices running different platforms. To use the
examples, you'll need to run an MQTT broker. We suggest
[Mosquitto](https://mosquitto.org/), but you can use any MQTT compatible broker.

With the broker running, first use DKG to generate a secret-shared key before
running the signature generation tools. The first device sets the configuration,
while subsequent devices are given a Base45-encoded string (to represent a QR
code) which includes setup information.

### Common DKG Parameters & Usage

- `name` (first command line argument): A user-friendly name for the device.
- `threshold` (-t, default: 2) The threshold value to use.
- `instance_id`: Instance ID to use in Base45 encoding. If not set, a random InstanceID will be generated.
- `output_filename` (-o, default: "keyshare"): Filename prefix for saving the key share.
- `mqtt_host`: (default: "localhost"): hostname to use for the MQTT broker.
- `mqtt_port`: (default: 1883): port to use for the MQTT broker.
- `qr_data`: (-q): QR Data from other party. If not set, the device will be the initiator.

By necessity, the CLI is interactive. Usage example:

1. Start an MQTT broker (e.g. Mosquitto).
2. Start the first device (initiator): `./dkg Device0`
    - You may optionally set the threshold, instance ID, output filename, mqtt
      host and port, as above.
    - When properly started, this will display "My QR" followed by the QR Code
      data. Copy this data for the next command.
3. Start another device: `./dkg Device1 -q <QR_DATA>`
    - Note that the MQTT host and port must be configured to match the initial
      device. In the future this may become part of the QR Data.
4. Start any other devices in the same way, or copy QR data from one to the
   other for additional verification.
5. Once the desired devices are started, press enter in any one CLI to begin the
   DKG process.

### Common Signing Parameters & Usage

- `keyshare_filename` (first command line parameter): the filename of the
  keyshare data to load.
- `mqtt_host`: (default: "localhost"): hostname to use for the MQTT broker.
- `mqtt_port`: (default: 1883): port to use for the MQTT broker.

By necessity the CLI is interactive. The CLI for all of the examples should be
similar, but might have small discrepancies. Usage is generally:

1. Start instances for the desired active key shares, e.g. `./sign
   keyshare_deviceX`.
2. On any interface, use the CLI to request a signature, e.g. `s Some Message`
3. You should see the new request appear on the other devices. If you approve
   the request on a threshold number of interfaces the signature will be
   automatically generated.

You can also reject requests and cancel requests from the originator to test
these functionalities.

### Rust

Running the example code in Rust should be as easy as:

```sh
cd examples/rust
cargo run --bin dkg Device0
cargo run --bin sign keyshare_Device0
```

### Swift

The example Swift CLI references the generated Swift package in the project root
directly. As such, you must generate the Swift package first before you can run
the example. From the project root:

```sh
./build-swift.sh
cd examples/swift
swift run dkg Device0
swift run sign keyshare_Device0
```

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
