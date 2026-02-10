import ArgumentParser
import CLICore
import DKLSLib
import Foundation
import MQTTNIO
import NIO
import base45_swift

struct DKGArgs: ParsableCommand {
    @Argument(help: "Name of this device.")
    var name: String

    @Option(
        help:
            "InstanceID to use in Base45 encoding. If not set, a random InstanceID will be generated."
    )
    var instanceID: String = ""

    @Option(name: .shortAndLong, help: "Threshold number of devices. Only valid for new instances.")
    var threshold: UInt8 = 2

    @Option(name: .shortAndLong, help: "Output filename.")
    var outputFilename: String = "keyshare"

    @Option(name: .long, help: "MQTT host.")
    var mqttHost: String = "localhost"

    @Option(name: .long, help: "MQTT port.")
    var mqttPort: Int = 1883

    @Option(name: .shortAndLong, help: "QR Data from other device.")
    var qrData: String = ""

    func validate() throws {
        if name.isEmpty {
            throw ValidationError("Name cannot be empty")
        }
        if qrData.isEmpty {
            if !instanceID.isEmpty {
                do {
                    _ = try self.decodeInstanceID()
                } catch {
                    throw ValidationError("Invalid Instance ID")
                }
            }
            if threshold < 2 {
                throw ValidationError("Threshold must be at least 2")
            }
        } else {
            do {
                _ = try self.decodeQrBytes()
            } catch {
                throw ValidationError("QR Data must be valid Base45")
            }
            if !instanceID.isEmpty {
                throw ValidationError("Cannot set InstanceID when using QR Data.")
            }
        }
    }

    func decodeInstanceID() throws -> InstanceId {
        let bytes = try instanceID.fromBase45()
        return try InstanceId.fromBytes(bytes: bytes)
    }

    func decodeQrBytes() throws -> Data {
        return try qrData.fromBase45()
    }

}

print(colorize("DKLS CLI DKG Test", .cyan))
print()

let dkgArgs: DKGArgs
do {
    dkgArgs = try DKGArgs.parse()
} catch {
    print(colorize("Error parsing arguments: \(error)", .red))
    exit(1)
}

let outputFilename = dkgArgs.outputFilename + "_" + dkgArgs.name
print("Output filename: \(outputFilename)")
print("MQTT host: \(dkgArgs.mqttHost)")
print("MQTT port: \(dkgArgs.mqttPort)")
print()

let dkgNode: DkgNode
let instanceStr: String
if dkgArgs.qrData.isEmpty {
    let instanceID: InstanceId
    if dkgArgs.instanceID.isEmpty {
        instanceID = InstanceId.fromEntropy()
    } else {
        do {
            let bytes = try dkgArgs.instanceID.fromBase45()
            instanceID = try InstanceId.fromBytes(bytes: bytes)
        } catch {
            print(colorize("This should never happen: Invalid Instance ID", .red))
            exit(1)
        }
    }
    instanceStr = hexString(instanceID.toBytes())
    print(colorize("👂 Listening for messages...", .yellow))
    print(
        colorize(
            "Starting DKG as starter for instance \(instanceStr), threshold \(dkgArgs.threshold)",
            .yellow
        ))
    dkgNode = DkgNode.init(
        name: dkgArgs.name, instance: instanceID, threshold: dkgArgs.threshold)

    do {
        try print(colorize("My QR: |\(dkgNode.getQrBytes().toBase45())|", .yellow))
    } catch {
        // Should never happen at this point.
        print(colorize("Error getting QR data: \(error)", .red))
        exit(1)
    }

} else {
    print(colorize("Starting DKG as participant for QR data \(dkgArgs.qrData)", .yellow))
    do {
        let qr = try QrData.fromBytes(bytes: try dkgArgs.decodeQrBytes())
        instanceStr = hexString(qr.getInstance().toBytes())
        dkgNode = DkgNode.fromQr(name: dkgArgs.name, qrData: qr)
    } catch {
        print(colorize("Error parsing QR data: \(error)", .red))
        exit(1)
    }
}

let client = MQTTClient(
    host: dkgArgs.mqttHost,
    port: dkgArgs.mqttPort,
    identifier: "swift-\(ProcessInfo.processInfo.processIdentifier)",
    eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
    configuration: .init(version: .v5_0)
)

var messageLoopTask = Task {
    print(colorize("Connecting to MQTT broker...", .yellow))
    do {
        _ = try await client.connect().get()
        print(colorize("Connected!", .green))

    } catch {
        print(colorize("Error: \(error)", .red))
        exit(1)
    }
    let setupInterface = MQTTInterface(
        client: client,
        topic: "dkg/\(instanceStr)/setup",
    )
    let dkgInterface = MQTTInterface(
        client: client,
        topic: "dkg/\(instanceStr)/proto",
    )

    do {
        print(colorize("Starting message loop...", .yellow))
        try await dkgNode.messageLoop(setupIf: setupInterface, dkgIf: dkgInterface)
    } catch {
        print(colorize("Error in message loop: \(error)", .red))
    }
    print(colorize("Message loop completed.", .magenta))
}

final class SetupChangeListener: DkgSetupChangeListener, @unchecked Sendable {
    func onSetupChanged(devices: [DeviceInfo], myId: UInt8) {
        print("\n" + colorize("--- DKG Setup Update ---", .magenta))
        print("Devices (\(devices.count)):")
        for (i, device) in devices.enumerated() {
            let verified: String
            let mark: String
            if i == myId {
                verified = " (this device)"
                mark = "•"
            } else if device.isVerified() {
                verified = " (Verified)"
                mark = "✓"
            } else {
                verified = ""
                mark = "?"
            }
            print("  \(i + 1). \(mark) \(device.name())\(verified)")
        }
        print(colorize("------------------------", .magenta) + "\n")
    }
}

final class StateChangeListener: DkgStateChangeListener, @unchecked Sendable {
    let inputTask: Task<Void, Never>?

    init(inputTask: Task<Void, Never>?) {
        self.inputTask = inputTask
    }

    func onStateChanged(oldState: DkgState, newState: DkgState) {
        print(colorize("State changed: \(oldState) -> \(newState)", .cyan))
        if oldState == .waitForSetup
            && (newState == .waitForSigs || newState == .waitForDevices || newState == .ready)
        {
            do {
                try print(colorize("My QR: |\(dkgNode.getQrBytes().toBase45())|", .yellow))
            } catch {
                // Should never happen at this point.
                print(colorize("Error getting QR data: \(error)", .red))
            }
        }
        if newState == .running {
            inputTask?.cancel()
        }
    }
}

var inputTask = Task.detached {
    while true {
        guard let line = readLine() else {
            print(colorize("Exiting...", .red))
            exit(1)
        }
        if line.isEmpty {
            if dkgNode.getState() == .ready {
                break
            } else {
                print(colorize("Not ready yet.", .yellow))
            }
        } else {
            // Assume this is QR data
            guard let qrData = try? line.fromBase45() else {
                print(colorize("QR Data has invalid Base45 encoding", .red))
                continue
            }
            do {
                try dkgNode.receiveQrBytes(qrBytes: qrData)
            } catch {
                print(colorize("Error in QR data: \(error)", .red))
            }
        }
    }
    print(colorize("Starting DKG", .yellow))
    do {
        try await dkgNode.startDkg()
    } catch {
        print(colorize("Error starting DKG: \(error)", .red))
        exit(1)
    }
}

let listener = StateChangeListener(inputTask: inputTask)
dkgNode.addStateChangeListener(listener: listener)

let setupListener = SetupChangeListener()
dkgNode.addSetupChangeListener(listener: setupListener)

print(colorize("Waiting for DKG to complete...", .yellow))
await messageLoopTask.value

do {
    let localData = try dkgNode.getLocalData()
    // localData.keyshare.print()
    // print(colorize("Key share bytes: \(share.toBytes().count) bytes", .magenta))
    try localData.toBytes().write(to: URL(fileURLWithPath: outputFilename))
    print(colorize("✓ Device local data written to \(outputFilename)", .green))
} catch {
    print(colorize("Error: \(error)", .red))
}

print(colorize("Disconnecting...", .yellow))
do {
    try await client.disconnect().get()
    try client.syncShutdownGracefully()
    print(colorize("Goodbye!", .green))
} catch {
    print(colorize("Error while disconnecting \(error)", .red))
}
