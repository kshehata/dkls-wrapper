import ArgumentParser
import CLICore
import DKLSLib
import Foundation
import MQTTNIO
import NIO

struct DKGArgs: ParsableCommand {
    @Argument(help: "Name of this device.")
    var name: String

    @Option(
        help:
            "InstanceID to use in Base64 encoding. If not set, a random InstanceID will be generated."
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

    @Option(name: .shortAndLong, help: "QR Data from other party.")
    var qrData: String = ""

    func validate() throws {
        if name.isEmpty {
            throw ValidationError("Name cannot be empty")
        }
        if qrData.isEmpty {
            if !instanceID.isEmpty {
                guard let data = Data(base64Encoded: instanceID) else {
                    throw ValidationError("Instance ID must be valid base64")
                }
                do {
                    _ = try InstanceId.fromBytes(bytes: data)
                } catch {
                    throw ValidationError("Invalid Instance ID")
                }
            }
            if threshold < 2 {
                throw ValidationError("Threshold must be at least 2")
            }
        } else {
            guard Data(base64Encoded: qrData) != nil else {
                throw ValidationError("QR Data must be valid base64")
            }
            if !instanceID.isEmpty {
                throw ValidationError("Cannot set InstanceID when using QR Data.")
            }
        }
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

let client = MQTTClient(
    host: dkgArgs.mqttHost,
    port: dkgArgs.mqttPort,
    identifier: "swift-\(ProcessInfo.processInfo.processIdentifier)",
    eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
    configuration: .init(version: .v5_0)
)

print(colorize("Connecting to MQTT broker...", .yellow))
do {
    _ = try await client.connect().get()
    print(colorize("Connected!", .green))

} catch {
    print(colorize("Error: \(error)", .red))
    exit(1)
}

func getMQTTInterface(_ instanceStr: String, _ sub: String) -> MQTTInterface {
    return MQTTInterface(
        client: client,
        topic: "dkg/\(instanceStr)/\(sub)"
    )
}

let dkgNode: DkgNode
if dkgArgs.qrData.isEmpty {
    let instanceID: InstanceId
    if dkgArgs.instanceID.isEmpty {
        instanceID = InstanceId.fromEntropy()
    } else {
        do {
            instanceID = try InstanceId.fromBytes(bytes: Data(base64Encoded: dkgArgs.instanceID)!)
        } catch {
            print(colorize("This should never happen: Invalid Instance ID", .red))
            exit(1)
        }
    }
    print(colorize("👂 Listening for messages...", .yellow))
    let instanceStr = hexString(instanceID.toBytes())
    let setupInterface = getMQTTInterface(instanceStr, "setup")
    let dkgInterface = getMQTTInterface(instanceStr, "proto")
    print(
        colorize(
            "Starting DKG as starter for instance \(instanceStr), threshold \(dkgArgs.threshold)",
            .yellow
        ))
    dkgNode = DkgNode.init(
        name: dkgArgs.name, instance: instanceID, threshold: dkgArgs.threshold,
        setupIf: setupInterface, dkgIf: dkgInterface)

    do {
        try print(colorize("My QR: \(dkgNode.getQrBytes().base64EncodedString())", .yellow))
    } catch {
        // Should never happen at this point.
        print(colorize("Error getting QR data: \(error)", .red))
        exit(1)
    }

} else {
    print(colorize("Starting DKG as participant for QR data \(dkgArgs.qrData)", .yellow))
    do {
        let qr = try QrData.fromBytes(bytes: Data(base64Encoded: dkgArgs.qrData)!)
        let instanceStr = hexString(qr.getInstance().toBytes())
        let setupInterface = getMQTTInterface(instanceStr, "setup")
        let dkgInterface = getMQTTInterface(instanceStr, "proto")
        dkgNode = try DkgNode.fromQr(
            name: dkgArgs.name, qrData: qr,
            setupIf: setupInterface,
            dkgIf: dkgInterface)
    } catch {
        print(colorize("Error parsing QR data: \(error)", .red))
        exit(1)
    }
}

var messageLoopTask = Task {
    do {
        print(colorize("Starting message loop...", .yellow))
        try await dkgNode.messageLoop()
    } catch {
        print(colorize("Error in message loop: \(error)", .red))
    }
    print(colorize("Message loop completed.", .magenta))
}

final class SetupChangeListener: DkgSetupChangeListener, @unchecked Sendable {
    func onSetupChanged(setup: DkgSetupMessage) {
        let parties = setup.getParties()
        print("\n" + colorize("--- DKG Setup Update ---", .magenta))
        // print("Instance: \(hexString(setup.getInstance().toBytes()))")
        print("Threshold: \(setup.getThreshold())")
        print("Parties (\(parties.count)):")
        for (i, party) in parties.enumerated() {
            let verified = party.isVerified() ? " (Verified)" : ""
            let mark = party.isVerified() ? "✓" : "?"  // u2713
            print("  \(i + 1). \(mark) \(party.name())\(verified)")
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
        if newState == .running {
            inputTask?.cancel()
        }
    }
}

var inputTask = Task.detached {
    while true {
        let line = readLine()
        if line == "q" || line == "quit" {
            print(colorize("Exiting...", .red))
            exit(0)
        }
        if line == "start" || line == "s" {
            if dkgNode.getState() == .ready {
                break
            } else {
                print(colorize("Not ready yet. Try again.", .yellow))
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
    let share = try dkgNode.getResult()
    share.print()
    // print(colorize("Key share bytes: \(share.toBytes().count) bytes", .magenta))
    try share.toBytes().write(to: URL(fileURLWithPath: outputFilename))
    print(colorize("✓ Key share written to \(outputFilename)", .green))
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
