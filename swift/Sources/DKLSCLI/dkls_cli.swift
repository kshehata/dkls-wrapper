import DKLSLib
import Foundation
import MQTTNIO
import NIO

// ANSI color codes for terminal output
enum Color: String {
    case reset = "\u{001B}[0m"
    case red = "\u{001B}[31m"
    case green = "\u{001B}[32m"
    case yellow = "\u{001B}[33m"
    case blue = "\u{001B}[34m"
    case magenta = "\u{001B}[35m"
    case cyan = "\u{001B}[36m"
}

func colorize(_ text: String, _ color: Color) -> String {
    return "\(color.rawValue)\(text)\(Color.reset.rawValue)"
}

class MQTTInterface: NetworkInterface {
    private let client: MQTTClient
    private let topic: String
    private var messageIterator: AsyncThrowingStream<Data, Error>.Iterator?

    init(client: MQTTClient, topic: String) {
        self.client = client
        self.topic = topic
        self.messageIterator = createMessageStream().makeAsyncIterator()
    }

    private func createMessageStream() -> AsyncThrowingStream<Data, Error> {
        let topic = self.topic
        let client = self.client

        return AsyncThrowingStream { continuation in
            // Subscribe to topic using MQTT v5 NoLocal option
            let future = client.v5.subscribe(to: [
                MQTTSubscribeInfoV5(topicFilter: topic, qos: .atLeastOnce, noLocal: true)
            ])

            future.whenSuccess { _ in
                print(colorize("Subscribed to \(topic)", .green))
            }

            future.whenFailure { error in
                continuation.finish(throwing: error)
            }

            // Add listener for messages
            client.addPublishListener(named: topic) { result in
                switch result {
                case .success(let packet):
                    guard packet.topicName == topic else { return }
                    var buffer = packet.payload
                    if let data = buffer.readData(length: buffer.readableBytes) {
                        continuation.yield(data)
                    }
                case .failure(let error):
                    continuation.finish(throwing: error)
                }
            }

            continuation.onTermination = { @Sendable _ in
                let _ = client.unsubscribe(from: [topic])
                client.removePublishListener(named: topic)
            }
        }
    }

    func send(data: Data) async throws {
        try await client.publish(
            to: topic,
            payload: ByteBuffer(data: data),
            qos: .atLeastOnce
        ).get()
    }

    func receive() async throws -> Data {
        return try await messageIterator?.next() ?? Data()
    }
}

func hexString(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

func checkWriteable(_ path: String) -> Bool {
    let fm = FileManager.default
    let dest = path
    let parent = (dest as NSString).deletingLastPathComponent
    let checkPath = fm.fileExists(atPath: dest) ? dest : (parent.isEmpty ? "." : parent)
    return fm.isWritableFile(atPath: checkPath)
}

@main
struct DKLSCLI {
    static func main() async {
        print(colorize("DKLS CLI DKG Test", .cyan))
        print()

        let dkgNode: DkgNode
        let args = ProcessInfo.processInfo.arguments
        if args.count <= 2 {
            print(colorize("Paste the setup bytes from the other party:", .red))
            let setupBase64 = readLine()!
            do {
                dkgNode = try DkgNode.fromSetupBytes(setup: Data(base64Encoded: setupBase64)!)
            } catch {
                print(colorize("Error parsing setup bytes", .red))
                exit(1)
            }

        } else if args.count == 3 || args.count == 4 {
            let instanceID: InstanceId
            if args[1] == "-" {
                instanceID = InstanceId.fromEntropy()
            } else {
                guard let data = Data(base64Encoded: args[1]) else {
                    print(colorize("Error: Invalid base64 for Instance ID", .red))
                    exit(1)
                }
                do {
                    instanceID = try InstanceId.fromBytes(bytes: data)
                } catch {
                    print(colorize("Error: Invalid Instance ID bytes", .red))
                    exit(1)
                }
            }
            let threshold = UInt8(args[2])!
            dkgNode = DkgNode.starter(instance: instanceID, threshold: threshold)

        } else {
            print(
                colorize(
                    "Usage: \(args[0]) <instanceID|-> <threshold> <outputFilename>",
                    .red))
            return
        }

        let outputFilename: String
        if args.count == 4 {
            outputFilename = args[3]
        } else if args.count == 2 {
            outputFilename = args[1]
        } else {
            outputFilename = "keyshare\(dkgNode.partyId())"
        }
        if !checkWriteable(outputFilename) {
            print(colorize("Error: Cannot write to \(outputFilename)", .red))
            exit(1)
        }
        print(
            colorize(
                "Saving keyshare to \(outputFilename)",
                .cyan))

        let instanceStr = hexString(dkgNode.instanceId().toBytes())
        print(
            colorize(
                "🆔 Using Instance ID: \(instanceStr)",
                .cyan))
        print(
            colorize(
                "Settings: n = \(dkgNode.threshold()), t = \(dkgNode.threshold()), i = \(dkgNode.partyId())",
                .cyan))
        print(colorize("Setup bytes:", .cyan))
        print(dkgNode.setupBytes().base64EncodedString())
        print()

        let client = MQTTClient(
            host: ProcessInfo.processInfo.environment["MQTT_HOST"] ?? "localhost",
            port: Int(ProcessInfo.processInfo.environment["MQTT_PORT"] ?? "1883")!,
            identifier: "swift-\(ProcessInfo.processInfo.processIdentifier)",
            eventLoopGroupProvider: .createNew,
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

        print(colorize("👂 Listening for messages...", .yellow))
        let setupInterface = MQTTInterface(
            client: client,
            topic: "dkg_setup/\(instanceStr)"
        )

        Task {
            do {
                print(colorize("Waiting for other party's setup string...", .yellow))
                while true {
                    let data = try await setupInterface.receive()
                    print(colorize("Received Setup String: \(data.count) bytes", .magenta))
                    do {
                        try dkgNode.updateFromBytes(setup: data)
                    } catch {
                        print(colorize("Error updating from received setup: \(error)", .red))
                    }
                }
            } catch {
                print(colorize("Error receiving messages: \(error)", .red))
            }
        }

        let service = MQTTInterface(
            client: client,
            topic: "dkg/\(instanceStr)"
        )

        print(colorize("✓ Connected to message stream", .green))
        print()

        do {
            try await setupInterface.send(data: dkgNode.setupBytes())
            print(colorize("✓ Sent setup string", .green))
        } catch {
            print(colorize("Error sending setup string: \(error)", .red))
            exit(1)
        }

        await Task.detached {
            print(colorize("Ready. Press enter to start.", .magenta))
            _ = readLine()
        }.value

        do {
            print(colorize("Generating key shares...", .yellow))
            let share = try await dkgNode.doKeygen(interface: service)
            print(colorize("✓ Key shares generated", .green))
            print()
            share.print()
            print(colorize("Key share bytes: \(share.toBytes().count) bytes", .magenta))
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
    }
}
