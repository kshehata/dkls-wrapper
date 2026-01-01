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
    }

    func send(data: Data) async throws {
        try await client.publish(
            to: topic,
            payload: ByteBuffer(data: data),
            qos: .atLeastOnce
        ).get()
    }

    func receive() async throws -> Data {
        if messageIterator == nil {
            let topic = self.topic
            let client = self.client
            let stream = AsyncThrowingStream<Data, Error> { continuation in
                // Subscribe to topic
                let future = client.subscribe(to: [
                    MQTTSubscribeInfo(topicFilter: topic, qos: .atLeastOnce)
                ])

                future.whenSuccess { _ in
                    print(colorize("Subscribed to \(topic)", .green))
                }

                future.whenFailure { error in
                    continuation.finish(throwing: error)
                }

                // Add listener for messages
                client.addPublishListener(named: "dkls_listener") { result in
                    switch result {
                    case .success(let packet):
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
                    client.removePublishListener(named: "dkls_listener")
                }
            }
            messageIterator = stream.makeAsyncIterator()
        }

        guard let data = try await messageIterator?.next() else {
            throw NSError(
                domain: "MQTTService", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Message stream ended"])
        }
        return data
    }
}

@main
struct DKLSCLI {
    static func main() async {
        print(colorize("DKLS CLI DKG Test", .cyan))
        print()

        let client = MQTTClient(
            host: ProcessInfo.processInfo.environment["MQTT_HOST"] ?? "localhost",
            port: Int(ProcessInfo.processInfo.environment["MQTT_PORT"] ?? "1883")!,
            identifier: "swift-\(ProcessInfo.processInfo.processIdentifier)",
            eventLoopGroupProvider: .createNew
        )

        print(colorize("Connecting to MQTT broker...", .yellow))
        do {
            _ = try await client.connect().get()
            print(colorize("Connected!", .green))

        } catch {
            print(colorize("Error: \(error)", .red))
            exit(1)
        }

        let service = MQTTInterface(
            client: client,
            topic: "dkls-test"
        )

        Task {
            do {
                while true {
                    let data = try await service.receive()
                    if let text = String(data: data, encoding: .utf8) {
                        print()
                        print(colorize("Received Message:", .magenta))
                        print("  \(text)")
                    } else {
                        print()
                        print(colorize("Received \(data.count) bytes", .magenta))
                    }
                }
            } catch {
                print(colorize("Error receiving messages: \(error)", .red))
            }
        }

        let input_task = Task.detached {
            print(colorize("Type your message and press Enter to send.", .cyan))
            print(colorize("Use /q or press Ctrl+C to exit.", .cyan))
            print(colorize("--------------------------------------------------", .cyan))
            print()

            while let line = readLine() {
                if line.lowercased().starts(with: "/q") {
                    break
                }
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty {
                    continue
                }
                do {
                    try await service.send(data: trimmed.data(using: .utf8) ?? Data())
                } catch {
                    print(
                        colorize("❌ Error sending message: \(error.localizedDescription)", .red)
                    )
                }
            }
            print("Input listener stopped.")
        }

        await input_task.value

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
