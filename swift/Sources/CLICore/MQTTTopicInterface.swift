import DKLSLib
import Foundation
import MQTTNIO
import NIO

public final class MQTTInterface: NetworkInterface, @unchecked Sendable {
    private let client: MQTTClient
    private let topic: String
    private let retainOnSend: Bool
    private var messageIterator: AsyncThrowingStream<Data, Error>.Iterator?

    public init(client: MQTTClient, topic: String, retainOnSend: Bool = false) {
        self.client = client
        self.topic = topic
        self.retainOnSend = retainOnSend
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

    public func send(data: Data) async throws {
        try await client.publish(
            to: topic,
            payload: ByteBuffer(data: data),
            qos: .atLeastOnce,
            retain: retainOnSend,
        ).get()
    }

    public func receive() async throws -> Data {
        return try await messageIterator?.next() ?? Data()
    }
}
