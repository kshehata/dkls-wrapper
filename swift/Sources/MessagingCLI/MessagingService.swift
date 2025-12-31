import DKLSLib
import FirebaseFirestore
import Foundation

/// Represents a message in the messaging system
struct Message: Codable {
    let sender: String
    let text: String
    let timestamp: Date
    let instanceID: Data

    init(instanceID: Data, sender: String, text: String, timestamp: Date = Date()) {
        self.instanceID = instanceID
        self.sender = sender
        self.text = text
        self.timestamp = timestamp
    }
}

/// Service for sending and receiving messages via Firebase Firestore
class MessagingService: NetworkInterface {
    private let db: Firestore
    private let instanceID: Data
    private let sender: String
    private let messagesCollection = "messages"
    private var listener: ListenerRegistration?
    private var messageIterator: AsyncThrowingStream<Data, Error>.Iterator?

    public static func getInstance(instanceID: Data, sender: String) -> MessagingService {
        return MessagingService(instanceID: instanceID, sender: sender)
    }

    private init(instanceID: Data, sender: String) {
        self.db = Firestore.firestore()
        self.instanceID = instanceID
        self.sender = sender
    }

    /// Send a message to the Messages collection
    /// - Parameters:
    ///   - text: The message text
    func sendMessage(text: String) throws {
        let message = Message(instanceID: instanceID, sender: sender, text: text)
        try db.collection(messagesCollection).addDocument(from: message)
    }

    func send(data: Data) async throws {
        try sendMessage(text: data.base64URLEncodedString())
    }

    func receive() async throws -> Data {
        if messageIterator == nil {
            let stream = AsyncThrowingStream<Data, Error> { continuation in
                let listener = db.collection(messagesCollection)
                    .whereField("instanceID", isEqualTo: instanceID)
                    .order(by: "timestamp", descending: false)
                    .addSnapshotListener { querySnapshot, error in
                        if let error = error {
                            continuation.finish(throwing: error)
                            return
                        }

                        querySnapshot?.documentChanges.forEach { diff in
                            if diff.type == .added {
                                do {
                                    let message = try diff.document.data(as: Message.self)
                                    // ignore messages from self
                                    if message.sender == self.sender {
                                        return
                                    }
                                    // Handle URL-safe Base64
                                    var base64 = message.text
                                        .replacingOccurrences(of: "-", with: "+")
                                        .replacingOccurrences(of: "_", with: "/")
                                    while base64.count % 4 != 0 {
                                        base64.append("=")
                                    }

                                    if let data = Data(base64Encoded: base64) {
                                        continuation.yield(data)
                                    }
                                } catch {
                                    print("Error parsing message: \(error)")
                                }
                            }
                        }
                    }

                continuation.onTermination = { @Sendable _ in
                    listener.remove()
                }
            }
            messageIterator = stream.makeAsyncIterator()
        }

        guard let data = try await messageIterator?.next() else {
            throw NSError(
                domain: "MessagingService", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Message stream ended"])
        }
        return data
    }

    /// Listen to messages in real-time
    /// - Parameter callback: Called whenever messages are updated
    /// - Returns: A listener registration that can be used to stop listening
    @discardableResult
    func listenToMessages(callback: @escaping ([Message]) -> Void)
        -> ListenerRegistration
    {
        // Remove existing listener if any
        listener?.remove()

        // Create new listener ordered by timestamp and filtered by instanceID
        let listener = db.collection(messagesCollection)
            .whereField("instanceID", isEqualTo: instanceID)
            .order(by: "timestamp", descending: false)
            .addSnapshotListener { querySnapshot, error in
                if let error = error {
                    print("Error listening to messages: \(error.localizedDescription)")
                    return
                }

                guard let documents = querySnapshot?.documents else {
                    callback([])
                    return
                }

                let messages = documents.compactMap { document -> Message? in
                    try? document.data(as: Message.self)
                }

                callback(messages)
            }

        self.listener = listener
        return listener
    }

    /// Stop listening to messages
    func stopListening() {
        listener?.remove()
        listener = nil
    }
}
