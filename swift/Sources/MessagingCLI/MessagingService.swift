import FirebaseFirestore
import Foundation

/// Represents a message in the messaging system
struct Message: Codable {
    let sender: String
    let text: String
    let timestamp: Date

    init(sender: String, text: String, timestamp: Date = Date()) {
        self.sender = sender
        self.text = text
        self.timestamp = timestamp
    }
}

/// Service for sending and receiving messages via Firebase Firestore
class MessagingService {
    static let shared = MessagingService()

    private let db: Firestore
    private let messagesCollection = "messages"
    private var listener: ListenerRegistration?

    private init() {
        self.db = Firestore.firestore()
    }

    /// Send a message to the Messages collection
    /// - Parameters:
    ///   - sender: The sender identifier (typically user ID)
    ///   - text: The message text
    func sendMessage(sender: String, text: String) async throws {
        let message = Message(sender: sender, text: text)
        let messageData: [String: Any] = [
            "sender": message.sender,
            "text": message.text,
            "timestamp": Timestamp(date: message.timestamp),
        ]

        try await db.collection(messagesCollection).addDocument(data: messageData)
    }

    /// Listen to messages in real-time
    /// - Parameter callback: Called whenever messages are updated
    /// - Returns: A listener registration that can be used to stop listening
    @discardableResult
    func listenToMessages(callback: @escaping ([Message]) -> Void) -> ListenerRegistration {
        // Remove existing listener if any
        listener?.remove()

        // Create new listener ordered by timestamp
        let listener = db.collection(messagesCollection)
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
                    let data = document.data()
                    guard let sender = data["sender"] as? String,
                        let text = data["text"] as? String,
                        let timestamp = data["timestamp"] as? Timestamp
                    else {
                        return nil
                    }
                    return Message(sender: sender, text: text, timestamp: timestamp.dateValue())
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
