import Foundation

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

// Track displayed messages to avoid duplicates
var displayedMessages = Set<String>()

@main
struct MessagingCLI {
    static func main() async {
        print(colorize("🔥 Firebase Messaging CLI", .cyan))
        print(colorize("=" * 50, .cyan))
        print()

        do {
            // Configure Firebase
            print(colorize("📱 Configuring Firebase...", .yellow))
            try FirebaseConfig.shared.configure()
            print(colorize("✓ Firebase configured", .green))

            // Sign in anonymously
            print(colorize("Skipping sign in...", .yellow))
            print("What is your name? ", terminator: "")
            let userId = readLine() ?? "Bob"
            // print(colorize("🔐 Signing in anonymously...", .yellow))
            // let user = try await FirebaseConfig.shared.signInAnonymously()
            // let userId = user.uid
            // print(colorize("✓ Signed in as: \(userId)", .green))
            print()

            // Start listening to messages
            print(colorize("👂 Listening for messages...", .yellow))
            MessagingService.shared.listenToMessages { messages in
                for message in messages {
                    let messageId =
                        "\(message.sender):\(message.timestamp.timeIntervalSince1970):\(message.text)"

                    // Only display new messages
                    if !displayedMessages.contains(messageId) {
                        displayedMessages.insert(messageId)

                        let timestamp = formatTimestamp(message.timestamp)
                        let senderColor: Color = message.sender == userId ? .blue : .magenta
                        let senderLabel =
                            message.sender == userId ? "You" : "User \(message.sender.prefix(8))"

                        print()
                        print(colorize("[\(timestamp)] \(senderLabel):", senderColor))
                        print("  \(message.text)")
                    }
                }
            }

            print(colorize("✓ Connected to message stream", .green))
            print()
            // try await Task.sleep(nanoseconds: 1_000_000_000)  // Sleep for 100ms to get any old messages

            // Set up signal handler for graceful shutdown
            signal(SIGINT) { _ in
                print()
                print(colorize("\n👋 Shutting down...", .yellow))
                MessagingService.shared.stopListening()
                exit(0)
            }

            let input_task = Task.detached {
                print(colorize("Type your message and press Enter to send.", .cyan))
                print(colorize("Use /q or press Ctrl+C to exit.", .cyan))
                print(colorize("-" * 50, .cyan))
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
                        try await MessagingService.shared.sendMessage(sender: userId, text: trimmed)
                    } catch {
                        print(
                            colorize("❌ Error sending message: \(error.localizedDescription)", .red)
                        )
                    }
                }
                print("Input listener stopped.")
            }

            await input_task.value

        } catch {
            print(colorize("❌ Error: \(error)", .red))
            exit(1)
        }
    }

    static func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

// String repetition helper
extension String {
    static func * (left: String, right: Int) -> String {
        return String(repeating: left, count: right)
    }
}
