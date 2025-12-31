import DKLSLib
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

@main
struct MessagingCLI {
    static func main() async {
        print(colorize("🔥 Firebase Messaging CLI", .cyan))
        print(colorize("=" * 50, .cyan))
        print()

        do {
            // Parse arguments
            let args = ProcessInfo.processInfo.arguments
            let instanceID =
                (args.count > 1 ? Data(base64Encoded: args[1]) : nil)
                ?? InstanceId.fromEntropy().toBytes()

            print(colorize("🆔 Using Instance ID: \(instanceID.base64EncodedString())", .cyan))

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
            let service = MessagingService.getInstance(instanceID: instanceID, sender: userId)

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

            print(colorize("✓ Connected to message stream", .green))
            print()

            // Ignore the default action for SIGINT to allow our DispatchSource to handle it
            signal(SIGINT, SIG_IGN)

            // Set up signal handler for graceful shutdown
            let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            signalSource.setEventHandler {
                print()
                print(colorize("\n👋 Shutting down...", .yellow))
                service.stopListening()
                exit(0)
            }
            signalSource.resume()

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
