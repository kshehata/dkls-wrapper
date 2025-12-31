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
        print(colorize("DKLS CLI DKG Test", .cyan))
        print(colorize("=" * 50, .cyan))
        print()

        do {
            // Parse arguments
            let args = ProcessInfo.processInfo.arguments
            guard args.count >= 5 else {
                print(
                    colorize(
                        "Usage: \(args[0]) <instanceID|-> <numParties> <threshold> <partyIndex>",
                        .red))
                return
            }

            let numParties = UInt8(args[2])!
            let threshold = UInt8(args[3])!
            let partyIndex = UInt8(args[4])!

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

            print(colorize("🆔 Using Instance ID: \(instanceID.toBytes().base64EncodedString())", .cyan))
            print(
                colorize("Settings: n = \(numParties), t = \(threshold), i = \(partyIndex)", .cyan))

            print(colorize("Setting up DKG node...", .yellow))
            let dkgNode = DkgNode.forId(
                instance: instanceID, threshold: threshold, numParties: numParties,
                partyId: partyIndex)
            print(colorize("✓ DKG node set up", .green))

            // Configure Firebase
            print(colorize("📱 Configuring Firebase...", .yellow))
            try FirebaseConfig.shared.configure()
            print(colorize("✓ Firebase configured", .green))

            // Start listening to messages
            print(colorize("👂 Listening for messages...", .yellow))
            let service = MessagingService.getInstance(
                instanceID: instanceID.toBytes(), sender: String(partyIndex))
            print(colorize("✓ Connected to message stream", .green))
            print()

            print(colorize("Generating key shares...", .yellow))
            let share = try await dkgNode.doKeygen(interface: service)
            print(colorize("✓ Key shares generated", .green))
            print()
            share.print()

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
