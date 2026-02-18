import ArgumentParser
import CLICore
import DKLSLib
import Foundation
import MQTTNIO
import NIO

final class ConsoleListener: SignRequestListener, SignResultListener, @unchecked Sendable {
    private let localData: DeviceLocalData
    private var pendingRequests: [SignRequest] = []
    private let lock = NSLock()

    init(localData: DeviceLocalData) {
        self.localData = localData
    }

    func receiveSignRequest(req: SignRequest) {
        print("\n*** NEW SIGN REQUEST ***")

        lock.lock()
        pendingRequests.append(req)
        let index = pendingRequests.count - 1
        lock.unlock()

        if let msg = req.getMessage() {
            switch msg {
            case .string(let s):
                print("Message: \(s)")
            case .bytes(let b):
                print("Bytes: \(b)")
            }
        }

        // Print sender information if available
        let partyVks = req.partyVk()
        if !partyVks.isEmpty {
            let vk = partyVks[0]
            let name =
                findDeviceByVk(devices: localData.getDeviceList(), vk: vk)?.name()
                ?? "Unknown Device"
            print("From: \(name) (VK: \(hexString(vk.toBytes())))")
        }

        print("Request Added as #\(index). ID: \(hexString(req.instance().toBytes()))")
        print("Type 'a \(index)' to approve.")
        print("> ", terminator: "")
        fflush(stdout)
    }

    func signResult(req: SignRequest, result: Signature) {
        print("\n*** SIGNATURE GENERATED ***")
        print("Instance ID: \(hexString(req.instance().toBytes()))")
        print("Signature: \(hexString(result.toBytes()))")
        print("> ", terminator: "")
        fflush(stdout)
    }

    func signError(req: SignRequest, error: GeneralError) {
        print("\n*** SIGNING ERROR ***")
        print("Instance ID: \(hexString(req.instance().toBytes()))")
        print("Error: \(error)")
        print("> ", terminator: "")
        fflush(stdout)
    }

    func getPendingRequest(index: Int) -> SignRequest? {
        lock.lock()
        defer { lock.unlock() }
        if index >= 0 && index < pendingRequests.count {
            return pendingRequests[index]
        }
        return nil
    }

    func removePendingRequest(index: Int) {
        lock.lock()
        defer { lock.unlock() }
        if index >= 0 && index < pendingRequests.count {
            pendingRequests.remove(at: index)
        }
    }

    func listRequests() {
        lock.lock()
        defer { lock.unlock() }
        if pendingRequests.isEmpty {
            print("No pending requests.")
        } else {
            for (i, req) in pendingRequests.enumerated() {
                var messageDisplay = "<binary data>"
                if let msg = req.getMessage(), case .string(let s) = msg {
                    messageDisplay = s
                }
                print("[\(i)] \(messageDisplay) (ID: \(hexString(req.instance().toBytes())))")
            }
        }
    }
}

struct SignArgs: ParsableCommand {
    @Argument(help: "Keyshare filename.")
    var keyshareFilename: String

    @Option(name: .long, help: "MQTT host.")
    var mqttHost: String = "localhost"

    @Option(name: .long, help: "MQTT port.")
    var mqttPort: Int = 1883
}

@main
struct SignCLI {
    static func main() async {
        print(colorize("DKLS CLI Signing Tool", .cyan))

        let signArgs: SignArgs
        do {
            signArgs = try SignArgs.parse()
        } catch {
            print(colorize("Error parsing arguments: \(error)", .red))
            SignArgs.exit(withError: error)
        }

        print("Loading keyshare from \(signArgs.keyshareFilename)...")

        let localData: DeviceLocalData
        do {
            localData = try DeviceLocalData.fromBytes(
                bytes: Data(contentsOf: URL(fileURLWithPath: signArgs.keyshareFilename)))
        } catch {
            print("Error reading device data: \(error.localizedDescription)")
            exit(2)
        }
        print("Loaded ID: \(hexString(localData.keyId()))")

        let client = MQTTClient(
            host: signArgs.mqttHost,
            port: signArgs.mqttPort,
            identifier: "swift-\(ProcessInfo.processInfo.processIdentifier)",
            eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
            configuration: .init(version: .v5_0)
        )

        let keyIdStr = hexString(localData.keyId())
        let topic = "sign/\(keyIdStr)"
        print("Subscribing to \(topic)")

        do {
            _ = try await client.connect().get()
            print(colorize("Connected!", .green))
        } catch {
            print(colorize("Error connecting: \(error)", .red))
            exit(1)
        }

        let netInterface = MQTTInterface(
            client: client,
            topic: topic
        )

        let signNode = SignNode(ctx: localData, netIf: netInterface)
        let listener = ConsoleListener(localData: localData)

        signNode.setListener(listener: listener)
        signNode.setResultListener(listener: listener)

        // Run message loop in background
        Task.detached {
            do {
                try await signNode.messageLoop()
            } catch {
                print("Message loop error: \(error)")
            }
        }

        print("Ready.")
        print("Commands:")
        print("  s, sign <message>    - Request signature for a string message")
        print("  a, approve <index>   - Approve a pending request by index")
        print("  l, list              - List pending requests")
        print("  x, exit              - Exit")

        print("> ", terminator: "")
        fflush(stdout)

        while let input = readLine() {
            let trimmedInput = input.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedInput.isEmpty {
                print("> ", terminator: "")
                fflush(stdout)
                continue
            }

            let parts = trimmedInput.split(separator: " ", maxSplits: 1).map { String($0) }
            let command = parts[0]
            let params = parts.count > 1 ? parts[1] : ""

            switch command {
            case "s", "sign":
                if params.isEmpty {
                    print("Usage: s <message>")
                } else {
                    print("Requesting signature for: '\(params)'")
                    do {
                        try await signNode.requestSignString(message: params)
                        print("Request sent. Waiting for approval...")
                    } catch {
                        print("Error requesting signature: \(error)")
                    }
                }

            case "a", "approve":
                if let idx = Int(params) {
                    if let req = listener.getPendingRequest(index: idx) {
                        print("Approving request #\(idx)...")
                        listener.removePendingRequest(index: idx)  // Remove from list immediately?
                        do {
                            try await signNode.acceptRequest(req: req)
                            print("Approval sent.")
                        } catch {
                            print("Error approving: \(error)")
                        }
                    } else {
                        print("Invalid request index.")
                    }
                } else {
                    print("Usage: a <index>")
                }

            case "l", "list":
                listener.listRequests()

            case "x", "exit", "quit":
                print(colorize("Disconnecting...", .yellow))
                do {
                    try await client.disconnect().get()
                    try client.syncShutdownGracefully()
                    print(colorize("Goodbye!", .green))
                } catch {
                    print(colorize("Error while disconnecting \(error)", .red))
                }
                exit(0)

            default:
                print("Unknown command.")
            }

            print("> ", terminator: "")
            fflush(stdout)
        }
    }
}
