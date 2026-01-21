import ArgumentParser
import CLICore
import DKLSLib
import Foundation
import MQTTNIO
import NIO

func verifySig(sig: Signature, message: Data, vk: NodeVerifyingKey) {
    do {
        print(colorize("✓ Signature generated", .green))
        print()
        print(colorize("Signature bytes: \(sig.toBytes().count) bytes", .magenta))
        print(hexString(sig.toBytes()))
        print()
        try vk.verify(msg: message, sig: sig)
        print(colorize("✓ Signature verified", .green))
    } catch {
        print(colorize("Error: \(error)", .red))
    }
}

struct SignArgs: ParsableCommand {
    @Argument(help: "Keyshare filename.")
    var keyshareFilename: String

    @Option(name: .shortAndLong, help: "Message to sign.")
    var message: String = ""

    @Option(name: .long, help: "MQTT host.")
    var mqttHost: String = "localhost"

    @Option(name: .long, help: "MQTT port.")
    var mqttPort: Int = 1883
}

print(colorize("DKLS CLI Signing Test", .cyan))
print()

let signArgs: SignArgs
do {
    signArgs = try SignArgs.parse()
} catch {
    print(colorize("Error parsing arguments: \(error)", .red))
    exit(1)
}

let keyshare: Keyshare
do {
    keyshare = try Keyshare.fromBytes(
        bytes: Data(contentsOf: URL(fileURLWithPath: signArgs.keyshareFilename)))
} catch {
    print("Error reading keyshare: \(error.localizedDescription)")
    exit(2)
}
print("MQTT host: \(signArgs.mqttHost)")
print("MQTT port: \(signArgs.mqttPort)")
print()

let client = MQTTClient(
    host: signArgs.mqttHost,
    port: signArgs.mqttPort,
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

print(colorize("👂 Listening for messages...", .yellow))
let netInterface = MQTTInterface(
    client: client,
    topic: "sign/"
)

let sk = NodeSecretKey.fromEntropy()
let signNode = SignNode.init(secretKey: sk, keyshare: keyshare)

if signArgs.message.isEmpty {
    while true {
        do {
            let req = try await signNode.getNextReq(netIf: netInterface)
            try req.checkSigs()
            print(colorize("Received signature request:", .magenta))
            print("InstanceID: \(hexString(req.instance().toBytes()))")
            print("Message:")
            print(String(data: req.message(), encoding: .utf8)!)
            print("Approve? [y/N]")
            let approval = readLine()!
            if approval.lowercased() != "y" {
                continue
            }
            let message = req.message()
            let sig = try await signNode.doJoinRequest(req: req, netIf: netInterface)
            verifySig(sig: sig, message: message, vk: keyshare.vk())
            break
        } catch {
            print(colorize("Error: \(error)", .red))
        }
    }
} else {
    do {
        print("Requesting signature for message: \(signArgs.message)")
        let message = Data(signArgs.message.utf8)
        let sig = try await signNode.doSignBytes(bytes: message, netIf: netInterface)
        verifySig(sig: sig, message: message, vk: keyshare.vk())
    } catch {
        print(colorize("Error: \(error)", .red))
    }
}

print(colorize("Disconnecting...", .yellow))
do {
    try await client.disconnect().get()
    try client.syncShutdownGracefully()
    print(colorize("Goodbye!", .green))
} catch {
    print(colorize("Error while disconnecting \(error)", .red))
}
