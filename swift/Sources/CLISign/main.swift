import CLICore
import DKLSLib
import Foundation
import MQTTNIO
import NIO

print(colorize("DKLS CLI Signing Test", .cyan))
print()

let args = ProcessInfo.processInfo.arguments
if args.count < 2 {
    print("Usage: \(args[0]) [keyshare filename]")
    exit(1)
}

let keyshare: Keyshare
do {
    keyshare = try Keyshare.fromBytes(bytes: Data(contentsOf: URL(fileURLWithPath: args[1])))
} catch {
    print("Error reading keyshare: \(error.localizedDescription)")
    exit(2)
}

let signNode: SignNode
print(
    colorize(
        "Paste the setup bytes from the other party, or press enter to start a new instance:", .red)
)

// TODO: Need the message to be signed!
// Also: the threshold, since we can't get that from Keyshare ?!?
let threshold: UInt8 = 2

let setupBase64 = readLine()!
let instanceID: InstanceId
if setupBase64.isEmpty {
    print(
        colorize(
            "What message do you want to sign?", .red)
    )
    let message = readLine()!
    instanceID = InstanceId.fromEntropy()
    signNode = SignNode.starter(
        message: message, instance: instanceID, threshold: threshold, keyshare: keyshare)

} else {
    do {
        signNode = try SignNode.fromRequestBytes(
            req: Data(base64Encoded: setupBase64)!, keyshare: keyshare)
    } catch {
        print(colorize("Error parsing setup bytes", .red))
        exit(3)
    }
}

let instanceStr = hexString(signNode.instanceId().toBytes())
print(
    colorize(
        "🆔 Using Instance ID: \(instanceStr)",
        .cyan))
print(
    colorize(
        "Settings: t = \(signNode.threshold()), i = \(signNode.partyId()), hash = \(hexString(signNode.hash()))",
        .cyan))
print(colorize("Request bytes:", .cyan))
print(signNode.requestBytes().base64EncodedString())
print()

let client = MQTTClient(
    host: ProcessInfo.processInfo.environment["MQTT_HOST"] ?? "localhost",
    port: Int(ProcessInfo.processInfo.environment["MQTT_PORT"] ?? "1883")!,
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
let reqInterface = MQTTInterface(
    client: client,
    topic: "sign_req/\(instanceStr)"
)

let service = MQTTInterface(
    client: client,
    topic: "sign/\(instanceStr)"
)

print(colorize("✓ Connected to message stream", .green))
print()

do {
    try await reqInterface.send(data: signNode.requestBytes())
    print(colorize("✓ Sent request string", .green))
} catch {
    print(colorize("Error sending request string: \(error)", .red))
    exit(1)
}

while signNode.numParties() < signNode.threshold() {
    do {
        print(colorize("Waiting for other party's request string...", .yellow))
        let data = try await reqInterface.receive()
        print(colorize("Received Request String: \(data.count) bytes", .magenta))
        try signNode.updateFromBytes(req: data)
    } catch {
        print(colorize("Error receiving messages: \(error)", .red))
        exit(1)
    }
}

print(colorize("✓ All parties have joined", .green))
print()

do {
    print(colorize("Generating signature...", .yellow))
    let sig = try await signNode.doSign(interface: service)
    print(colorize("✓ Signature generated", .green))
    print()
    print(colorize("Signature bytes: \(sig.toBytes().count) bytes", .magenta))
    print(hexString(sig.toBytes()))
    print()
    try keyshare.vk().verify(msg: signNode.message(), sig: sig)
    print(colorize("✓ Signature verified", .green))
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
