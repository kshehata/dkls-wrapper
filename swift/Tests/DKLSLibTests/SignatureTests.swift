import Foundation
import Testing

@testable import DKLSLib

@Test func testSignature() async throws {
    let shares = genKeyshares(t: 3, n: 3)
    let party_sk = genRandomKeys(n: 3)
    let bridge = TestMemoryBridge()

    // Setup nodes
    var nodes: [SignNode] = []
    var netIfs: [BridgeNetworkInterface] = []

    for (sk, share) in zip(party_sk, shares) {
        let node = SignNode(secretKey: sk, keyshare: share)
        let netIf = BridgeNetworkInterface(bridge: bridge)
        await netIf.connect()
        nodes.append(node)
        netIfs.append(netIf)
    }

    let message = "Hello World"
    let msgData = Data(message.utf8)

    // Run in parallel
    let signatures = try await withThrowingTaskGroup(of: Signature.self) { group in
        // Node 0 initiates
        group.addTask {
            let node = nodes[0]
            let netIf = netIfs[0]
            return try await node.doSignString(string: message, netIf: netIf)
        }

        // Give the initiator a moment to send the request
        try await Task.sleep(nanoseconds: 100 * 1_000_000)

        // Other nodes join
        for i in 1..<3 {
            group.addTask {
                let node = nodes[i]
                let netIf = netIfs[i]
                // 1. Get request from network
                let req = try await node.getNextReq(netIf: netIf)
                // 2. Join request
                return try await node.doJoinRequest(req: req, netIf: netIf)
            }
        }

        var results: [Signature] = []
        for try await sig in group {
            results.append(sig)
        }
        return results
    }

    #expect(signatures.count == 3)
    // Verification
    let vk = shares[0].vk()
    for sig in signatures {
        try vk.verify(msg: msgData, sig: sig)
    }
}
