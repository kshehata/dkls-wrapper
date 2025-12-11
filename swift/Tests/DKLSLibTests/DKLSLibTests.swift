import Testing

@testable import DKLSLib

@Test func example() async throws {
    #expect(swift_add(left: 2, right: 2) == 4)
}

@Test func runDKG() async throws {
    let instance = InstanceId.fromEntropy()
    var nodes: [DkgNode] = [DkgNode.starter(instance: instance, threshold: 2)]
    for i in 1...2 {
        nodes.append(
            DkgNode.init(instance: instance, threshold: 2, partyVk: nodes[i - 1].partyVk()))
        let new_vk = nodes[i].myVk()
        for j in 0..<i {
            nodes[j].addParty(partyVk: new_vk)
        }
    }
    let runner = DkgRunner.init()
    runner.initializeTokioRuntime()
    let shares = try await withThrowingTaskGroup(of: Keyshare.self) { group in
        // Spawn a task for each node
        for node in nodes {
            group.addTask {
                try await runner.run(node: node)
            }
        }

        // Collect all results
        var results: [Keyshare] = []
        for try await share in group {
            results.append(share)
        }
        return results
    }
    #expect(shares.count == 3)
    for s in shares {
        s.print()
    }
}
