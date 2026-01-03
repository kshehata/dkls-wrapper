import Foundation
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
            try DkgNode.fromSetupString(setupStr: nodes[i - 1].setupString()))
        let setupStr = nodes[i].setupString()
        for j in 0..<i {
            try nodes[j].updateFrom(setupStr: setupStr)
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

final class NetworkMirror: NetworkInterface {
    let semaphore = DispatchSemaphore(value: 0)
    var buffer: Data
    init() {
        self.buffer = Data()
    }

    func send(data: Data) async throws {
        print("I sleep.")
        await Task.sleep(100)
        print("Sending data: \(data)")
        buffer = data
        semaphore.signal()
    }

    func receive() async throws -> Data {
        let result = semaphore.wait(timeout: .now() + 0.001)
        guard result == .success else { throw NetworkError.MessageSendError }
        print("Receiving data: \(buffer)")
        return buffer
    }
}

@Test func network_interface_test() async throws {
    let mirror = NetworkMirror()
    let tester = NetworkInterfaceTester(interface: mirror)
    try await tester.test()
}

final class MockNetworkInterface: NetworkInterface {
    let send_result: Result<(), NetworkError>
    let send_delay: UInt64
    let receive_result: Result<Data, NetworkError>
    let received_delay: UInt64

    init(
        send_result: Result<(), NetworkError> = .success(()),
        send_delay: UInt64 = 0,
        receive_result: Result<Data, NetworkError> = .success(Data()),
        received_delay: UInt64 = 0
    ) {

        self.send_result = send_result
        self.send_delay = send_delay
        self.receive_result = receive_result
        self.received_delay = received_delay
    }

    func send(data: Data) async throws {
        if send_delay > 0 {
            await Task.sleep(send_delay)
        }
        try send_result.get()
    }

    func receive() async throws -> Data {
        if received_delay > 0 {
            await Task.sleep(received_delay)
        }
        return try receive_result.get()
    }
}

@Test func network_interface_send_fail() async throws {
    let network_interface = MockNetworkInterface(
        send_result: .failure(NetworkError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) { try await tester.test() }
}

@Test func network_interface_receive_fail() async throws {
    let network_interface = MockNetworkInterface(
        receive_result: .failure(NetworkError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) { try await tester.test() }
}

@Test func network_interface_receive_wrong_data() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data()), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) { try await tester.test() }
}

@Test func network_interface_receive_wrong_data2() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data([1, 2, 3, 5])), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) { try await tester.test() }
}

@Test func network_relay_test() async throws {
    let mirror = NetworkMirror()
    let tester = NetworkInterfaceTester(interface: mirror)
    try await tester.testRelay(data: Data([1, 2, 3, 4]))
}

@Test func network_relay_send_fail() async throws {
    let network_interface = MockNetworkInterface(
        send_result: .failure(NetworkError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_fail() async throws {
    let network_interface = MockNetworkInterface(
        receive_result: .failure(NetworkError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_wrong_data() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data()), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_wrong_data2() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data([1, 2, 3, 5])), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: NetworkError.MessageSendError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}
