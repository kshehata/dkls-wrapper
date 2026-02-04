import Foundation
import Testing

@testable import DKLSLib

@Test func example() async throws {
    #expect(swift_add(left: 2, right: 2) == 4)
}

actor TestMemoryBridge {
    var listeners: [UUID: AsyncStream<Data>.Continuation] = [:]

    func register(id: UUID, continuation: AsyncStream<Data>.Continuation) {
        listeners[id] = continuation
    }

    func broadcast(sender: UUID, data: Data) {
        for (id, continuation) in listeners {
            if id != sender {
                continuation.yield(data)
            }
        }
    }
}

final class BridgeNetworkInterface: NetworkInterface, @unchecked Sendable {
    let bridge: TestMemoryBridge
    let id: UUID
    let stream: AsyncStream<Data>
    var iterator: AsyncStream<Data>.Iterator
    var continuation: AsyncStream<Data>.Continuation!

    init(bridge: TestMemoryBridge) {
        self.bridge = bridge
        self.id = UUID()
        var continuation: AsyncStream<Data>.Continuation!
        self.stream = AsyncStream<Data> { continuation = $0 }
        self.iterator = self.stream.makeAsyncIterator()
        self.continuation = continuation
    }

    func connect() async {
        await bridge.register(id: self.id, continuation: continuation)
    }

    func send(data: Data) async throws {
        await bridge.broadcast(sender: id, data: data)
    }

    func receive() async throws -> Data {
        guard let data = await iterator.next() else {
            throw GeneralError.MessageSendError
        }
        return data
    }
}

final class TestSetupListener: DkgSetupChangeListener, @unchecked Sendable {
    var count: Int = 0
    let lock = NSLock()

    func onSetupChanged(devices: [DeviceInfo], myId: UInt8) {
        lock.lock()
        count = devices.count
        lock.unlock()
    }

    func getCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }
}

@Test func runDKG() async throws {
    let instance = InstanceId.fromEntropy()
    let setupBridge = TestMemoryBridge()
    let dkgBridge = TestMemoryBridge()
    let listener = TestSetupListener()

    // Run them
    let shares = try await withThrowingTaskGroup(of: Keyshare.self) { group in
        // Create Node 1 (Starter)
        let node1Setup = BridgeNetworkInterface(bridge: setupBridge)
        await node1Setup.connect()
        let node1Dkg = BridgeNetworkInterface(bridge: dkgBridge)
        await node1Dkg.connect()

        let node1 = DkgNode(
            name: "Node 1",
            instance: instance,
            threshold: 2,
            setupIf: node1Setup,
            dkgIf: node1Dkg
        )
        node1.addSetupChangeListener(listener: listener)

        let qrBytes = try node1.getQrBytes()
        let qr = try QrData.fromBytes(bytes: qrBytes)

        // Start Node 1 Task
        group.addTask {
            try await node1.messageLoop()
            return try node1.getResult()
        }

        // Give Node 1 a moment to initialize
        try await Task.sleep(nanoseconds: 100 * 1_000_000)

        // Create Node 2
        let node2Setup = BridgeNetworkInterface(bridge: setupBridge)
        await node2Setup.connect()
        let node2Dkg = BridgeNetworkInterface(bridge: dkgBridge)
        await node2Dkg.connect()

        let node2 = DkgNode.fromQr(
            name: "Node 2",
            qrData: qr,
            setupIf: node2Setup,
            dkgIf: node2Dkg
        )

        // Start Node 2 Task
        group.addTask {
            try await node2.messageLoop()
            return try node2.getResult()
        }

        // Give Node 2 a moment to connect and send Join
        try await Task.sleep(nanoseconds: 100 * 1_000_000)

        // Create Node 3
        let node3Setup = BridgeNetworkInterface(bridge: setupBridge)
        await node3Setup.connect()
        let node3Dkg = BridgeNetworkInterface(bridge: dkgBridge)
        await node3Dkg.connect()

        let node3 = DkgNode.fromQr(
            name: "Node 3",
            qrData: qr,
            setupIf: node3Setup,
            dkgIf: node3Dkg
        )

        // Start Node 3 Task
        group.addTask {
            try await node3.messageLoop()
            return try node3.getResult()
        }

        // Wait for all 3 nodes and Node 1 Ready state
        while true {
            let count = listener.getCount()
            let state = node1.getState()
            if count >= 3 && state == .ready {
                break
            }
            try await Task.sleep(nanoseconds: 100 * 1_000_000)
        }

        // Start DKG
        try await node1.startDkg()

        var results: [Keyshare] = []
        for try await share in group {
            results.append(share)
        }
        return results
    }

    #expect(shares.count == 3)
    let firstVk = shares[0].vk().toBytes()
    for s in shares {
        s.print()
        #expect(s.vk().toBytes() == firstVk)
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
        guard result == .success else {
            throw GeneralError.MessageSendError
        }
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
    let send_result: Result<(), GeneralError>
    let send_delay: UInt64
    let receive_result: Result<Data, GeneralError>
    let received_delay: UInt64

    init(
        send_result: Result<(), GeneralError> = .success(()),
        send_delay: UInt64 = 0,
        receive_result: Result<Data, GeneralError> = .success(Data()),
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
        send_result: .failure(GeneralError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) { try await tester.test() }
}

@Test func network_interface_receive_fail() async throws {
    let network_interface = MockNetworkInterface(
        receive_result: .failure(GeneralError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) { try await tester.test() }
}

@Test func network_interface_receive_wrong_data() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data()), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) { try await tester.test() }
}

@Test func network_interface_receive_wrong_data2() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data([1, 2, 3, 5])), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) { try await tester.test() }
}

@Test func network_relay_test() async throws {
    let mirror = NetworkMirror()
    let tester = NetworkInterfaceTester(interface: mirror)
    try await tester.testRelay(data: Data([1, 2, 3, 4]))
}

@Test func network_relay_send_fail() async throws {
    let network_interface = MockNetworkInterface(
        send_result: .failure(GeneralError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_fail() async throws {
    let network_interface = MockNetworkInterface(
        receive_result: .failure(GeneralError.MessageSendError))
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_wrong_data() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data()), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}

@Test func network_relay_receive_wrong_data2() async throws {
    let network_interface = MockNetworkInterface(
        send_delay: 100, receive_result: .success(Data([1, 2, 3, 5])), received_delay: 100)
    let tester = NetworkInterfaceTester(interface: network_interface)
    await #expect(throws: GeneralError.self) {
        try await tester.testRelay(data: Data([1, 2, 3, 4]))
    }
}
