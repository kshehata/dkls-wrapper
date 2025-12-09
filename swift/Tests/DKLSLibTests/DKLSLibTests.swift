import Testing

@testable import DKLSLib

@Test func example() async throws {
    #expect(swift_add(left: 2, right: 2) == 4)
}

@Test func exampleDirect() async throws {
    #expect(rustAdd(left: 2, right: 2) == 4)
}
