import FirebaseAuth
import FirebaseCore
import FirebaseFirestore
import Foundation

/// Firebase configuration and initialization
class FirebaseConfig {
    static let shared = FirebaseConfig()

    private var isConfigured = false
    private var currentUser: User?

    private init() {}

    /// Configure Firebase with GoogleService-Info.plist
    func configure() throws {
        guard !isConfigured else { return }

        // Find the GoogleService-Info.plist file
        guard let plistPath = findGoogleServicePlist() else {
            throw FirebaseConfigError.plistNotFound
        }

        // Configure Firebase with the plist
        guard let options = FirebaseOptions(contentsOfFile: plistPath) else {
            throw FirebaseConfigError.invalidPlist
        }

        let settings = FirestoreSettings()
        // Disable offline persistence
        settings.isPersistenceEnabled = false

        FirebaseApp.configure(options: options)
        let db = Firestore.firestore()
        db.settings = settings
        isConfigured = true
    }

    /// Sign in anonymously to Firebase
    func signInAnonymously() async throws -> User {
        if !isConfigured {
            try configure()
        }

        try Auth.auth().useUserAccessGroup(nil)
        let authResult = try await Auth.auth().signInAnonymously()
        currentUser = authResult.user
        return authResult.user
    }

    /// Get the current authenticated user
    func getCurrentUser() -> User? {
        return Auth.auth().currentUser ?? currentUser
    }

    /// Find GoogleService-Info.plist in various possible locations
    private func findGoogleServicePlist() -> String? {
        // Try current directory
        let currentDir = FileManager.default.currentDirectoryPath
        let currentDirPlist = "\(currentDir)/GoogleService-Info.plist"
        if FileManager.default.fileExists(atPath: currentDirPlist) {
            return currentDirPlist
        }

        // Try swift directory (for development)
        let swiftDirPlist = "\(currentDir)/swift/GoogleService-Info.plist"
        if FileManager.default.fileExists(atPath: swiftDirPlist) {
            return swiftDirPlist
        }

        // Try parent directory
        let parentDir = (currentDir as NSString).deletingLastPathComponent
        let parentDirPlist = "\(parentDir)/GoogleService-Info.plist"
        if FileManager.default.fileExists(atPath: parentDirPlist) {
            return parentDirPlist
        }

        // Try Resources directory in bundle
        if let bundlePath = Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") {
            return bundlePath
        }

        return nil
    }
}

/// Errors that can occur during Firebase configuration
enum FirebaseConfigError: Error, CustomStringConvertible {
    case plistNotFound
    case invalidPlist
    case authenticationFailed

    var description: String {
        switch self {
        case .plistNotFound:
            return
                "GoogleService-Info.plist not found. Please ensure it's in the current directory or swift directory."
        case .invalidPlist:
            return "GoogleService-Info.plist is invalid or corrupted."
        case .authenticationFailed:
            return "Failed to authenticate anonymously with Firebase."
        }
    }
}
