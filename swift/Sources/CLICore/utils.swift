import Foundation

// ANSI color codes for terminal output
public enum Color: String {
    case reset = "\u{001B}[0m"
    case red = "\u{001B}[31m"
    case green = "\u{001B}[32m"
    case yellow = "\u{001B}[33m"
    case blue = "\u{001B}[34m"
    case magenta = "\u{001B}[35m"
    case cyan = "\u{001B}[36m"
}

public func colorize(_ text: String, _ color: Color) -> String {
    return "\(color.rawValue)\(text)\(Color.reset.rawValue)"
}

public func hexString(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

public func checkWriteable(_ path: String) -> Bool {
    let fm = FileManager.default
    let dest = path
    let parent = (dest as NSString).deletingLastPathComponent
    let checkPath = fm.fileExists(atPath: dest) ? dest : (parent.isEmpty ? "." : parent)
    return fm.isWritableFile(atPath: checkPath)
}
