import Foundation

public enum UnfairError: Error, CustomStringConvertible {
    case usage(String)
    case io(String)
    case invalidMachO(String)
    case noArm64Slice(String)
    case missingRootSinf
    case mremapUnavailable
    case decryptFailed(String)
    case panic(String)

    public var description: String {
        switch self {
        case .usage(let message),
             .io(let message),
             .invalidMachO(let message),
             .decryptFailed(let message),
             .panic(let message):
            return message
        case .noArm64Slice(let path):
            return "no supported arm64 slice: \(path)"
        case .missingRootSinf:
            return "SC_Info precheck failed: root sinf source missing"
        case .mremapUnavailable:
            return "mremap_encrypted unavailable on this platform"
        }
    }
}

public struct UnfairLogger {
    public var log: (String) -> Void
    public var isVerbose: Bool

    public init(verbose: Bool = false, log: @escaping (String) -> Void = { print("[unfair] \($0)") }) {
        self.isVerbose = verbose
        self.log = log
    }

    public func verbose(_ message: String) {
        if isVerbose {
            log(message)
        }
    }
}
