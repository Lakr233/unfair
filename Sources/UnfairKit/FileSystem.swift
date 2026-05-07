import Darwin
import Foundation

enum FileSystem {
    static func createDirectory(_ url: URL) throws {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw UnfairError.io("path exists and is not a directory: \(url.path)")
            }
            return
        }

        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try chmod(url, mode: 0o755)
    }

    static func chmod(_ url: URL, mode: mode_t) throws {
        guard Darwin.chmod(url.path, mode) == 0 else {
            throw UnfairError.io("chmod failed: \(url.path): \(String(cString: strerror(errno)))")
        }
    }

    static func fileSize(_ url: URL) throws -> Int64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber else {
            throw UnfairError.io("file size missing: \(url.path)")
        }
        return size.int64Value
    }

    static func sameFile(_ left: URL, _ right: URL) -> Bool {
        var leftStat = stat()
        var rightStat = stat()
        guard stat(left.path, &leftStat) == 0, stat(right.path, &rightStat) == 0 else {
            return false
        }
        return leftStat.st_dev == rightStat.st_dev && leftStat.st_ino == rightStat.st_ino
    }

    static func removeTree(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    static func clearExtendedAttributesRecursively(at url: URL) {
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil, options: []) else {
            clearExtendedAttributes(at: url)
            return
        }
        clearExtendedAttributes(at: url)
        for case let child as URL in enumerator {
            clearExtendedAttributes(at: child)
        }
    }

    private static func clearExtendedAttributes(at url: URL) {
        let length = listxattr(url.path, nil, 0, XATTR_NOFOLLOW)
        guard length > 0 else {
            return
        }

        var names = [CChar](repeating: 0, count: length)
        let read = listxattr(url.path, &names, length, XATTR_NOFOLLOW)
        guard read > 0 else {
            return
        }

        var index = 0
        while index < read {
            let name = names.withUnsafeBufferPointer { buffer in
                String(cString: buffer.baseAddress!.advanced(by: index))
            }
            removexattr(url.path, name, XATTR_NOFOLLOW)
            index += name.utf8.count + 1
        }
    }
}
