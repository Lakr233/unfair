import Foundation
import ZIPFoundation

public final class PackageProcessor {
    private let logger: UnfairLogger

    public init(logger: UnfairLogger = UnfairLogger()) {
        self.logger = logger
    }

    public func process(input: URL, output: URL, workingDirectory providedWorkingDirectory: URL? = nil) throws {
        let workingDirectory = try prepareWorkingDirectory(providedWorkingDirectory)
        defer { FileSystem.removeTree(workingDirectory) }

        logger.verbose("temp dir: \(workingDirectory.path)")
        try extractIPA(input, to: workingDirectory)

        let payloadURL = try payloadDirectory(in: workingDirectory)
        logger.log("payload: payload")
        FileSystem.clearExtendedAttributesRecursively(at: workingDirectory)

        var decryptedRecords: [MachORecord] = []
        for app in try appBundles(in: payloadURL) {
            decryptedRecords.append(contentsOf: try processAppBundle(app))
        }

        let destination = destinationPath(input: input, output: output)
        let archiveOutput = workingDirectory.appendingPathComponent("output.ipa")
        try writeArchive(input: input, decryptedRecords: decryptedRecords, to: archiveOutput)
        try copyArchive(archiveOutput, to: destination)
        logger.log("output: \(destination.path)")
    }

    private func writeArchive(input: URL, decryptedRecords: [MachORecord], to destination: URL) throws {
        try FileSystem.createDirectory(destination.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.copyItem(at: input, to: destination)

        let archive = try Archive(url: destination, accessMode: .update, pathEncoding: nil)
        try removeSymlinkEntries(in: archive)

        for record in decryptedRecords {
            try replaceEntry(for: record, in: archive)
        }
    }

    private func removeSymlinkEntries(in archive: Archive) throws {
        let symlinks = archive.filter { $0.type == .symlink }
        for entry in symlinks {
            logger.verbose("skipped symlink in output: \(entry.path)")
            try archive.remove(entry)
        }
    }

    private func replaceEntry(for record: MachORecord, in archive: Archive) throws {
        let path = "Payload/" + record.displayPath
        guard let entry = archive[path] else {
            throw UnfairError.io("archive entry missing: \(path)")
        }
        guard entry.type != .symlink else {
            logger.verbose("skipped symlink update: \(path)")
            return
        }

        let attributes = entry.fileAttributes
        let modificationDate = attributes[.modificationDate] as? Date ?? Date()
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? defaultFilePermissions
        let compressionMethod: CompressionMethod = entry.isCompressed ? .deflate : .none
        let fileSize = try FileSystem.fileSize(record.url)

        let handle = try FileHandle(forReadingFrom: record.url)
        defer { try? handle.close() }
        let provider: Provider = { position, size in
            try handle.seek(toOffset: UInt64(position))
            return handle.readData(ofLength: size)
        }

        try archive.remove(entry)
        try archive.addEntry(
            with: path,
            type: .file,
            uncompressedSize: fileSize,
            modificationDate: modificationDate,
            permissions: permissions,
            compressionMethod: compressionMethod,
            provider: provider
        )
    }

    private func processAppBundle(_ appURL: URL) throws -> [MachORecord] {
        let label = appURL.lastPathComponent
        logger.log("app: \(label)")

        let records = try MachOInspector.scanBinaries(appURL: appURL, label: label)
        let encryptedRecords = records.filter(\.isEncrypted)
        logScan(records, encryptedRecords: encryptedRecords)

        guard let rootSinf = findRootSinf(appURL: appURL, records: records) else {
            throw UnfairError.missingRootSinf
        }

        try decrypt(records: encryptedRecords, rootSinf: rootSinf)
        try verifyDecryptedBinaries(in: appURL, label: label)
        return encryptedRecords
    }

    private func logScan(_ records: [MachORecord], encryptedRecords: [MachORecord]) {
        logger.log("mach-o binaries scanned: \(records.count)")
        for record in encryptedRecords {
            logger.verbose("encrypted mach-o: \(record.displayPath)")
        }
        logger.log("encrypted binaries found: \(encryptedRecords.count)")
    }

    private func decrypt(records: [MachORecord], rootSinf: URL) throws {
        let decryptor = BinaryDecryptor(logger: logger)
        let previousDirectory = FileManager.default.currentDirectoryPath
        defer { FileManager.default.changeCurrentDirectoryPath(previousDirectory) }

        for record in records {
            let binaryDir = record.url.deletingLastPathComponent()
            try validateXRootLocation(record.url, label: "binary")
            logger.verbose("cwd: \(binaryDir.path)")
            FileManager.default.changeCurrentDirectoryPath(binaryDir.path)
            try decryptor.decryptBinary(
                at: URL(fileURLWithPath: record.name),
                rootSinf: rootSinf,
                displayPath: record.displayPath
            )
        }
    }

    private func verifyDecryptedBinaries(in appURL: URL, label: String) throws {
        let records = try MachOInspector.scanBinaries(appURL: appURL, label: label)
        let remaining = records.filter(\.isEncrypted)
        guard remaining.isEmpty else {
            logRemainingEncryptedBinaries(remaining)
            throw UnfairError.panic("encrypted binaries remain")
        }
    }

    private func logRemainingEncryptedBinaries(_ records: [MachORecord]) {
        logger.log("panic: \(records.count) encrypted binaries still have cryptid 1")
        for record in records {
            logger.log("encrypted mach-o: \(record.displayPath)")
        }
    }

    private func extractIPA(_ input: URL, to tempDir: URL) throws {
        let archive = try Archive(url: input, accessMode: .read, pathEncoding: nil)
        for entry in archive {
            if entry.type == .symlink {
                logger.verbose("skipped symlink on extract: \(entry.path)")
                continue
            }

            let entryURL = tempDir.appendingPathComponent(entry.path)
            guard isContained(entryURL, in: tempDir) else {
                throw UnfairError.io("archive entry escapes extraction directory: \(entry.path)")
            }

            _ = try archive.extract(entry, to: entryURL)
        }
    }

    private func payloadDirectory(in root: URL) throws -> URL {
        guard let payloadURL = findPayload(in: root) else {
            throw UnfairError.io("ERROR: Payload directory missing after extract")
        }
        return payloadURL
    }

    private func findPayload(in root: URL) -> URL? {
        if (try? root.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
            return nil
        }

        let candidate = root.appendingPathComponent("Payload", isDirectory: true)
        let candidateValues = try? candidate.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        if candidateValues?.isSymbolicLink != true, candidateValues?.isDirectory == true {
            return candidate
        }

        guard let children = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else {
            return nil
        }
        for child in children {
            if let found = findPayload(in: child) {
                return found
            }
        }
        return nil
    }

    private func appBundles(in payloadURL: URL) throws -> [URL] {
        let children = try FileManager.default.contentsOfDirectory(at: payloadURL, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        let apps = try children.filter { url in
            guard url.pathExtension == "app" else {
                return false
            }
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            return values.isSymbolicLink != true && values.isDirectory == true
        }
        guard apps.isEmpty == false else {
            throw UnfairError.io("ERROR: no Payload/*.app directory found")
        }
        return apps
    }

    private func findRootSinf(appURL: URL, records: [MachORecord]) -> URL? {
        for record in records where record.isEncrypted {
            guard record.url.deletingLastPathComponent().standardizedFileURL == appURL.standardizedFileURL else {
                continue
            }
            let source = appURL
                .appendingPathComponent("SC_Info", isDirectory: true)
                .appendingPathComponent(record.name + ".sinf")
            if FileManager.default.fileExists(atPath: source.path) {
                return source
            }
        }
        return nil
    }

    private func destinationPath(input: URL, output: URL) -> URL {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: output.path, isDirectory: &isDirectory), isDirectory.boolValue {
            let name = input.deletingPathExtension().lastPathComponent + ".unfair.ipa"
            return output.appendingPathComponent(name)
        }
        return output
    }

    private func copyArchive(_ source: URL, to destination: URL) throws {
        try FileSystem.createDirectory(destination.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.copyItem(at: source, to: destination)
    }

    private func prepareWorkingDirectory(_ providedWorkingDirectory: URL?) throws -> URL {
        if let providedWorkingDirectory = providedWorkingDirectory {
            let directory = providedWorkingDirectory.standardizedFileURL
            try validateXRootLocation(directory, label: "working directory")
            FileSystem.removeTree(directory)
            try FileSystem.createDirectory(directory)
            return directory
        }
        return try createWorkingDirectory()
    }

    private func createWorkingDirectory() throws -> URL {
        let tmpDir = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        let root = URL(fileURLWithPath: tmpDir, isDirectory: true)
            .deletingLastPathComponent()
            .appendingPathComponent("X", isDirectory: true)
            .appendingPathComponent("unfair", isDirectory: true)
        try FileSystem.createDirectory(root)
        let dir = root.appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
        try FileSystem.createDirectory(dir)
        return dir.standardizedFileURL
    }

    private func validateXRootLocation(_ url: URL, label: String) throws {
        let paths = [
            url.standardizedFileURL.path,
            url.standardizedFileURL.resolvingSymlinksInPath().path,
        ]
        guard paths.contains(where: isInsideRequiredXRoot) else {
            throw UnfairError.io("\(label) must be inside /var/folders/bg/<token>/X: \(url.path)")
        }
    }

    private func isInsideRequiredXRoot(_ path: String) -> Bool {
        var components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        if components.count > 1, components[1] == "private" {
            components.remove(at: 1)
        }
        guard components.count > 6 else {
            return false
        }
        return components[0] == "/"
            && components[1] == "var"
            && components[2] == "folders"
            && components[3] == "bg"
            && components[5] == "X"
    }

    private func isContained(_ url: URL, in root: URL) -> Bool {
        let path = url.standardizedFileURL.path
        let rootPath = root.standardizedFileURL.path
        return path == rootPath || path.hasPrefix(rootPath + "/")
    }
}
