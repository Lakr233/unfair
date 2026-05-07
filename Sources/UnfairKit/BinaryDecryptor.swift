import Darwin
import Foundation
import MachO

public final class BinaryDecryptor {
    private let logger: UnfairLogger
    private typealias MremapEncrypted = @convention(c) (UnsafeMutableRawPointer?, Int, UInt32, UInt32, UInt32) -> Int32

    private struct TemporarySinf {
        var destination: URL
    }

    private enum DecryptionStatus {
        case decrypted
        case skipped
    }

    private let cpuTypeArm64 = UInt32(bitPattern: CPU_TYPE_ARM64)
    private let cpuSubtypeArm64All = UInt32(CPU_SUBTYPE_ARM64_ALL)

    public init(logger: UnfairLogger = UnfairLogger()) {
        self.logger = logger
    }

    public func decryptBinary(at url: URL, rootSinf: URL, displayPath: String? = nil) throws {
        let temporarySinf = try installTemporarySinf(for: url, rootSinf: rootSinf)
        defer { removeTemporarySinf(temporarySinf) }
        let status = try decryptBinaryInPlace(at: url)
        let label = displayPath ?? url.path
        switch status {
        case .decrypted:
            logger.log("decrypted: \(label)")
        case .skipped:
            logger.log("skipped: \(label)")
        }
    }

    private func installTemporarySinf(for url: URL, rootSinf: URL) throws -> TemporarySinf? {
        let scInfo = URL(fileURLWithPath: "SC_Info", isDirectory: true)
        try FileSystem.createDirectory(scInfo)

        let destination = scInfo.appendingPathComponent(url.lastPathComponent + ".sinf")
        if FileSystem.sameFile(rootSinf, destination) {
            return nil
        }

        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }

        logger.verbose("sinf copy: root sinf -> ./SC_Info/\(url.lastPathComponent).sinf")
        try FileManager.default.copyItem(at: rootSinf, to: destination)
        return TemporarySinf(destination: destination)
    }

    private func removeTemporarySinf(_ temporarySinf: TemporarySinf?) {
        guard let temporarySinf = temporarySinf else {
            return
        }
        try? FileManager.default.removeItem(at: temporarySinf.destination)
    }

    private func decryptBinaryInPlace(at url: URL) throws -> DecryptionStatus {
        logger.verbose("target: \(url.path)")
        logger.verbose("opening \(url.path) (read-write)")

        let fd = open(url.path, O_RDWR)
        guard fd >= 0 else {
            throw UnfairError.io("open failed: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }

        var statInfo = stat()
        guard fstat(fd, &statInfo) == 0 else {
            throw UnfairError.io("fstat failed: \(String(cString: strerror(errno)))")
        }
        let fileSize = Int(statInfo.st_size)
        logger.verbose("file size: \(fileSize) bytes")
        guard fileSize > 0 else {
            throw UnfairError.invalidMachO("invalid file size")
        }

        guard let mapped = mmap(nil, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
              mapped != MAP_FAILED else {
            throw UnfairError.io("mmap failed: \(String(cString: strerror(errno)))")
        }
        defer { munmap(mapped, fileSize) }

        let rawBase = UnsafeRawPointer(mapped)
        let slice = try MachOInspector.selectArm64Slice(base: rawBase, size: fileSize, logger: logger)
        let sliceBase = mapped.advanced(by: slice.offset)
        let sliceRawBase = UnsafeRawPointer(sliceBase)

        let header = sliceRawBase.load(as: mach_header_64.self)
        logger.verbose("mach-o header: magic=0x\(String(header.magic, radix: 16))  ncmds=\(header.ncmds)  sizeofcmds=0x\(String(header.sizeofcmds, radix: 16))")

        guard let enc = try MachOInspector.findEncryptionInfo(base: sliceRawBase, size: slice.size) else {
            logger.verbose("warning: lc_encryption_info_64 not found")
            return .skipped
        }
        logger.verbose("encryption info command: cmd_offset=0x\(String(enc.commandOffset, radix: 16))")

        if enc.cryptid == 0 {
            logger.verbose("cryptid is 0; skipping")
            return .skipped
        }

        guard MachOInspector.hasRange(size: slice.size, offset: Int(enc.cryptoff), length: Int(enc.cryptsize)) else {
            throw UnfairError.invalidMachO("invalid encrypted region")
        }

        try unprotectRegion(fd: fd, fileOffset: slice.offset, sliceBase: sliceBase, sliceSize: slice.size, info: enc)

        let infoPointer = sliceBase.advanced(by: enc.commandOffset).assumingMemoryBound(to: encryption_info_command_64.self)
        if infoPointer.pointee.cryptid != 0 {
            infoPointer.pointee.cryptid = 0
            logger.verbose("cryptid set to 0")
        }

        guard msync(mapped, fileSize, MS_SYNC) == 0 else {
            throw UnfairError.io("sync failed: \(String(cString: strerror(errno)))")
        }
        logger.verbose("done - binary decrypted in-place")
        return .decrypted
    }

    private func unprotectRegion(fd: Int32, fileOffset: Int, sliceBase: UnsafeMutableRawPointer, sliceSize: Int, info: EncryptionInfo) throws {
        if info.cryptsize == 0 {
            logger.verbose("encrypted region is empty")
            return
        }

        let encryptedOffset = fileOffset + Int(info.cryptoff)
        logger.verbose("decrypting: cryptid=\(info.cryptid)  cryptoff=0x\(String(info.cryptoff, radix: 16))  cryptsize=0x\(String(info.cryptsize, radix: 16))  fileoff=0x\(String(encryptedOffset, radix: 16))")

        let encryptedSize = Int(info.cryptsize)
        guard let encrypted = mmap(nil, encryptedSize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, off_t(encryptedOffset)),
              encrypted != MAP_FAILED else {
            throw UnfairError.io("mmap encrypted region failed: \(String(cString: strerror(errno)))")
        }
        defer { munmap(encrypted, encryptedSize) }

        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "mremap_encrypted") else {
            throw UnfairError.mremapUnavailable
        }
        let mremap = unsafeBitCast(symbol, to: MremapEncrypted.self)

        logger.verbose("calling mremap_encrypted (cpu=arm64, sub=all)")
        let result = mremap(encrypted, encryptedSize, info.cryptid, cpuTypeArm64, cpuSubtypeArm64All)
        guard result == 0 else {
            throw UnfairError.decryptFailed("mremap_encrypted failed: \(String(cString: strerror(errno)))")
        }

        logger.verbose("copying 0x\(String(info.cryptsize, radix: 16)) decrypted bytes back to base")
        memcpy(sliceBase.advanced(by: Int(info.cryptoff)), encrypted, encryptedSize)
        logger.verbose("decrypt done")
    }
}
