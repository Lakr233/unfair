import Darwin
import Foundation
import MachO

struct MachORecord {
    var url: URL
    var displayPath: String
    var name: String
    var hasEncryptionInfo: Bool
    var cryptid: UInt32

    var isEncrypted: Bool {
        hasEncryptionInfo && cryptid == 1
    }
}

struct MachOSlice {
    var offset: Int
    var size: Int
}

struct EncryptionInfo {
    var commandOffset: Int
    var cryptoff: UInt32
    var cryptsize: UInt32
    var cryptid: UInt32
}

struct MachOInspection {
    var hasEncryptionInfo: Bool
    var cryptid: UInt32
}

enum MachOInspector {
    private static let fatCigam = UInt32(FAT_CIGAM)
    private static let mhMagic64 = UInt32(MH_MAGIC_64)
    private static let lcEncryptionInfo64 = UInt32(LC_ENCRYPTION_INFO_64)
    private static let cpuTypeArm64 = UInt32(bitPattern: CPU_TYPE_ARM64)
    private static let cpuSubtypeMask = UInt32(CPU_SUBTYPE_MASK)
    private static let cpuSubtypeArm64All = UInt32(CPU_SUBTYPE_ARM64_ALL)

    static func scanBinaries(appURL: URL, label: String) throws -> [MachORecord] {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey]
        guard let enumerator = FileManager.default.enumerator(
            at: appURL,
            includingPropertiesForKeys: keys,
            options: []
        ) else {
            throw UnfairError.io("opendir failed: \(appURL.path)")
        }

        var records: [MachORecord] = []
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: Set(keys))
            guard values.isRegularFile == true else {
                continue
            }

            guard let inspection = try inspect(url: url) else {
                continue
            }

            let display = displayPath(for: url, appURL: appURL, label: label)
            records.append(MachORecord(
                url: url,
                displayPath: display,
                name: url.lastPathComponent,
                hasEncryptionInfo: inspection.hasEncryptionInfo,
                cryptid: inspection.cryptid
            ))
        }
        return records
    }

    static func inspect(url: URL) throws -> MachOInspection? {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress, rawBuffer.count >= MemoryLayout<UInt32>.size else {
                return nil
            }
            let magic = base.load(as: UInt32.self)
            guard magic == fatCigam || magic == mhMagic64 else {
                return nil
            }
            guard let slice = try? selectArm64Slice(base: base, size: rawBuffer.count, logger: nil) else {
                return nil
            }
            guard let enc = try? findEncryptionInfo(base: base.advanced(by: slice.offset), size: slice.size) else {
                return nil
            }
            return MachOInspection(hasEncryptionInfo: true, cryptid: enc.cryptid)
        }
    }

    static func selectArm64Slice(base: UnsafeRawPointer, size: Int, logger: UnfairLogger?) throws -> MachOSlice {
        guard hasRange(size: size, offset: 0, length: MemoryLayout<UInt32>.size) else {
            throw UnfairError.invalidMachO("invalid Mach-O")
        }

        let magic = base.load(as: UInt32.self)
        if magic != fatCigam {
            return MachOSlice(offset: 0, size: size)
        }

        guard hasRange(size: size, offset: 0, length: MemoryLayout<fat_header>.size) else {
            throw UnfairError.invalidMachO("invalid FAT header")
        }

        let header = base.load(as: fat_header.self)
        let archCount = Int(UInt32(bigEndian: header.nfat_arch))
        let tableSize = archCount * MemoryLayout<fat_arch>.size
        guard archCount > 0,
              tableSize / MemoryLayout<fat_arch>.size == archCount,
              hasRange(size: size, offset: MemoryLayout<fat_header>.size, length: tableSize) else {
            throw UnfairError.invalidMachO("invalid FAT arch table")
        }

        logger?.verbose("detected fat binary with \(archCount) arches")
        let arches = base.advanced(by: MemoryLayout<fat_header>.size)
        for index in 0..<archCount {
            let arch = arches.advanced(by: index * MemoryLayout<fat_arch>.size).load(as: fat_arch.self)
            let cputype = UInt32(bigEndian: UInt32(bitPattern: arch.cputype))
            let subtype = UInt32(bigEndian: UInt32(bitPattern: arch.cpusubtype))
            let offset = Int(UInt32(bigEndian: arch.offset))
            let archSize = Int(UInt32(bigEndian: arch.size))
            logger?.verbose("  arch[\(index)]: cputype=\(cputype) cpusubtype=\(subtype) offset=\(offset) size=\(archSize)")

            guard cputype == cpuTypeArm64, isSupportedArm64Subtype(subtype) else {
                continue
            }
            guard archSize > 0, hasRange(size: size, offset: offset, length: archSize) else {
                throw UnfairError.invalidMachO("invalid arm64 slice")
            }
            logger?.verbose("  selected arm64 slice at offset 0x\(String(offset, radix: 16))")
            return MachOSlice(offset: offset, size: archSize)
        }

        throw UnfairError.noArm64Slice("fat binary")
    }

    static func findEncryptionInfo(base: UnsafeRawPointer, size: Int) throws -> EncryptionInfo? {
        guard hasRange(size: size, offset: 0, length: MemoryLayout<mach_header_64>.size) else {
            throw UnfairError.invalidMachO("invalid Mach-O header")
        }

        let header = base.load(as: mach_header_64.self)
        guard UInt32(header.magic) == mhMagic64,
              UInt32(bitPattern: header.cputype) == cpuTypeArm64,
              isSupportedArm64Subtype(UInt32(bitPattern: header.cpusubtype)) else {
            throw UnfairError.invalidMachO("invalid Mach-O header")
        }

        guard hasRange(size: size, offset: MemoryLayout<mach_header_64>.size, length: Int(header.sizeofcmds)) else {
            throw UnfairError.invalidMachO("invalid load command range")
        }

        var commandOffset = MemoryLayout<mach_header_64>.size
        for _ in 0..<header.ncmds {
            guard hasRange(size: size, offset: commandOffset, length: MemoryLayout<load_command>.size) else {
                throw UnfairError.invalidMachO("invalid load command")
            }

            let command = base.advanced(by: commandOffset).load(as: load_command.self)
            guard command.cmdsize >= UInt32(MemoryLayout<load_command>.size),
                  hasRange(size: size, offset: commandOffset, length: Int(command.cmdsize)) else {
                throw UnfairError.invalidMachO("invalid load command size")
            }

            if command.cmd == lcEncryptionInfo64 {
                guard command.cmdsize >= UInt32(MemoryLayout<encryption_info_command_64>.size) else {
                    throw UnfairError.invalidMachO("invalid encryption command")
                }
                let info = base.advanced(by: commandOffset).load(as: encryption_info_command_64.self)
                return EncryptionInfo(
                    commandOffset: commandOffset,
                    cryptoff: info.cryptoff,
                    cryptsize: info.cryptsize,
                    cryptid: info.cryptid
                )
            }

            commandOffset += Int(command.cmdsize)
        }

        return nil
    }

    static func hasRange(size: Int, offset: Int, length: Int) -> Bool {
        offset >= 0 && length >= 0 && offset <= size && length <= size - offset
    }

    private static func isSupportedArm64Subtype(_ subtype: UInt32) -> Bool {
        let baseSubtype = subtype & ~cpuSubtypeMask
        return baseSubtype == cpuSubtypeArm64All || baseSubtype == UInt32(CPU_SUBTYPE_ARM64E)
    }

    private static func displayPath(for url: URL, appURL: URL, label: String) -> String {
        let root = appURL.path
        let path = url.path
        guard path == root || path.hasPrefix(root + "/") else {
            return path
        }
        return label + String(path.dropFirst(root.count))
    }
}
