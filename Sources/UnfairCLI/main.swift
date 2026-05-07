import ArgumentParser
import Foundation
import UnfairKit

struct UnfairCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unfair",
        abstract: "Decrypt FairPlay-protected Mach-O files inside IPA packages.",
        subcommands: [Package.self, Binary.self]
    )
}

UnfairCommand.main()

struct Package: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Process an IPA package.")

    @Option(name: [.short, .customLong("input")], help: "Input .ipa path.")
    var input: String

    @Option(name: [.short, .customLong("output")], help: "Output .ipa path or destination directory.")
    var output: String

    @Option(name: .customLong("working-directory"), help: "Scratch directory under /var/folders/bg/<token>/X.")
    var workingDirectory: String?

    @Flag(name: [.short, .long], help: "Show detailed Mach-O and mremap logs.")
    var verbose = false

    func run() throws {
        try PackageProcessor(logger: UnfairLogger(verbose: verbose)).process(
            input: fileURL(input),
            output: fileURL(output),
            workingDirectory: workingDirectory.map(fileURL)
        )
    }
}

struct Binary: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Decrypt one Mach-O binary in place.")

    @Option(name: .shortAndLong, help: "Mach-O binary path.")
    var decrypt: String

    @Option(name: .customLong("root-sinf"), help: "Root .sinf file to copy into the target SC_Info directory.")
    var rootSinf: String

    @Flag(name: [.short, .long], help: "Show detailed Mach-O and mremap logs.")
    var verbose = false

    func run() throws {
        try BinaryDecryptor(logger: UnfairLogger(verbose: verbose)).decryptBinary(
            at: fileURL(decrypt),
            rootSinf: fileURL(rootSinf)
        )
    }
}

private func fileURL(_ path: String) -> URL {
    URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
}
