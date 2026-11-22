// The GUI and terminal approve exactly the same normalized EMS address.
import CryptoKit
import FortinoKit
import Foundation

struct EnrollmentApproval {
    /// Normalized `host:port`, as `EmsServer.display` and `EnrollmentPackage.address` give it.
    let address: String
    private let directory = "/private/var/db/fortino-ems-approvals"

    init(package: EnrollmentPackage) { address = package.address }
    init(server: EmsServer) { address = server.display }

    private var marker: String {
        let digest = SHA256.hash(data: Data(address.utf8))
        return directory + "/" + digest.map { String(format: "%02x", $0) }.joined()
    }

    func requestInApp() throws {
        // EnrollmentPackage has no public initializer. Its address comes from parseEms.
        let script = """
        do shell script "umask 077 && /usr/bin/install -d -m 0700 -o root -g wheel \(directory) && /usr/bin/touch \(marker)" with prompt "Allow Fortino to register this Mac with the EMS server \(address)?" with administrator privileges
        """
        var error: NSDictionary?
        guard let approval = NSAppleScript(source: script) else {
            throw ProtoError(code: "internal", message: "Could not prepare local EMS approval.")
        }
        approval.executeAndReturnError(&error)
        if error != nil {
            throw ProtoError(code: "permission_denied", message: "EMS server approval was cancelled or failed.")
        }
    }

    func requestInTerminal() throws {
        for args in [["/usr/bin/install", "-d", "-m", "0700", "-o", "root", "-g", "wheel", directory],
                     ["/usr/bin/touch", marker]] {
            let sudo = Process()
            sudo.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            sudo.arguments = args
            try sudo.run()
            sudo.waitUntilExit()
            guard sudo.terminationStatus == 0 else {
                throw ProtoError(code: "permission_denied", message: "Local EMS approval failed.")
            }
        }
    }
}
