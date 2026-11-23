// Trusting one VPN gateway certificate the system doesn't (typically a gateway reached by an
// address its certificate doesn't name). The pin is a root-owned marker the VPN service reads;
// writing it needs the administrator's password, like an EMS approval.
import CryptoKit
import FortinoKit
import Foundation

struct GatewayPin {
    /// Normalized `host:port`, as the service computes it.
    let address: String
    /// Must match `GATEWAY_PIN_DIR` in `crates/fortinod/src/procworker.rs`.
    private let directory = "/private/var/db/fortino-gateway-pins"

    init(endpoint: Endpoint) { address = "\(endpoint.host.lowercased()):\(endpoint.port)" }

    private var marker: String {
        let digest = SHA256.hash(data: Data(address.utf8))
        return directory + "/" + digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Writes `sha256:<pin>` as root. `pin` is 64 lower-case hex digits.
    func write(pin: String) throws {
        guard pin.count == 64, pin.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw ProtoError(code: "invalid_request", message: "Invalid certificate fingerprint.")
        }
        // The address is a validated profile host (DNS name or IPv4) and port; nothing to quote.
        guard address.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || ".-:".contains($0)) }) else {
            throw ProtoError(code: "invalid_request", message: "Invalid gateway address.")
        }
        let script = """
        do shell script "umask 077 && /usr/bin/install -d -m 0700 -o root -g wheel \(directory) && /usr/bin/printf sha256:%s \(pin) > \(marker)" with prompt "Allow Fortino to trust this certificate for the VPN gateway \(address)?" with administrator privileges
        """
        var error: NSDictionary?
        guard let approval = NSAppleScript(source: script) else {
            throw ProtoError(code: "internal", message: "Could not prepare the certificate approval.")
        }
        approval.executeAndReturnError(&error)
        if error != nil {
            throw ProtoError(code: "permission_denied", message: "Trusting the gateway certificate was cancelled or failed.")
        }
    }
}
