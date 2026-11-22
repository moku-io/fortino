// Checks an EMS server's certificate with the system's trust policy before the administrator
// approves the server. An untrusted certificate (typically an EMS reached by an address its
// certificate doesn't name) is shown once with its SHA-256; if accepted, the approval pins
// exactly that certificate. Only the TLS handshake is sent.

import AppKit
import CryptoKit
import Foundation
import FortinoKit
import Security

struct EmsCertificate {
    /// Whether macOS trusts the certificate for this host name or address.
    let trusted: Bool
    /// Why it isn't trusted, from the system's evaluation.
    let reason: String?
    /// The certificate's subject summary (usually its common name).
    let subject: String
    /// SHA-256 of the leaf certificate, lower-case hex.
    let sha256: String

    var displayFingerprint: String {
        stride(from: 0, to: sha256.count, by: 2).map { i -> String in
            let a = sha256.index(sha256.startIndex, offsetBy: i)
            return String(sha256[a..<sha256.index(a, offsetBy: 2)]).uppercased()
        }.joined(separator: ":")
    }

    /// Opens a TLS connection to `server`, evaluates its certificate and closes the connection.
    static func fetch(_ server: EmsServer) async throws -> EmsCertificate {
        guard let url = URL(string: "https://\(server.host):\(server.port)/") else {
            throw ProtoError(code: "invalid_request", message: "Invalid EMS address.")
        }
        let grab = Grab()
        let session = URLSession(configuration: .ephemeral, delegate: grab, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        _ = try? await session.data(for: request)
        guard let cert = grab.result else {
            throw ProtoError(code: "transport_failure",
                             message: "Could not reach the EMS server \(server.display) to check its certificate.")
        }
        return cert
    }

    /// Captures the server trust at the TLS challenge and cancels before any request is sent.
    private final class Grab: NSObject, URLSessionDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var captured: EmsCertificate?
        var result: EmsCertificate? { lock.withLock { captured } }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            var error: CFError?
            let trusted = SecTrustEvaluateWithError(trust, &error)
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
                let der = SecCertificateCopyData(leaf) as Data
                let cert = EmsCertificate(
                    trusted: trusted,
                    reason: error.map { CFErrorCopyDescription($0) as String },
                    subject: (SecCertificateCopySubjectSummary(leaf) as String?) ?? "unknown",
                    sha256: SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined())
                lock.withLock { captured = cert }
            }
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

extension EmsCertificate {
    /// Asks whether to trust this untrusted certificate permanently for `server`.
    @MainActor
    func confirmTrust(for server: EmsServer) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "The certificate of EMS server \(server.display) is not trusted"
        alert.informativeText = """
        \(reason ?? "macOS could not verify it.")

        Issued to: \(subject)
        SHA-256: \(displayFingerprint)

        Trust it only if you expected this server to use this certificate, for example because \
        it is reached by an address its certificate doesn't name. Fortino will trust exactly \
        this certificate for this server from now on, and will warn you again if it changes.
        """
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Trust Permanently")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertSecondButtonReturn
    }
}
