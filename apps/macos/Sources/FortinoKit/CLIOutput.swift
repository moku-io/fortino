// What the app reads back from the `fortino` command it bundles.

import Foundation

private struct ErrorEnvelope: Decodable {
    var error: ProtoError?
}

/// Why a `fortino --json …` run failed. With `--json` the command prints its error object on
/// standard output (`{"v":1,"error":{…}}`) and only notes on standard error, so the JSON comes
/// first; standard error is the fallback (the command didn't start, or printed no JSON).
public func cliFailure(stdout: Data, stderr: String) -> String? {
    if let e = (try? JSONDecoder().decode(ErrorEnvelope.self, from: stdout))?.error {
        return e.message
    }
    let s = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
    return s.isEmpty ? nil : s
}
