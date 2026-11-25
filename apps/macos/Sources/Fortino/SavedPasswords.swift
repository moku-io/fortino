// Saved passwords. The `fortino` command bundled with the app owns the login keychain item: the
// app asks it to answer a password prompt, to save a password it accepted, and to forget one, so
// one program reads and writes the item and macOS doesn't ask the user about a second one. The
// password reaches the service exactly as if it had been typed.

import Foundation
import FortinoKit

/// What the keychain holds for a profile, as `fortino password status` reports it.
struct SavedPasswordState: Decodable, Equatable {
    var saved: Bool
    var username: String?
    var rejected: Bool
    var location: String
    var error: String?
}

/// Why the app's password prompt wasn't answered from the keychain.
enum SavedPasswordNote: Equatable {
    /// Nothing saved yet for this account: the typed password is saved once connected.
    case willSave
    /// The gateway rejected the saved password last time.
    case rejected
    /// The keychain couldn't be read (locked, or access was denied).
    case unavailable
}

/// A typed password waiting for its attempt to connect before it is saved.
struct PendingPasswordSave {
    let attempt: String
    let profileId: String
    let username: String
    let password: String
}

private struct CLIEnvelope<T: Decodable>: Decodable {
    var result: T?
    var error: ProtoError?
}

private struct AnswerResult: Decodable {
    var answered: Bool
    var reason: String
}

extension AppModel {
    /// The account the service uses for `status`'s attempt: the profile's username, else the one
    /// typed for this attempt.
    func attemptUsername(_ profile: Profile, attempt: String?) -> String? {
        if let u = profile.spec.usernameHint { return u }
        guard let t = typedUsername, t.attempt == attempt else { return nil }
        return t.value
    }

    /// The profile of `status`'s attempt, when it saves its password.
    func savingProfile(for status: Status) -> Profile? {
        profiles.first { $0.id == status.profileId && $0.spec.savePassword == true }
    }

    /// Answers `challenge` with the saved password. Returns nil when it was answered (the
    /// prompt goes away by itself), else why not.
    func answerFromKeychain(profile: Profile, status: Status, challenge: Challenge) async -> SavedPasswordNote? {
        guard let attempt = status.attemptId else { return .unavailable }
        var args = ["password", "answer", profile.id, "--attempt", attempt, "--challenge", challenge.id]
        if let u = attemptUsername(profile, attempt: attempt) { args += ["--username", u] }
        let (_, out, _) = await runCLI(args)
        guard let r = (try? JSONDecoder().decode(CLIEnvelope<AnswerResult>.self, from: out))?.result else {
            return .unavailable
        }
        if r.answered {
            keychainAnsweredAttempt = attempt
            await refreshSavedPassword(profile.id)
            return nil
        }
        switch r.reason {
        case "rejected": return .rejected
        case "unavailable": return .unavailable
        default: return .willSave
        }
    }

    /// Remembers an answer typed in the sign-in panel for the current attempt.
    func noteTyped(_ kind: ChallengeKind, value: String, savePassword: Bool) {
        guard let st = status, let attempt = st.attemptId else { return }
        switch kind {
        case .username:
            typedUsername = (attempt, value)
        case .password:
            guard savePassword, let p = profiles.first(where: { $0.id == st.profileId }),
                  let u = attemptUsername(p, attempt: attempt) else {
                pendingPasswordSave = nil
                return
            }
            pendingPasswordSave = PendingPasswordSave(attempt: attempt, profileId: p.id, username: u,
                                                      password: value)
        case .otp:
            break
        }
    }

    /// Saves a typed password once its attempt connects; drops it when the attempt ends.
    func settlePendingPassword(_ s: Status) {
        guard let pending = pendingPasswordSave else { return }
        if s.attemptId != pending.attempt || s.state == .idle || s.state == .recoveryRequired {
            pendingPasswordSave = nil
            return
        }
        guard s.state == .connected else { return }
        pendingPasswordSave = nil
        Task {
            let (code, _, err) = await runCLI(
                ["password", "save", pending.profileId, "--username", pending.username, "--stdin"],
                input: Data((pending.password + "\n").utf8))
            if code != 0 {
                actionError = "The password could not be saved: "
                    + err.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            await refreshSavedPassword(pending.profileId)
        }
    }

    /// Reads what the keychain holds for a profile (never the password itself).
    func refreshSavedPassword(_ profileId: String) async {
        let (_, out, _) = await runCLI(["password", "status", profileId])
        savedPasswords[profileId] =
            (try? JSONDecoder().decode(CLIEnvelope<SavedPasswordState>.self, from: out))?.result
    }

    /// Removes a profile's saved password; the profile's choice stays as it is.
    func forgetSavedPassword(_ profileId: String) async {
        let (code, _, err) = await runCLI(["password", "forget", profileId])
        if code != 0 {
            actionError = "The saved password could not be removed: "
                + err.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        await refreshSavedPassword(profileId)
    }
}
