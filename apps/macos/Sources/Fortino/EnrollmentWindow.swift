import AppKit
import FortinoKit
import SwiftUI
import UniformTypeIdentifiers

/// Enrollment with an organization's FortiClient deployment package (DMG). The package carries
/// the EMS address and an installer ID; it is checked against the profile it is for, so a
/// package from another organization can't register this Mac with the wrong EMS.
struct EnrollmentWindow: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var package: EnrollmentPackage?
    /// The package's EMS compared with the profile's: nil while checking.
    @State private var match: Match?
    @State private var needsApproval = false
    @State private var registered = false
    @State private var busy = false
    @State private var message: String?
    @State private var messageIsError = false

    private enum Match: Equatable {
        /// The profile names no EMS (or there is no profile).
        case noProfileEms
        case same
        case different(profileEms: String)
    }

    private var profile: Profile? { model.emsSetupProfile }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ServiceUpdateBanner(model: model).padding(.horizontal, -20).padding(.top, -20)
            Text("Enroll with a Deployment Package").font(.title3.weight(.semibold))
            Text(intro).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button(package == nil ? "Choose FortiClient DMG…" : "Choose Another DMG…", action: choose)
            if let package {
                LabeledContent("Package EMS") { Text(verbatim: package.address).textSelection(.enabled) }
                if let profile {
                    LabeledContent("Profile") {
                        Text(profile.spec.name + (profile.spec.endpoint.ems.map { " (\($0.display))" } ?? ""))
                    }
                }
                switch match {
                case nil:
                    ProgressView("Comparing with the profile's EMS…").controlSize(.small)
                case .different(let profileEms)?:
                    Label {
                        Text("This package is for \(package.address), but “\(profile?.spec.name ?? "")” uses \(profileEms). Enrolling would register this Mac with another organization's EMS. Choose the package your IT gave you for this profile, or use EMS Setup: a package isn't required to register.")
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                    }
                    Button("Open EMS Setup…") { openWindow(id: "ems-setup") }
                case .same?, .noProfileEms?:
                    Button(needsApproval ? "Allow Server and Enroll…" : "Enroll This Mac") {
                        enroll(package)
                    }
                    .buttonStyle(.borderedProminent)
                    Text("Enrolling registers this Mac with that EMS; your IT administrator can see the device.")
                        .font(.callout).foregroundStyle(.secondary)
                    if registered, match == .noProfileEms, let profile,
                       case let .success(server?) = parseEms(package.address) {
                        // Only for a profile without an EMS: never replace one it already has.
                        Button("Use this EMS for “" + profile.spec.name + "”") {
                            busy = true
                            Task {
                                defer { busy = false }
                                var spec = profile.spec
                                spec.endpoint.ems = server
                                if let error = await model.save(spec, existing: profile) {
                                    show(error.message, error: true)
                                }
                            }
                        }
                    }
                }
            }
            if busy { ProgressView().controlSize(.small) }
            if let message {
                Text(message)
                    .foregroundStyle(messageIsError ? .red : .primary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
        .disabled(busy)
        .padding(20)
        .frame(minWidth: 480, minHeight: 220, alignment: .topLeading)
    }

    private var intro: String {
        "Some organizations give out a FortiClient DMG made by their EMS. Fortino reads only its EMS address and installer ID; nothing is installed. Most EMS servers don't need it: EMS Setup registers this Mac without one."
    }

    private func show(_ text: String, error: Bool = false) {
        message = text
        messageIsError = error
    }

    private func enroll(_ package: EnrollmentPackage) {
        busy = true
        Task {
            defer { busy = false }
            do {
                if needsApproval {
                    guard case let .success(server?) = parseEms(package.address),
                          try await model.approveWithCertificateCheck(server) else { return }
                    needsApproval = false
                }
                let result = try await model.enroll(package)
                registered = ["registered", "existing-registration", "managed-by-forticlient"].contains(result.status)
                switch result.status {
                case "approval-required":
                    needsApproval = true
                    show("This EMS server needs to be allowed on this Mac first (this Mac's administrator password).")
                case "managed-by-forticlient":
                    show("FortiClient already manages this Mac on this EMS.")
                case "held-by-forticlient":
                    show("Not enrolled: FortiClient on this Mac is registered with this EMS, and the EMS keeps one registration per Mac. Quit FortiClient (including its EMS agent) or remove its EMS connection, then try again.", error: true)
                case "existing-registration":
                    show("Fortino already has a registration for this EMS, made with other deployment settings. It keeps using it.")
                case "registered":
                    show(result.rules ? "Registered. The EMS sent its compliance rules." : "Registered. The EMS hasn't sent compliance rules yet; they usually arrive with the first check-in.")
                default:
                    show("The service answered “\(result.status)”.", error: true)
                }
            } catch {
                show((error as? ProtoError)?.message ?? error.localizedDescription, error: true)
            }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "dmg") ?? .diskImage]
        guard panel.runModal() == .OK, let image = panel.url else { return }
        needsApproval = false
        registered = false
        package = nil
        match = nil
        message = nil
        busy = true
        let profileEms = profile?.spec.endpoint.ems
        Task {
            defer { busy = false }
            do {
                let p = try await Task.detached { try EnrollmentPackage.read(image) }.value
                package = p
                match = await Task.detached { () -> Match in
                    guard let profileEms, case let .success(pkg?) = parseEms(p.address) else {
                        return .noProfileEms
                    }
                    return pkg.isSameServer(as: profileEms) ? .same : .different(profileEms: profileEms.display)
                }.value
            } catch {
                show(error.localizedDescription, error: true)
            }
        }
    }
}
