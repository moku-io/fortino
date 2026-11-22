import AppKit
import FortinoKit
import SwiftUI
import UniformTypeIdentifiers

struct EnrollmentWindow: View {
    @ObservedObject var model: AppModel
    @State private var package: EnrollmentPackage?
    @State private var needsApproval = false
    @State private var registered = false
    @State private var busy = false
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ServiceUpdateBanner(model: model).padding(.horizontal, -20).padding(.top, -20)
            Button("Choose FortiClient DMG…", action: choose)
            if let package {
                Text("EMS server").font(.headline)
                Text(verbatim: package.address).textSelection(.enabled)
                Button(needsApproval ? "Approve Server and Enroll…" : "Enroll This Mac") {
                    enroll(package)
                }
                if registered, let profile = model.selectedProfile,
                   case let .success(server?) = parseEms(package.address),
                   profile.spec.endpoint.ems != server {
                    Button("Use this EMS for “" + profile.spec.name + "”") {
                        busy = true
                        Task {
                            defer { busy = false }
                            var spec = profile.spec
                            spec.endpoint.ems = server
                            if let error = await model.save(spec, existing: profile) { message = error.message }
                        }
                    }
                }
            }
            if busy { ProgressView().controlSize(.small) }
            if let message { Text(message) }
        }
        .disabled(busy)
        .padding(20)
        .frame(minWidth: 430, minHeight: 180, alignment: .leading)
    }

    private func enroll(_ package: EnrollmentPackage) {
        busy = true
        Task {
            defer { busy = false }
            do {
                if needsApproval {
                    try EnrollmentApproval(package: package).requestInApp()
                    needsApproval = false
                }
                let result = try await model.enroll(package)
                registered = ["registered", "existing-registration", "managed-by-forticlient"].contains(result.status)
                switch result.status {
                case "approval-required":
                    needsApproval = true
                    message = "A local administrator must approve this EMS server for this Mac."
                case "managed-by-forticlient":
                    message = "FortiClient already manages this Mac on this EMS."
                case "existing-registration":
                    message = "Fortino already has a registration for this EMS using different deployment settings."
                case "registered":
                    message = result.rules ? "Registered. Host-verification rules are available." : "Registered. No host-verification rules are stored yet."
                default:
                    message = "The service returned an unknown enrollment status."
                }
            } catch {
                message = error.localizedDescription
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
        message = nil
        busy = true
        Task {
            defer { busy = false }
            do {
                package = try await Task.detached { try EnrollmentPackage.read(image) }.value
            } catch {
                message = error.localizedDescription
            }
        }
    }
}
