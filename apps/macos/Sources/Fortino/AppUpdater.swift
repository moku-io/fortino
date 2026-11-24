// App updates through Sparkle. The feed (SUFeedURL in Info.plist) is an appcast attached to the
// latest GitHub release; each DMG it names carries an EdDSA signature checked against
// SUPublicEDKey before anything is installed. Sparkle shows the standard dialog with the release
// notes and Install Update / Remind Me Later / Skip This Version, replaces the app and relaunches
// it. The VPN service then follows through the build-ID check in AppModel (ServiceUpdate); a
// connected VPN stays up while the app relaunches.

import AppKit
import Combine
import Sparkle

@MainActor
final class AppUpdater: NSObject, ObservableObject {
    /// False while a check or an update session is under way, and in development runs.
    @Published private(set) var canCheckForUpdates = false
    /// Version of an update found by a scheduled check that is waiting for the user, shown as a
    /// row in the menu-bar panel instead of a window popping up over whatever the user is doing.
    @Published private(set) var availableUpdate: String?
    @Published private(set) var lastUpdateCheckDate: Date?

    /// Nil in development runs (`swift run`, no bundle or no feed), where there is nothing to
    /// update.
    private var controller: SPUStandardUpdaterController?
    private let sparkleDelegate = SparkleDelegate()
    private var observers: [AnyCancellable] = []

    /// Whether this copy can update itself: a bundled app with a feed.
    var isAvailable: Bool { controller != nil }

    var automaticallyChecksForUpdates: Bool {
        get { controller?.updater.automaticallyChecksForUpdates ?? false }
        set {
            objectWillChange.send()
            controller?.updater.automaticallyChecksForUpdates = newValue
        }
    }

    func start() {
        guard controller == nil,
              Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil
        else { return }
        sparkleDelegate.owner = self
        let c = SPUStandardUpdaterController(
            startingUpdater: false, updaterDelegate: sparkleDelegate, userDriverDelegate: sparkleDelegate)
        controller = c
        c.updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.canCheckForUpdates = $0 }
            .store(in: &observers)
        c.updater.publisher(for: \.lastUpdateCheckDate)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.lastUpdateCheckDate = $0 }
            .store(in: &observers)
        c.startUpdater()
    }

    /// Checks now and shows the result, or brings back an update found earlier.
    func checkForUpdates() {
        NSApp.activate(ignoringOtherApps: true)
        controller?.checkForUpdates(nil)
    }

    fileprivate func willShow(update: SUAppcastItem, inFront: Bool) {
        if inFront {
            NSApp.activate(ignoringOtherApps: true)
            availableUpdate = nil
        } else {
            availableUpdate = update.displayVersionString
        }
    }

    fileprivate func sessionEnded() {
        availableUpdate = nil
    }
}

/// Sparkle's delegates, kept apart from the main-actor model: Sparkle calls them on the main
/// thread through Objective-C protocols that carry no actor annotation.
private final class SparkleDelegate: NSObject, SPUUpdaterDelegate, SPUStandardUserDriverDelegate {
    weak var owner: AppUpdater?

    /// `FORTINO_UPDATE_FEED` points a test install at another appcast. Updates are still
    /// verified against the key in Info.plist, so the override cannot install unsigned code.
    func feedURLString(for updater: SPUUpdater) -> String? {
        ProcessInfo.processInfo.environment["FORTINO_UPDATE_FEED"]
    }

    // A menu-bar app has no window in front when a scheduled check finds an update. Sparkle shows
    // its window only when the app is already in focus; otherwise the menu-bar panel offers it.
    var supportsGentleScheduledUpdateReminders: Bool { true }

    func standardUserDriverShouldHandleShowingScheduledUpdate(
        _ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool
    ) -> Bool {
        immediateFocus
    }

    func standardUserDriverWillHandleShowingUpdate(
        _ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState
    ) {
        MainActor.assumeIsolated {
            owner?.willShow(update: update, inFront: handleShowingUpdate || state.userInitiated)
        }
    }

    func standardUserDriverDidReceiveUserAttention(forUpdate update: SUAppcastItem) {
        MainActor.assumeIsolated { owner?.sessionEnded() }
    }

    func standardUserDriverWillFinishUpdateSession() {
        MainActor.assumeIsolated { owner?.sessionEnded() }
    }
}
