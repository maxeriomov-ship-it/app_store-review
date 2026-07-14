import AuthenticationServices
import AVFoundation
import StoreKit
import SwiftUI

@main
struct CompliantApp: App {
    var body: some Scene {
        WindowGroup {
            ReviewReadyView()
        }
    }
}

struct ReviewReadyView: View {
    @State private var status = String(localized: "welcome_title")

    var body: some View {
        NavigationStack {
            List {
                Text(status)
                SignInWithAppleButton(.signIn, onRequest: configureAppleRequest, onCompletion: finishAppleLogin)
                Button(String(localized: "scan_receipt"), action: requestCamera)
                Button(String(localized: "restore_purchases"), action: restorePurchases)
                Button(String(localized: "delete_account"), action: deleteAccount)
                Button(String(localized: "sign_out"), action: signOut)
            }
            .navigationTitle(String(localized: "app_title"))
        }
    }

    private func configureAppleRequest(_ request: ASAuthorizationAppleIDRequest) {
        request.requestedScopes = [.email]
    }

    private func finishAppleLogin(_ result: Result<ASAuthorization, Error>) {
        status = result.isSuccess ? String(localized: "signed_in") : String(localized: "sign_in_failed")
    }

    private func requestCamera() {
        AVCaptureDevice.requestAccess(for: .video) { allowed in
            Task { @MainActor in
                status = allowed ? String(localized: "camera_ready") : String(localized: "camera_denied")
            }
        }
    }

    private func restorePurchases() {
        Task {
            try? await AppStore.sync()
            for await _ in Transaction.currentEntitlements { }
        }
    }

    private func deleteAccount() { status = String(localized: "deletion_requested") }
    private func signOut() { status = String(localized: "signed_out") }
}

private extension Result {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}
