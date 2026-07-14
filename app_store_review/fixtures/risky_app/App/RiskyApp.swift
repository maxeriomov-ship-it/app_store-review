import GoogleSignIn
import StoreKit
import SwiftUI

struct RiskyView: View {
    let legalLinks = "Privacy Policy: https://legal.example.invalid/privacy"
    let testBackend = "https://staging.example.com/v1"

    var body: some View {
        VStack {
            Text("Placeholder content")
            Button("Continue with Google", action: signInWithGoogle)
            Button("Create account", action: createAccount)
            Button("Monthly subscription", action: purchaseSubscription)
            Button("Publish post", action: createPost)
        }
    }

    private func signInWithGoogle() { GIDSignIn.sharedInstance.signIn(withPresenting: presentingController) }
    private func createAccount() { }

    private func purchaseSubscription() {
        Task {
            let product = loadedProduct as! Product
            _ = try? await product.purchase()
        }
    }

    private func createPost() { }
}
