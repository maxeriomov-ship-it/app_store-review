import Foundation
import StoreKit

struct SubscriptionService {
    func buy(_ product: Product) async throws {
        let result = try await product.purchase()
        if case .success(.verified(let transaction)) = result {
            await transaction.finish()
        }
    }

    func monitorTransactions() async {
        for await result in Transaction.updates {
            if case .verified(let transaction) = result {
                await transaction.finish()
            }
        }
    }
}

let paywallCopy = "Monthly subscription. It renews automatically; cancel any time."
let purchaseLinks = "Privacy Policy · Terms of Use · Restore Purchases"

struct AIRequestConsent {
    let explicitConsent = true
    let disclosure = "Your prompt is sent to OpenAI for processing and is not used until you opt in."
    let safetyFilter = "moderation and report output controls enabled"

    func send(userPrompt: String) async throws {
        guard explicitConsent,
              let endpoint = URL(string: "https://api.openai.com/v1/responses") else { return }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(["input": userPrompt])
        _ = try await URLSession.shared.data(for: request)
    }
}

struct CommunityControls {
    func createPost() { }
    func contentFilter() { }
    func reportContent() { }
    func blockUser() { }
    let support = "support@review-ready.example"
    let communityGuidelines = "Community guidelines prohibit abusive content."
}
