import Foundation

struct AIClient {
    let endpoint = URL(string: "https://api.openai.com/v1/responses")

    func send(userPrompt: String, email: String) async throws {
        guard let endpoint else { return }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode([
            "input": userPrompt,
            "email": email
        ])
        _ = try await URLSession.shared.data(for: request)
    }
}
