# Platform support matrix

Start with automatic detection, then confirm the actual iOS target and release path. A detected framework changes file locations and runtime commands; it does not change Apple requirements.

| Stack | Detection signals | Primary static evidence | Build/runtime confirmation | Important limits |
|---|---|---|---|---|
| SwiftUI | `.swift`, `import SwiftUI`, Xcode target | Swift source, plist, entitlements, assets, `.xcprivacy`, project settings | Release scheme build; physical iPhone/iPad where supported | View reachability and broken interactions need runtime inspection |
| UIKit | `.swift`/`.m`, `import UIKit`, storyboard/xib | Source, storyboard/xib, plist, entitlements, project settings | Release scheme build and device navigation | Storyboard identifiers and dynamic routes may not be statically resolvable |
| Xcode project/workspace | `.xcodeproj`, `.xcworkspace`, schemes | `project.pbxproj`, shared schemes, xcconfig, build settings | `xcodebuild` read-only inspection/build when authorized | User-specific or CI settings may differ from repository state |
| Swift Package Manager | `Package.swift`, `Package.resolved` | Manifests, resolved versions, package sources/resources | Resolve/build only when dependencies are already available or install access is authorized | Package alone may not declare the host app's plist/entitlements/privacy answers |
| CocoaPods | `Podfile`, `Podfile.lock`, workspace | Lockfile, podspecs/manifests, embedded privacy manifests | Workspace build | Package presence does not prove API use or data collection |
| React Native | `package.json`, React Native package, `ios/` | JS/TS, native iOS folder, lockfiles, plist, entitlements | Native Release build plus JS bundle and device flow | JS routing and remote configuration need runtime/back-end evidence |
| Flutter | `pubspec.yaml`, `ios/Runner` | Dart, Podfile.lock, iOS runner configuration, plugins, plist | `flutter build ios`/Xcode Release when tools and dependencies are available | Plugin registrant presence does not prove feature activation |
| Capacitor | Capacitor config/package plus `ios/` | Web code, native iOS project, plugins, plist | Synced native Release build and device flow | Generated native files may be stale; WebView minimum-functionality risk is contextual |
| Expo native iOS | Expo config/package plus generated/prebuilt `ios/` | App config, plugins, native project, lockfiles | Build the exact native artifact submitted through the chosen pipeline | Managed config alone cannot prove the generated binary's entitlements/manifests |
| Other iOS target | plist/pbxproj/entitlements/Apple platform build artifacts | Native target configuration and embedded dependencies | Exact submitted Release build | Require manual mapping if detector cannot identify the build system |

## Common applicability routing

- No account or login: account deletion and social-login checks are `Not applicable`, after confirming no hidden account creation.
- Account creation: load account deletion, data deletion, access recovery, logout, and reviewer-account checks.
- Third-party/social login: inspect Guideline 4.8 scope and exceptions; do not demand a specific provider from a keyword alone.
- Digital purchases/subscriptions: load StoreKit, paywall, restoration, entitlement, and App Store Connect product checks.
- AI provider integration: load disclosure, explicit permission for personal-data sharing, retention/deletion, safety, and age-rating checks.
- UGC/chat/community: load filtering, reporting, blocking, moderation response, contact, terms, and age-rating checks.
- WebView/template/catalog: perform a manual standalone-value review and label the result subjective.

## Tool availability

Use Python standard library first. Use `plutil`, `xcodebuild`, `xcrun`, and `simctl` only when present and only for non-destructive inspection or explicitly authorized testing. Missing tools produce `Not verified`, not failure and not a compliance finding. Do not install dependencies merely to complete an audit.
