# Approov Service for Alamofire

![Swift](https://img.shields.io/badge/Swift-5.8%2B-F05138?logo=swift&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-11%2B-000000?logo=apple&logoColor=white)
![SwiftPM](https://img.shields.io/github/v/tag/approov/approov-service-alamofire?logo=swift&logoColor=white&label=SwiftPM&color=F05138)
![CocoaPods](https://img.shields.io/cocoapods/v/ApproovSession?logo=cocoapods&logoColor=white&label=CocoaPods)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)
![Build](https://github.com/approov/approov-service-alamofire/actions/workflows/build_and_test.yml/badge.svg)

A wrapper for the [Approov SDK](https://github.com/approov/approov-ios-sdk) to enable easy integration when using [`Alamofire`](https://github.com/Alamofire/Alamofire) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

This page provides the steps for integrating Approov into your app. A step-by-step tutorial is available in the [Quickstart](https://github.com/approov/quickstart-ios-swift-alamofire).

## ADDING APPROOV SERVICE DEPENDENCY
The Approov integration is available via the [Swift Package Manager](https://www.swift.org/package-manager/) and [CocoaPods](https://cocoapods.org/).

**Swift Package Manager** — add a dependency on the package in Xcode using the git repository URL `https://github.com/approov/approov-service-alamofire.git` and choose the version you wish to use.

**CocoaPods** — add the pod to your `Podfile`:

```ruby
pod 'ApproovSession'
```

In both cases the module is imported as `ApproovAFSession` (the primary session type is `ApproovSession`):

```swift
import ApproovAFSession
```

This package is an open-source wrapper layer that allows you to easily use Approov with Alamofire. It has a further dependency on the closed-source [`Approov` iOS SDK](https://github.com/approov/approov-ios-sdk).

## INITIALIZING APPROOV SERVICE
In order to use the `ApproovService` you must initialize it when your app is created, before constructing an `ApproovSession`. Initialization can fail (bad config, SDK error) and `initialize(config:)` is a throwing call, so wrap it in `do/catch` and make sure your app survives a failure rather than crashing:

```swift
import ApproovAFSession
import Foundation
import os

let log = Logger(subsystem: "com.yourcompany.yourapp", category: "approov")

// An app-generated id used to correlate this install/session across your own app logs and
// your backend. Use a UUID, or any session/user identifier you already have — it is NOT an
// Approov secret.
let correlationId = UUID().uuidString

do {
    try ApproovService.initialize(config: "<enter-your-config-string-here>")
    // Confirm Approov is actually active before treating it as enabled, then log identifiers
    // for correlation / observability.
    if ApproovService.isApproovEnabled() {
        let deviceID = ApproovService.getDeviceID() ?? "unknown"
        log.info("Approov initialized; deviceID=\(deviceID, privacy: .public) session=\(correlationId, privacy: .public)")
    } else {
        log.notice("Approov initialized in bypass mode (no protection); session=\(correlationId, privacy: .public)")
    }
} catch {
    // Initialization failed — log it and continue UNPROTECTED so the app still works.
    // Re-initializing with an empty config string enters bypass mode (initialized, but no
    // Approov token injection, pinning, or secret substitution).
    log.error("Approov init failed (session=\(correlationId, privacy: .public)); continuing unprotected: \(String(describing: error), privacy: .public)")
    try? ApproovService.initialize(config: "")
}
```

The `<enter-your-config-string-here>` is a custom string that configures your Approov account access. This will have been provided in your Approov onboarding email.

On success the example logs the Approov **device ID** (`getDeviceID()`) and an **app-generated session/correlation id** (a UUID, or any session/user identifier you use) so a given install can be correlated across your app logs, backend, and the Approov [Live Metrics](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). If initialization fails, the example re-initializes with an empty config so the app keeps working — but those requests go out **without Approov protection**, so treat the backend as the enforcement point.

## USING APPROOV SERVICE
Once initialized, use an `ApproovSession` in place of the Alamofire `Session`. It transparently adds the `Approov-Token` header, applies dynamic pinning, and performs any configured secret substitutions and message signing on protected requests:

```swift
import ApproovAFSession

let session = ApproovSession()
session.request("https://api.example.com/endpoint")
    .responseDecodable(of: MyModel.self) { response in
        // handle the response
    }
```

Use this session for all API calls you wish to protect. Approov errors are surfaced as `ApproovError`. See [ALAMOFIRE-OPTIONS.md](ALAMOFIRE-OPTIONS.md) for customizing the `Session`, `ServerTrustManager`, retry behaviour, and network delegates, and [USAGE.md](USAGE.md) for token binding, secret substitution, message signing, and `ApproovServiceMutator` customization.

## CHECKING IT WORKS
Initially you won't have set which API domains to protect, so no Approov token is added. The service still contacts the Approov cloud, and you will see logging from Approov saying `UNKNOWN_URL`.

Your Approov onboarding email should contain a link allowing you to access [Live Metrics Graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). After you've run your app with Approov integration you should be able to see the results in the live metrics within a minute or so. At this stage you could even release your app to get details of your app population and the attributes of the devices they are running upon.

## NEXT STEPS
To actually protect your APIs and/or secrets there are some further steps. Approov provides two different options for protection:

* [API PROTECTION](https://github.com/approov/quickstart-ios-swift-alamofire/blob/master/API-PROTECTION.md): You should use this if you control the backend API(s) being protected and are able to modify them to ensure that a valid Approov token is being passed by the app. An [Approov Token](https://approov.io/docs/latest/approov-usage-documentation/#approov-tokens) is a short-lived cryptographically signed JWT proving the authenticity of the call.

* [SECRETS PROTECTION](https://github.com/approov/quickstart-ios-swift-alamofire/blob/master/SECRETS-PROTECTION.md): This allows app secrets, including API keys for 3rd party services, to be protected so that they no longer need to be included in the released app code. These secrets are only made available to valid apps at runtime.

Note that it is possible to use both approaches side-by-side in the same app.

---

## Useful Links

- [Approov SDK](https://github.com/approov/approov-ios-sdk)
- [Alamofire](https://github.com/Alamofire/Alamofire)
- [Approov Website](https://www.approov.io)
- [Quickstart Guide](https://github.com/approov/quickstart-ios-swift-alamofire)
- [Usage Guide](USAGE.md)
- [Alamofire Options](ALAMOFIRE-OPTIONS.md)
- [Reference Documentation](REFERENCE.md)
- [Changelog](CHANGELOG.md)
