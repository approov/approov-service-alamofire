// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.
import Foundation
import PackageDescription
// Release tag
let releaseTAG = "3.5.5"
// SDK package version (used for both iOS and watchOS)
let sdkVersion: Version = "3.5.3"
let useMiniSDK = ProcessInfo.processInfo.environment["APPROOV_USE_MINI_SDK"] == "1"
let miniSDKPath = ProcessInfo.processInfo.environment["APPROOV_MINI_SDK_PATH"] ?? "../core-service-layers-testing/mini-sdk/ios"

let approovPackageName = useMiniSDK ? "mini-sdk-ios" : "approov-ios-sdk"
let packagePlatforms: [SupportedPlatform] = useMiniSDK
    ? [
        .iOS(.v11),
        .watchOS(.v9),
        .macOS(.v13),
    ]
    : [
        .iOS(.v11),
        .watchOS(.v9),
    ]
var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.2.0")),
    .package(url: "https://github.com/apple/swift-http-structured-headers.git", from: "1.0.0"),
]
if useMiniSDK {
    packageDependencies.append(.package(name: "mini-sdk-ios", path: miniSDKPath))
} else {
    packageDependencies.append(.package(url: "https://github.com/approov/approov-ios-sdk.git", exact: sdkVersion))
}

var packageTargets: [Target] = [
    .target(
        name: "ApproovAFSession",
        dependencies: [
            .product(name: "Approov", package: approovPackageName),
            .product(name: "Alamofire", package: "Alamofire"),
            .product(name: "RawStructuredFieldValues", package: "swift-http-structured-headers")
        ],
        path: "Sources/ApproovSession",
        exclude: ["README.md", "LICENSE"]
    )
]

if useMiniSDK {
    packageTargets.append(
        .testTarget(
            name: "ApproovAFSessionMiniSDKTests",
            dependencies: [
                "ApproovAFSession",
                .product(name: "Approov", package: "mini-sdk-ios"),
                .product(name: "MiniSDKTestSupport", package: "mini-sdk-ios")
            ],
            path: "Tests/ApproovAFSessionMiniSDKTests"
        )
    )
}

let package = Package(
    name: "ApproovAFSession",
    platforms: packagePlatforms,
    products: [
        .library(
            name: "ApproovAFSession",
            targets: ["ApproovAFSession"]
        ),
        .library(name: "ApproovAFSessionDynamic", type: .dynamic, targets: ["ApproovAFSession"])
    ],
    dependencies: packageDependencies,
    targets: packageTargets
)
