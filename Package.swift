// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
// Release tag
let releaseTAG = "3.5.4"
// SDK package version (used for both iOS and watchOS)
let sdkVersion = "3.5.3"

let package = Package(
    name: "ApproovAFSession",
    platforms: [
        .iOS(.v11),
        .watchOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "ApproovAFSession",
            targets: ["ApproovAFSession"]
        ),
        .library(name: "ApproovAFSessionDynamic", type: .dynamic, targets: ["ApproovAFSession"])
    ],
    dependencies: [
        // Package's external dependencies and from where they can be fetched:
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.2.0")),
        .package(url: "https://github.com/apple/swift-http-structured-headers.git", from: "1.0.0"),
        // Force-unwrapping is safe here because sdkVersion is a valid semantic version string
        .package(url: "https://github.com/approov/approov-ios-sdk.git", from: Version(sdkVersion)!)
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "ApproovAFSession",
            dependencies: [
                .product(name: "Approov", package: "approov-ios-sdk"),
                .product(name: "Alamofire", package: "Alamofire"),
                .product(name: "RawStructuredFieldValues", package: "swift-http-structured-headers")
            ],
            path: "Sources/ApproovSession",  // Point to the shared source code
            exclude: ["README.md", "LICENSE"]
        )
    ]
)
