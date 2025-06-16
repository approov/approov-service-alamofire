// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
// Release tag
let releaseTAG = "3.4.0"
// SDK package version (used for both iOS and watchOS)
let sdkVersion = "3.4.0"

let package = Package(
    name: "ApproovSession",
    platforms: [
        .iOS(.v11),
        .watchOS(.v9)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "ApproovSession",
            targets: ["ApproovSession"]
        ),
        .library(name: "ApproovSessionDynamic", type: .dynamic, targets: ["ApproovSession"])
    ],
    dependencies: [
        // Package's external dependencies and from where they can be fetched:
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.2.0")),
        .package(url: "https://github.com/apple/swift-http-structured-headers.git", from: "1.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "ApproovSession",
            dependencies: [
                "Approov",
                "Alamofire",
                .product(name: "RawStructuredFieldValues", package: "swift-http-structured-headers")
            ],
            path: "Sources/ApproovSession",  // Point to the shared source code
            exclude: ["README.md", "LICENSE"]
        ),
        // Binary target for the merged xcframework
        .binaryTarget(
            name: "Approov",
            url: "https://github.com/approov/approov-ios-sdk/releases/download/\(sdkVersion)/Approov.xcframework.zip",
            checksum: "9a02cb9ca905a9e2e0692047dfd4cdbfd3133c9e4b644bdfe898f7ce1b8d7461" // SHA256 checksum of the xcframework zip file
        )
    ]
)
