// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
let releaseTAG = "3.0.0"
let package = Package(
    name: "ApproovInterceptor",
    platforms: [.iOS(.v10)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "ApproovInterceptor",
            targets: ["ApproovInterceptor", "Approov"]),
    ],
    dependencies: [
        // Here we define our package's external dependencies
        // and from where they can be fetched:
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.2.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "ApproovInterceptor",
            dependencies: ["Alamofire"],
            exclude: ["README.md", "LICENSE"]
            ),
        .binaryTarget(
            name: "Approov",
            url: "https://github.com/approov/approov-ios-sdk/releases/download/" + releaseTAG + "/Approov.xcframework.zip",
            checksum : "5ec60ea00e8e10f34ee3c56033f26d78a8076224e89b6968b74bd1325b688653"
        )
    ]
)
