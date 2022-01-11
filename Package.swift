// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
let releaseTAG = "2.9.0-bitcode"
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
            checksum : "535cb7b12aa878d6abca175010adaa36a1acb3eebfb5d096a03b2630404f7569"

        )
    ]
)
