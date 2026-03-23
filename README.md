# Approov Service for Alamofire 

A wrapper for the [Approov SDK](https://github.com/approov/approov-ios-sdk) to enable easy integration when using [`Alamofire`](https://github.com/Alamofire/Alamofire) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

Please see the [Quickstart](https://github.com/approov/quickstart-ios-swift-alamofire) for usage instructions.

## Swift Package Manager Import

When adding this package with Swift Package Manager, import the module as:

```swift
import ApproovAFSession
```

The primary Alamofire session type remains `ApproovSession`.

## Documentation

This repository includes several Markdown files to help you understand and configure the Approov Service:

- [**README.md**](README.md) - This file, providing a basic overview and import instructions.
- [**USAGE.md**](USAGE.md) - Detailed guide on the features and functionality of the Approov Service, including how to interact with the service layer, customize its behavior with `ApproovServiceMutator`, and setup token binding or message signing.
- [**ALAMOFIRE-OPTIONS.md**](ALAMOFIRE-OPTIONS.md) - Additional options specifically available with the Alamofire networking stack, such as network retry options and customizing the `Session`, `ServerTrustManager`, or network delegates.
- [**CHANGELOG.md**](CHANGELOG.md) - Record of all notable changes, new features, and bug fixes for each version of the package.
