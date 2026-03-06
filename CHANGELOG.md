# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.5.5] - 2026-03-06

### Added
- Added `REFERENCE.md` and `USAGE.md` documentation to match other Approov Swift service layers.
- Separated `CHANGELOG.md` from the primary README for better discoverability.
- Introduced `ApproovServiceMutator` interface to allow customizing the behavior of the `ApproovService` during attestation and interception flows without forking the project.
### Changed
- `ApproovDefaultMessageSigning` now gracefully skips signing and proceeds with the request without throwing an error if the install message signature is unavailable.
- `ApproovDefaultMessageSigning` now implements `ApproovServiceMutator` instead of `ApproovInterceptorExtensions`.
### Deprecated
- `ApproovInterceptorExtensions` was replaced by the much more robust `ApproovServiceMutator` protocol. `setApproovInterceptorExtensions` now does nothing and emits a deprecation warning.
### Removed
- `setProceedOnNetworkFailure()` has been removed. Use the `ApproovServiceMutator` instead to customize behavior on network failures. See `USAGE.md` for examples of how to implement a custom mutator.
