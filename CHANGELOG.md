# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.


## [3.5.5] - 2026-03-06

### Fixed
- Made `loggingLevel` thread-safe with a dedicated `loggingQueue` to prevent data races on concurrent reads/writes.
- Gated all `os_log` calls in `ApproovTrustManager` behind `ApproovService.loggingLevel` so that `setLoggingLevel` controls all package logging consistently.
- Fixed logging level guard mismatch in `ApproovDefaultMessageSigning` (`.info` → `.error`) and gated additional debug logs.

### Added
- Added `REFERENCE.md` and `USAGE.md` documentation to match other Approov Swift service layers.
- Separated `CHANGELOG.md` from the primary README for better discoverability.
- Introduced `ApproovServiceMutator` interface to allow customizing the behavior of the `ApproovService` during attestation and interception flows without forking the project.
- Added `setUseApproovStatusIfNoToken` configuration to `ApproovService`. When enabled, failure reasons (like `mitm_detected` or `no_network`) are placed in the Approov-Token header if a request proceeds without a valid token.
- Added `setLoggingLevel(_ level: ApproovLogLevel)` configuration for fine-grained control over the package's internal `os_log` statements. Supports `.off`, `.error`, `.warning`, `.info`, and `.debug`.
### Changed
- `ApproovDefaultMessageSigning` now gracefully skips signing and proceeds with the request without throwing an error if the install message signature is unavailable.
- `ApproovDefaultMessageSigning` now implements `ApproovServiceMutator` instead of `ApproovInterceptorExtensions`.
- `ApproovDefaultMessageSigning` now checks for the configured Approov token header via an internal synchronized accessor instead of assuming `Approov-Token`.
### Deprecated
- `ApproovInterceptorExtensions` was replaced by the much more robust `ApproovServiceMutator` protocol. The deprecated `setApproovInterceptorExtensions` API now forwards to `setServiceMutator` for backward compatibility.
### Removed
- `setProceedOnNetworkFailure()` has been removed. Use the `ApproovServiceMutator` instead to customize behavior on network failures. See `USAGE.md` for examples of how to implement a custom mutator.
