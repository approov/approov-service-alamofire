# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.


## [3.5.6] - 2026-06-12

### Added
- `initialize(config:comment:)` now accepts an optional `comment` parameter forwarded to the native SDK, supporting `options:` startup flags and `reinit` flows.
- Bypass mode: passing an empty `config` string initializes the service layer without enabling the native Approov SDK; a subsequent call with a valid config upgrades to protected mode.
- `isInitialized()` public API exposing service-layer initialization state (distinct from `isApproovEnabled()`).
- `SECURITY.md` with version support table and vulnerability reporting instructions.
- GitHub Actions CI workflow (`build_and_test.yml`) for automated builds and mini-SDK contract tests.
- Mini-SDK integration tests covering §1 initialization scenarios: valid config, empty config, empty→valid upgrade, valid→empty (ignored), same-config reinit, different-config rejection with state preservation, mutator reset, and SDK method guards in bypass mode.

### Changed
- Commit-last initialization pattern: service-layer state is only modified after the SDK confirms success, preserving the current operating mode on failure.
- Valid-then-empty guard: once initialized with a valid config, subsequent empty-config calls are silently ignored (no downgrade from protected to bypass mode).
- Trust manager performs OS-level certificate validation (`performDefaultValidation`) even in bypass mode; dynamic pinning skipped when SDK is not enabled.

### Fixed
- Removed stale Android/OkHttpClient reference from `ApproovService.swift` doc comment.
- Corrected grammar and clarified supported version table in `SECURITY.md`.

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
