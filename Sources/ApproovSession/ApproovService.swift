// MIT License
//
// Copyright (c) 2016-present, Approov Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation
import Approov
import os.log

// Approov error conditions
public enum ApproovError: Error, LocalizedError {
    case initializationError(message: String)
    case configurationError(message: String)
    case pinningError(message: String)
    case networkingError(message: String)
    case permanentError(message: String)
    case rejectionError(message: String, ARC: String, rejectionReasons: String)
    public var localizedDescription: String {
        get {
            switch self {
            case let .initializationError(message),
                 let .configurationError(message),
                 let .pinningError(message),
                 let .networkingError(message),
                 let .permanentError(message):
                return message
            case let .rejectionError(message, ARC, rejectionReasons):
                var info: String = ""
                if ARC != "" {
                    info += ", ARC: " + ARC
                }
                if rejectionReasons != "" {
                    info += ", reasons: " + rejectionReasons
                }
                return message + info
            }
        }
    }
    public var errorDescription: String? {
        return localizedDescription
    }
}

// possible results from an Approov request update
public enum ApproovFetchDecision {
    case ShouldProceed      // Proceed with request
    case ShouldRetry        // User can retry request
    case ShouldFail         // Request should not be made
    case ShouldIgnore       // Do not process request
}

// result from adding Approov protection to a request
public struct ApproovUpdateResponse {
    var request: URLRequest
    var decision: ApproovFetchDecision
    var sdkMessage: String
    var error: Error?
}

// Log level for controlling the verbosity of os_log output from the ApproovService
public enum ApproovLogLevel: Int, Comparable {
    case off = 0
    case error = 1
    case warning = 2
    case info = 3
    case debug = 4
    public static func < (lhs: ApproovLogLevel, rhs: ApproovLogLevel) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}

// ApproovService provides a mediation layer to the Approov SDK itself
public class ApproovService {
    // private initializer
    private init() {}

    // the dispatch queue to manage serial access to intializer-modified variables
    private static let initializerQueue = DispatchQueue(label: "ApproovService.initializer", qos: .userInitiated)

    // status of service layer initialization
    private static var serviceIsInitialized = false

    // whether the native Approov SDK has been successfully initialized with a non-empty config
    private static var approovEnabled = false

    // the dispatch queue to manage serial access to other ApproovService state
    private static let stateQueue = DispatchQueue(label: "ApproovService.state", qos: .userInitiated)

    // binding header name
    private static var bindingHeader = ""

    // Approov token default header
    private static var approovTokenHeader = "Approov-Token"

    // Approov token custom prefix: any prefix to be added such as "Bearer "
    private static var approovTokenPrefix = ""

    // Approov TraceID optional header
    private static var approovTraceIDHeader: String? = "Approov-TraceID"

    // the target for request processing serviceMutator
    private static var serviceMutator: ApproovServiceMutator = ApproovServiceMutatorDefault.shared

    // whether to place ApproovTokenFetchStatus inside the Token header when an error occurs or a token is empty
    private static var useApproovStatusIfNoToken = false

    // dedicated queue for thread-safe access to the logging level (separate from stateQueue to
    // avoid nested sync deadlocks when logging is checked inside stateQueue-protected methods)
    private static let loggingQueue = DispatchQueue(label: "ApproovService.logging", qos: .userInitiated)
    private static var _loggingLevel: ApproovLogLevel = .info

    // whether to log to the unified logging system
    // internal access so ApproovDefaultMessageSigning can read the level
    static var loggingLevel: ApproovLogLevel {
        get { loggingQueue.sync { _loggingLevel } }
        set { loggingQueue.sync { _loggingLevel = newValue } }
    }

    // map of headers that should have their values substituted for secure strings, mapped to their
    // required prefixes
    private static var substitutionHeaders: Dictionary<String, String> = Dictionary()

    // set of query parameters that may be substituted, specified by the key name
    private static var substitutionQueryParams: Set<String> = Set()

    // map of URL regexs that should be excluded from any Approov protection, mapped to the compiled Pattern
    private static var exclusionURLRegexs: Dictionary<String, NSRegularExpression> = Dictionary()
    
    /**
     * Returns whether the service layer has been initialized. Returns true even for
     * empty-config bypass mode.
     *
     * @return true if the service layer has been initialized
     */
    public static func isInitialized() -> Bool {
        return initializerQueue.sync { serviceIsInitialized }
    }

    /**
     * Returns whether Approov protection is currently enabled. Returns true only when
     * the service layer has been initialized with a valid, non-empty configuration string.
     *
     * @return true if Approov protection is active
     */
    public static func isApproovEnabled() -> Bool {
        return initializerQueue.sync { approovEnabled }
    }

    /**
     * Initializes the SDK with the config obtained using `approov sdk -getConfigString` or
     * in the original onboarding email.
     *
     * Initialize ONCE, then configure. Every successful call RESETS all service-layer
     * configuration — token header and prefix, binding header, trace-ID header, header and
     * query-parameter substitutions, exclusion URL regexs, and the service mutator — back to
     * their defaults. Any values set via `setTokenHeader` / `addSubstitutionHeader` /
     * `addExclusionURLRegex` / `setServiceMutator` (etc.) must therefore be applied AFTER the
     * final initialize call: re-initializing afterwards, even with the same config, silently
     * discards them. A warning is logged when a re-initialization discards existing state.
     *
     * Calls are forwarded to the native Approov SDK, which is the authority on configuration
     * identity (it compares the config, the update config AND the comment). The resulting
     * behaviour is:
     *   - empty config: initializes the service layer in bypass mode (native SDK not enabled);
     *   - empty config after a valid init: ignored — no downgrade to bypass and, unlike a
     *     valid re-initialize, the existing service-layer configuration is preserved (not reset);
     *   - same config + same comment after a valid init: accepted as a no-op by the native SDK,
     *     but the service layer still resets its configuration to defaults;
     *   - same config + a different non-"reinit" comment, or a different config without a
     *     "reinit" comment: rejected by the native SDK — an `.initializationError` is thrown and
     *     the existing state is preserved;
     *   - a "reinit"-prefixed comment: the native SDK reinitializes and the service layer
     *     resets its configuration to defaults.
     *
     * If a non-empty config is used the native SDK is contacted first; service-layer state is
     * only modified after the SDK confirms success, preserving the current operating mode
     * (protected or bypass) if the call fails.
     *
     * @param config is the configuration to be used, or an empty string to bypass the actual initialization
     * @param comment is an optional comment to be passed to the SDK
     * @throws ApproovError if there was a problem
     */
    public static func initialize(config: String, comment: String? = nil) throws {
        try initializerQueue.sync {
            // Deliberate strict no-op: once protected, an empty config is ignored entirely.
            // There is no downgrade from protected to bypass mode and — unlike a valid
            // re-initialize — the existing service-layer configuration is preserved rather
            // than reset to defaults (see this method's documentation for the full matrix).
            if approovEnabled && config.isEmpty {
                if loggingLevel >= .info {
                    os_log("ApproovService: ignoring empty config after valid initialization", type: .info)
                }
                return
            }

            // Forward all non-empty configs to the native SDK without filtering.
            // The service layer must not intercept, filter, or short-circuit calls
            // based on its internal state (spec §1 line 25).
            if !config.isEmpty {
                do {
                    try Approov.initialize(config, updateConfig: "auto", comment: comment)
                } catch let error {
                    // The Swift/Objective-C bridge translates a BOOL=NO return into
                    // a thrown error with code 0 and domain Foundation._GenericObjCError.
                    // This indicates "already initialized with the same config" — a benign
                    // outcome that we treat as success.
                    let nsError = error as NSError
                    if nsError.code == 0, nsError.domain == "Foundation._GenericObjCError" {
                        if loggingLevel >= .info {
                            os_log("ApproovService: native SDK already initialized (same config): %@", type: .info, nsError.localizedDescription)
                        }
                    } else {
                        // Real failure — leave service-layer state completely unchanged
                        if loggingLevel >= .error {
                            os_log("ApproovService: initialization failed: %@", type: .error, nsError.localizedDescription)
                        }
                        throw ApproovError.initializationError(message: "Error initializing Approov SDK: \(nsError.localizedDescription)")
                    }
                }
            }

            // SDK succeeded (or bypass) — now reset and commit new service-layer state.
            // A successful initialize always resets the service layer's own configuration
            // back to defaults; warn if this discards an existing (re-initialize) setup so
            // that the unsupported "initialize again" pattern is observable.
            if serviceIsInitialized && loggingLevel >= .warning {
                os_log("ApproovService: re-initializing — all service-layer configuration (token header, prefixes, substitutions, exclusions, mutator) is being reset to defaults", type: .default)
            }
            serviceIsInitialized = false
            resetServiceConfiguration()
            serviceIsInitialized = true
            if !config.isEmpty {
                approovEnabled = true
                Approov.setUserProperty("approov-service-alamofire")
                if loggingLevel >= .info {
                    os_log("ApproovService: initialized with Approov protection enabled", type: .info)
                }
            } else {
                approovEnabled = false
                if loggingLevel >= .info {
                    os_log("ApproovService: initialized in bypass mode (empty config)", type: .info)
                }
            }
        }
    }

    /**
     * Gets the last ARC (Attestation Response Code) code.
     *
     * @return String of the last ARC or empty string if there was none
     */
    public static func getLastARC() -> String {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: getLastARC: Approov protection not enabled", type: .error)
            }
            return ""
        }
        // We have to get the current config and obtain one protected API endpoint at least
        // get the dynamic pins from Approov
        guard let approovPins = Approov.getPins("public-key-sha256") else {
            if loggingLevel >= .error {
                 os_log("ApproovService: no host pinning information available", type: .error)
            }
            return ""
        }
        // The approovPins contains a map of hostnames to pin strings.  We need to skip the '*' entry (Managed Trust Roots),
        // and use another hostname if available.
        if let hostname = approovPins.keys.first(where: { $0 != "*" }) {
            let result = Approov.fetchTokenAndWait(hostname)
            // Check if a token was fetched successfully and return its arc code
            if result.token.count > 0 {
                return result.arc
            }
        }
        if loggingLevel >= .info {
            os_log("ApproovService: ARC code unavailable", type: .info)
        }
        return ""
    }

    /**
     * Sets a development key indicating that the app is a development version and it should
     * pass attestation even if the app is not registered or it is running on an emulator. The
     * development key value can be rotated at any point in the account if a version of the app
     * containing the development key is accidentally released. This is primarily
     * used for situations where the app package must be modified or resigned in
     * some way as part of the testing process.
     *
     * @param devKey is the development key to be used
     */
    public static func setDevKey(devKey: String) {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: setDevKey: SDK not initialized", type: .error)
            }
            return
        }
        stateQueue.sync {
            Approov.setDevKey(devKey)
            if loggingLevel >= .debug {
                os_log("ApproovService: setDevKey")
            }
        }
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional
     * prefix String (such as "Bearer "). By default the token is provided on
     * "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header
     */
    public static func setApproovHeader(header: String, prefix: String) {
        stateQueue.sync {
            approovTokenHeader = header
            approovTokenPrefix = prefix
            if loggingLevel >= .debug {
                os_log("ApproovService: setApproovHeader: %@ %@", type: .debug, header, prefix)
            }
        }
    }

    /**
     * Gets the header that is used to add the Approov token.
     *
     * @return the name of the header used for the Approov token
     */
    static func getApproovTokenHeader() -> String {
        return stateQueue.sync {
            return approovTokenHeader
        }
    }

    /**
     * Sets the header name used to provide the optional Approov TraceID debug value. Passing
     * nil disables the TraceID header.
     *
     * @param header is the header to place the Approov TraceID on, or nil to disable it
     */
    public static func setApproovTraceIDHeader(header: String?) {
        stateQueue.sync {
            approovTraceIDHeader = header
            if loggingLevel >= .debug {
                os_log("ApproovService: setApproovTraceIDHeader: %@", type: .debug, header ?? "nil")
            }
        }
    }

    /**
     * Gets the header that is used to add the optional Approov TraceID debug value.
     *
     * @return the name of the header used for the Approov TraceID, or nil if disabled
     */
    public static func getApproovTraceIDHeader() -> String? {
        return stateQueue.sync {
            return approovTraceIDHeader
        }
    }

    /**
     * Sets a binding header that must be present on all requests using the Approov service. A
     * header should be chosen whose value is unchanging for most requests (such as an
     * Authorization header). A hash of the header value is included in the issued Approov tokens
     * to bind them to the value. This may then be verified by the backend API integration. This
     * method should typically only be called once.
     *
     * @param header is the header to use for Approov token binding
     */
    public static func setBindingHeader(header: String) {
        stateQueue.sync {
            bindingHeader = header
            if loggingLevel >= .debug {
                os_log("ApproovService: setBindingHeader: %@", type: .debug, header)
            }
        }
    }

    /**
     * Sets the ApproovServiceMutator instance to handle callbacks from the
     * ApproovService implementation. This facility enables customization of
     * ApproovService operations at key points in the configuration and
     * attestation flows. It should reduce the number of times this service
     * layer implementation needs to be forked in order to introduce custom
     * behavior.
     *
     * @param mutator is the ApproovServiceMutator with callback handlers that may
     *              override the default behavior of the ApproovService singleton.
     *              Passing nil to this method will reinstate the default behavior.
     */
    public static func setServiceMutator(_ mutator: ApproovServiceMutator?) {
        let appliedMutator = mutator ?? ApproovServiceMutatorDefault.shared
        if loggingLevel >= .debug {
            os_log("Applied ApproovServiceMutator: %@", type: .debug, String(describing: appliedMutator))
        }
        stateQueue.sync {
            serviceMutator = appliedMutator
        }
    }

    /**
     * Gets the active service mutator instance that is handling callbacks from ApproovService.
     *
     * @return the service mutator instance (never nil)
     */
    public static func getServiceMutator() -> ApproovServiceMutator {
        return stateQueue.sync {
            return serviceMutator
        }
    }

    /**
     * Sets a flag indicating if the Approov fetch status should be used as the token header value
     * if the actual token fetch fails or returns an empty token. This allows your backend to
     * distinguish between different failure reasons (e.g., NO_NETWORK, MITM_DETECTED) even when
     * the Approov-Token would otherwise be empty or missing.
     *
     * @param shouldUse the use status boolean
     */
    public static func setUseApproovStatusIfNoToken(shouldUse: Bool) {
        stateQueue.sync {
            useApproovStatusIfNoToken = shouldUse
            if loggingLevel >= .info {
                os_log("ApproovService: setUseApproovStatusIfNoToken %@", type: .info, shouldUse ? "YES" : "NO")
            }
        }
    }

    /**
     * Sets the service-layer logging level.
     *
     * This controls all logging emitted by the ApproovService layer. Set to `.debug`
     * when collecting diagnostics for customer issues.
     *
     * @param level the desired severity level
     */
    public static func setLoggingLevel(_ level: ApproovLogLevel) {
        loggingLevel = level
        if level >= .info {
            os_log("ApproovService: logging level set to %d", type: .info, level.rawValue)
        }
    }

    /**
     * @deprecated Use setServiceMutator instead.
     */
    @available(*, deprecated, message: "Use setServiceMutator instead.")
    public static func setApproovInterceptorExtensions(_ callbacks: ApproovInterceptorExtensions?) {
        setServiceMutator(callbacks)
    }

    /**
     * Gets the interceptor extensions callback handlers.
     *
     * @return the interceptor extensions callback handlers or nil if none set
     * @deprecated Use getServiceMutator instead.
     */
    @available(*, deprecated, message: "Use getServiceMutator instead.")
    public static func getApproovInterceptorExtensions() -> ApproovInterceptorExtensions? {
        return getServiceMutator() as? ApproovInterceptorExtensions
    }

    /**
     * Adds the name of a header which should be subject to secure strings substitution. This
     * means that if the header is present then the value will be used as a key to look up a
     * secure string value which will be substituted into the header value instead. This allows
     * easy migration to the use of secure strings. A required prefix may be specified to deal
     * with cases such as the use of "Bearer " prefixed before values in an authorization header.
     *
     * @param header is the header to be marked for substitution
     * @param prefix is any required prefix to the value being substituted or nil if not required
     */
    public static func addSubstitutionHeader(header: String, prefix: String?) {
        stateQueue.sync {
            if prefix == nil {
                substitutionHeaders[header] = ""
                if loggingLevel >= .debug {
                    os_log("ApproovService: addSubstitutionHeader: %@", type: .debug, header)
                }
            } else {
                substitutionHeaders[header] = prefix
                if loggingLevel >= .debug {
                    os_log("ApproovService: addSubstitutionHeader: %@ %@", type: .debug, header, prefix!)
                }
            }
        }
    }

    /**
     * Removes the name of a header if it exists from the secure strings substitution dictionary.
     *
     * @param header is the name of the header to be removed from substitution
     */
    public static func removeSubstitutionHeader(header: String) {
        stateQueue.sync {
            if substitutionHeaders[header] != nil {
                substitutionHeaders.removeValue(forKey: header)
            }
            if loggingLevel >= .debug {
                os_log("ApproovService: removeSubstitutionHeader: %@", type: .debug, header)
            }
        }
    }

    /**
     * Adds a key name for a query parameter that should be subject to secure strings substitution.
     * This means that if the query parameter is present in a URL then the value will be used as a
     * key to look up a secure string value which will be substituted as the query parameter value
     * instead. This allows easy migration to the use of secure strings. Note that this function
     * should be called on initialization rather than for every request.
     *
     * @param key is the query parameter key name to be added for substitution
     */
    public static func addSubstitutionQueryParam(key: String) {
        stateQueue.sync {
            substitutionQueryParams.insert(key)
            if loggingLevel >= .debug {
                os_log("ApproovService: addSubstitutionQueryParam: %@", type: .debug, key)
            }
        }
    }

    /**
     * Removes a query parameter key name previously added using addSubstitutionQueryParam.
     *
     * @param key is the query parameter key name to be removed for substitution
     */
    public static func removeSubstitutionQueryParam(key: String) {
        stateQueue.sync {
            substitutionQueryParams.remove(key)
            if loggingLevel >= .debug {
                os_log("ApproovService: removeSubstitutionQueryParam: %@", type: .debug, key)
            }
        }
    }

    /**
     * Adds an exclusion URL regular expression. If a URL for a request matches this regular expression
     * then it will not be subject to any Approov protection. Note that this facility must be used with
     * EXTREME CAUTION due to the impact of dynamic pinning. Pinning may be applied to all domains added
     * using Approov, and updates to the pins are received when an Approov fetch is performed. If you
     * exclude some URLs on domains that are protected with Approov, then these will be protected with
     * Approov pins but without a path to update the pins until a URL is used that is not excluded. Thus
     * you are responsible for ensuring that there is always a possibility of calling a non-excluded
     * URL, or you should make an explicit call to fetchToken if there are persistent pinning failures.
     * Conversely, use of those option may allow a connection to be established before any dynamic pins
     * have been received via Approov, thus potentially opening the channel to a MitM.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static func addExclusionURLRegex(urlRegex: String) {
        stateQueue.sync {
            do {
                let regex = try NSRegularExpression(pattern: urlRegex, options: [])
                exclusionURLRegexs[urlRegex] = regex
                if loggingLevel >= .debug {
                    os_log("ApproovService: addExclusionURLRegex: %@", type: .debug, urlRegex)
                }
            } catch {
                if loggingLevel >= .debug {
                    os_log("ApproovService: addExclusionURLRegex: %@ error: %@", type: .debug, urlRegex, error.localizedDescription)
                }
            }
        }
    }

    /**
     * Removes an exclusion URL regular expression previously added using addExclusionURLRegex.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static func removeExclusionURLRegex(urlRegex: String) {
        stateQueue.sync {
            if exclusionURLRegexs[urlRegex] != nil {
                exclusionURLRegexs.removeValue(forKey: urlRegex)
                if loggingLevel >= .debug {
                    os_log("ApproovService: removeExclusionURLRegex: %@", type: .debug, urlRegex)
                }
            }
        }
    }

    /**
     * Gets a copy of the current exclusion URL regexs.
     *
     * @return Dictionary of the exclusion regexs to their respective patterns.
     */
    public static func getExclusionURLRegexs() -> Dictionary<String, NSRegularExpression> {
        return stateQueue.sync {
            return exclusionURLRegexs
        }
    }

    /**
     * Allows an Approov fetch operation to be performed as early as possible. This
     * permits a token or secure strings to be available while an application might
     * be loading resources or is awaiting user input. Since the initial fetch is the
     * most expensive the prefetch can hide the most latency.
     */
    public static func prefetch() {
        initializerQueue.sync {
            if serviceIsInitialized && approovEnabled {
                Approov.fetchToken({(approovResult: ApproovTokenFetchResult) in
                    if approovResult.status == ApproovTokenFetchStatus.unknownURL {
                        if loggingLevel >= .debug {
                            os_log("ApproovService: prefetch: success", type: .debug)
                        }
                    } else {
                        if loggingLevel >= .debug {
                            os_log("ApproovService: prefetch: %@", type: .debug, Approov.string(from: approovResult.status))
                        }
                    }
                }, "approov.io")
            }
        }
    }

    /**
     * Performs a precheck to determine if the app will pass attestation. This requires secure
     * strings to be enabled for the account, although no strings need to be set up. This will
     * likely require network access so may take some time to complete. It may throw an exception
     * if the precheck fails or if there is some other problem. Exceptions could be due to
     * a rejection (throws a ApproovError.rejectionError) type which might include additional
     * information regarding the rejection reason. An ApproovError.networkingError exception should
     * allow a retry operation to be performed and finally if some other error occurs an
     * ApproovError.permanentError is raised.
     *
     * @throws ApproovError if there was a problem
     */
    public static func precheck() throws {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: precheck: SDK not initialized", type: .error)
            }
            throw ApproovError.permanentError(message: "ApproovService: precheck requires Approov to be enabled")
        }
        // try to fetch a non-existent secure string in order to check for a rejection
        let approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", nil)
        if approovResults.status == ApproovTokenFetchStatus.unknownKey {
            if loggingLevel >= .debug {
                os_log("ApproovService: precheck: success", type: .debug)
            }
        } else {
            if loggingLevel >= .debug {
                os_log("ApproovService: precheck: %@", type: .debug, Approov.string(from: approovResults.status))
            }
        }

        // process the returned Approov status using the mutator
        let mutator = stateQueue.sync { return serviceMutator }
        try mutator.handlePrecheckResult(approovResults)
    }

    /**
     * Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note
     * that different Approov apps on the same device will return a different ID. Moreover, the ID may be
     * changed by an uninstall and reinstall of the app.
     *
     * @return String of the device ID or nil in case of an error
     */
    public static func getDeviceID() -> String? {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: getDeviceID: SDK not initialized", type: .error)
            }
            return nil
        }
        let deviceID = Approov.getDeviceID()
        if (deviceID != nil) {
            if loggingLevel >= .debug {
                os_log("ApproovService: getDeviceID %@", type: .debug, deviceID!)
            }
        }
        return deviceID
    }

    /**
     * Directly sets the data hash to be included in subsequently fetched Approov tokens. If the hash is
     * different from any previously set value then this will cause the next token fetch operation to
     * fetch a new token with the correct payload data hash. The hash appears in the
     * 'pay' claim of the Approov token as a base64 encoded string of the SHA256 hash of the
     * data. Note that the data is hashed locally and never sent to the Approov cloud service.
     *
     * @param data is the data to be hashed and set in the token
     */
    public static func setDataHashInToken(data: String) {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: setDataHashInToken: SDK not initialized", type: .error)
            }
            return
        }
        if loggingLevel >= .debug {
            os_log("ApproovService: setDataHashInToken", type: .debug)
        }
        Approov.setDataHashInToken(data)
    }

    /**
     * Performs an Approov token fetch for the given URL. This should be used in situations where it
     * is not possible to use the networking interception to add the token. This will
     * likely require network access so may take some time to complete. If the attestation fails
     * for any reason then an ApproovError is thrown. This will be ApproovNetworkException for
     * networking issues wher a user initiated retry of the operation should be allowed. Note that
     * the returned token should NEVER be cached by your app, you should call this function when
     * it is needed.
     *
     * @param url is the URL giving the domain for the token fetch
     * @return String of the fetched token
     * @throws ApproovError if there was a problem
     */
    public static func fetchToken(url: String) throws -> String {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: fetchToken: SDK not initialized", type: .error)
            }
            throw ApproovError.permanentError(message: "ApproovService: fetchToken requires Approov to be enabled")
        }
        // fetch the Approov token
        let result: ApproovTokenFetchResult = Approov.fetchTokenAndWait(url)
        if loggingLevel >= .debug {
            os_log("ApproovService: fetchToken: %@", type: .debug, Approov.string(from: result.status))
        }

        // process the status using the mutator
        let mutator = stateQueue.sync { return serviceMutator }
        try mutator.handleFetchTokenResult(result)
        return result.token
    }

    /**
     * Gets the signature for the given message. This method is obsolete and will return
     * the account-specific message signature.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     */
    @available(*, deprecated, message: "Use getAccountMessageSignature or getInstallMessageSignature instead.")
    public static func getMessageSignature(message: String) -> String? {
        return getAccountMessageSignature(message: message)
    }

    /**
     * Gets the signature for the given message using the account-specific signing key.
     * This key is transmitted to the SDK after a successful fetch if the feature is enabled.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     */
    public static func getAccountMessageSignature(message: String) -> String? {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: getAccountMessageSignature: SDK not initialized", type: .error)
            }
            return nil
        }
        if loggingLevel >= .debug {
            os_log("ApproovService: getAccountMessageSignature", type: .debug)
        }
        return Approov.getMessageSignature(message)
    }

    /**
     * Gets the signature for the given message using the install-specific signing key.
     * This key is tied to the specific app installation and is transmitted after a successful fetch.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     */
    public static func getInstallMessageSignature(message: String) -> String? {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: getInstallMessageSignature: SDK not initialized", type: .error)
            }
            return nil
        }
        if loggingLevel >= .debug {
            os_log("ApproovService: getInstallMessageSignature", type: .debug)
        }
        return Approov.getInstallMessageSignature(message)
    }

    /**
     * Fetches a secure string with the given key. If newDef is not nil then a secure string for
     * the particular app instance may be defined. In this case the new value is returned as the
     * secure string. Use of an empty string for newDef removes the string entry. Note that this
     * call may require network transaction and thus may block for some time, so should not be called
     * from the UI thread. If the attestation fails for any reason then an exception is raised. Note
     * that the returned string should NEVER be cached by your app, you should call this function when
     * it is needed. If the fetch fails for any reason an exception is thrown with description.
     * A rejection throws an Approov.rejectionError type which might include additional information
     * regarding the failure reason.
     * An ApproovError.networkingError exception should allow a retry operation to be performed and finally,
     * if some other error occurs, an Approov.permanentError is raised.
     *
     * @param key is the secure string key to be looked up
     * @param newDef is any new definition for the secure string, or nil for lookup only
     * @return secure string (should not be cached by your app) or nil if it was not defined or an error occurred
     * @throws ApproovError if there was a problem
     */
    public static func fetchSecureString(key: String, newDef: String?) throws -> String? {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: fetchSecureString: SDK not initialized", type: .error)
            }
            throw ApproovError.permanentError(message: "ApproovService: fetchSecureString requires Approov to be enabled")
        }
        // determine the type of operation as the values themselves cannot be logged
        var type = "lookup"
        if newDef != nil {
            type = "definition"
        }

        // try and fetch the secure string
        let approovResult = Approov.fetchSecureStringAndWait(key, newDef)
        if loggingLevel >= .info {
            os_log("ApproovService: fetchSecureString: %@: %@", type: .info, type, Approov.string(from: approovResult.status))
        }

        // process the returned Approov status using the mutator
        let mutator = stateQueue.sync { return serviceMutator }
        try mutator.handleFetchSecureStringResult(approovResult, operation: type, key: key)
        return approovResult.secureString
    }

    /**
     * Fetches a custom JWT with the given payload. Note that this call will require network
     * transaction and thus will block for some time, so should not be called from the UI thread.
     * If the fetch fails for any reason an exception will be thrown. Exceptions could be due to
     * malformed JSON string provided (then an ApproovError.permanentError is raised), a rejection throws
     * an ApproovError.rejectionError type which might include additional information regarding the failure
     * reason. An Approov.networkingError exception should allow a retry operation to be performed.
     * If some other error occurs an Approov.permanentError is raised.
     *
     * @param payload is the marshaled JSON object for the claims to be included
     * @return custom JWT string or nil if an error occurred
     * @throws ApproovError if there was a problem
     */
    public static func fetchCustomJWT(payload: String) throws -> String? {
        if !isApproovEnabled() {
            if loggingLevel >= .error {
                os_log("ApproovService: fetchCustomJWT: SDK not initialized", type: .error)
            }
            throw ApproovError.permanentError(message: "ApproovService: fetchCustomJWT requires Approov to be enabled")
        }
        // fetch the custom JWT
        let approovResult = Approov.fetchCustomJWTAndWait(payload)
        if loggingLevel >= .info {
            os_log("ApproovService: fetchCustomJWT: %@", type: .info, Approov.string(from: approovResult.status))
        }

        // process the returned Approov status using the mutator
        let mutator = stateQueue.sync { return serviceMutator }
        try mutator.handleFetchCustomJWTResult(approovResult)
        return approovResult.token
    }

    /**
     * Host component only gets resolved if the string includes the protocol used. This is not always the case
     * when making requests so a convenience method is needed.
     *
     * @param url is the URL being handled
     * @return String of the host name
     */
    private static func hostnameFromURL(url: URL) -> String {
        if url.absoluteString.starts(with: "https") {
            return url.host!
        } else {
            let fullHost = "https://" + url.absoluteString
            let newURL = URL(string: fullHost)
            if let host = newURL?.host {
                return host
            } else {
                return ""
            }
        }
    }

    /**
     * Checks if the url matches one of the exclusion regexs.
     *
     * @param url is the URL to be checked
     * @return  Bool true if url matches preset pattern in Dictionary
     */
    private static func isURLExcluded(url: URL) -> Bool {
        return stateQueue.sync {
            for (_, regex) in exclusionURLRegexs {
                let urlString = url.absoluteString
                let urlStringRange = NSRange(urlString.startIndex..<urlString.endIndex, in: urlString)
                let matches: [NSTextCheckingResult] = regex.matches(in: urlString, options: [], range: urlStringRange)
                if !matches.isEmpty {
                    return true
                }
            }
            return false
        }
    }

    /**
     * Convenience function fetching the Approov token and updating the request with it. This will also
     * perform header or query parameter substitutions to include protected secrets.
     *
     * @param request is the original request to be made
     * @return ApproovUpdateResponse providing an updated requests, plus an errors and status
     */
    @available(*, deprecated, renamed: "updateRequestWithApproov(_:)")
    public static func updateRequestWithApproov(request: URLRequest) -> ApproovUpdateResponse {
        return updateRequestWithApproov(request)
    }

    /**
     * Updates the request with Approov protection.
     *
     * @param request is the original request to be made
     * @return ApproovUpdateResponse providing an updated requests, plus an errors and status
     */
    public static func updateRequestWithApproov(_ request: URLRequest) -> ApproovUpdateResponse {
        var changes = ApproovRequestMutations()

        // fetch the mutator that modifies decision-making behavior
        let mutator = stateQueue.sync { return serviceMutator }

        // check if the mutator wants to process this request
        do {
            if try !mutator.handleInterceptorShouldProcessRequest(request) {
                return ApproovUpdateResponse(request: request, decision: .ShouldProceed, sdkMessage: "", error: nil)
            }
        } catch {
            let nsError = error as NSError
            return ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: "", error: ApproovError.permanentError(message: nsError.localizedDescription))
        }

        if let url = request.url {
            if !isInitialized() || !isApproovEnabled() {
                if loggingLevel >= .info {
                    os_log("ApproovService: not initialized or not enabled, forwarding: %@", type: .info, url.absoluteString)
                }
                return ApproovUpdateResponse(request: request, decision: .ShouldIgnore, sdkMessage: "", error: nil)
            }
            if isURLExcluded(url: url) {
                if loggingLevel >= .info {
                    os_log("ApproovService: excluded, forwarding: %@", type: .info, url.absoluteString)
                }
                return ApproovUpdateResponse(request: request, decision: .ShouldIgnore, sdkMessage: "", error: nil)
            }
        } else {
            if loggingLevel >= .info {
                os_log("ApproovService: no url provided", type: .info)
            }
            return ApproovUpdateResponse(request: request, decision: .ShouldIgnore, sdkMessage: "", error: nil)
        }

        // we construct a response to return
        var response = ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: "", error: nil)

        // check if we need to apply a binding header
        let bindHeader = stateQueue.sync {
            return bindingHeader
        }
        if bindHeader != "" {
            // see if the binding header is present
            if let value = request.value(forHTTPHeaderField: bindHeader) {
                // add the binding header value as a data hash to Approov token
                Approov.setDataHashInToken(value)
            }
        }

        // fetch an Approov token: request.url can not be nil here
        let approovResult = Approov.fetchTokenAndWait(request.url!.absoluteString)
        let hostname = hostnameFromURL(url: request.url!)
        if loggingLevel >= .info {
            os_log("ApproovService: updateRequest %@: %@", type: .info, hostname, approovResult.loggableToken())
        }

        // log if a configuration update is received and call fetchConfig to clear the update state
        if approovResult.isConfigChanged {
            Approov.fetchConfig()
            if loggingLevel >= .info {
                os_log("ApproovService: dynamic configuration update performed")
            }
        }

        // handle the Approov token fetch response with the mutator
        do {
            if try !mutator.handleInterceptorFetchTokenResult(approovResult, url: request.url!.absoluteString) {
                // Determine whether mutator aborted due to rejection, networking issue or config error by running the default logic
                // we construct a response to return
                var response = ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: Approov.string(from: approovResult.status), error: nil)
                switch approovResult.status {
                case .noNetwork, .poorNetwork, .mitmDetected:
                    response.decision = .ShouldRetry
                    response.error = ApproovError.networkingError(message: response.sdkMessage)
                case .noApproovService, .unknownURL, .unprotectedURL:
                    response.decision = .ShouldProceed
                default:
                    response.error = ApproovError.permanentError(message: response.sdkMessage)
                }
                return response
            }
        } catch let mutatorError as ApproovError {
            // Handle specific errors thrown by the mutator (e.g. throwing rejection error or networking error early)
            switch mutatorError {
            case .rejectionError:
                return ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: Approov.string(from: approovResult.status), error: mutatorError)
            case .networkingError:
                return ApproovUpdateResponse(request: request, decision: .ShouldRetry, sdkMessage: Approov.string(from: approovResult.status), error: mutatorError)
            default:
                return ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: Approov.string(from: approovResult.status), error: mutatorError)
            }
        } catch {
            return ApproovUpdateResponse(request: request, decision: .ShouldFail, sdkMessage: Approov.string(from: approovResult.status), error: ApproovError.permanentError(message: error.localizedDescription))
        }

        response.sdkMessage = Approov.string(from: approovResult.status)
        var hasChanges = false
        var setTokenHeaderKey: String?
        var setTokenHeaderValue: String?
        var setTraceIDHeaderKey: String?
        var setTraceIDHeaderValue: String?
        var setSubstitutionHeaders: [String: String] = [:]
        var updateURL: URL?
        var queryKeys: [String] = []

        // All paths proceeding past the Mutator imply the request should continue
        response.decision = .ShouldProceed

        let tokenHeader = stateQueue.sync { return approovTokenHeader }
        let tokenPrefix = stateQueue.sync { return approovTokenPrefix }
        let useStatus = stateQueue.sync { return useApproovStatusIfNoToken }

        // Finalizes the in-flight interceptor result by applying every staged mutation to
        // `response.request` and then invoking the mutator post-processing callback.
        //
        // The function stages changes in local variables first so the success path and the
        // "proceed without a valid token" path can share the same commit logic. This function:
        // 1. Writes the Approov token header if one was prepared, which may contain either the
        //    actual token or an Approov status string when `useApproovStatusIfNoToken` is enabled.
        // 2. Writes the optional trace ID header.
        // 3. Applies any secure string header substitutions.
        // 4. Applies any query parameter substitutions and records them in `changes`.
        // 5. Passes the fully mutated request through `handleInterceptorProcessedRequest`.
        //
        // Calling this before returning is essential for non-success statuses that are still
        // allowed to proceed by the active mutator; without it the staged status header would
        // never be written to the outgoing request.
        func finalizeResponse() -> ApproovUpdateResponse {
            if hasChanges {
                if let tokenHeaderKey = setTokenHeaderKey,
                   let tokenHeaderValue = setTokenHeaderValue {
                    response.request.setValue(tokenHeaderValue, forHTTPHeaderField: tokenHeaderKey)
                    changes.setTokenHeaderKey(tokenHeaderKey)
                }
                if let traceIDHeaderKey = setTraceIDHeaderKey,
                   let traceIDHeaderValue = setTraceIDHeaderValue {
                    response.request.setValue(traceIDHeaderValue, forHTTPHeaderField: traceIDHeaderKey)
                    changes.setTraceIDHeaderKey(traceIDHeaderKey)
                }
                if !setSubstitutionHeaders.isEmpty {
                    for (header, value) in setSubstitutionHeaders {
                        response.request.setValue(value, forHTTPHeaderField: header)
                    }
                    changes.setSubstitutionHeaderKeys(Array(setSubstitutionHeaders.keys))
                }
                if let updateURLString = updateURL?.absoluteString,
                   let originalURLString = request.url?.absoluteString,
                   originalURLString != updateURLString {
                    response.request.url = updateURL
                    changes.setSubstitutionQueryParamResults(originalURL: originalURLString, substitutionQueryParamKeys: queryKeys)
                }
            }

            do {
                response.request = try mutator.handleInterceptorProcessedRequest(response.request, changes: changes)
            } catch let error {
                response.decision = .ShouldFail
                response.error = ApproovError.permanentError(
                    message: "Interceptor processed request error: \(error.localizedDescription)")
            }

            return response
        }

        if approovResult.status == .success {
            // Success Path
            hasChanges = true
            setTokenHeaderKey = tokenHeader
            
            if useStatus && approovResult.token.isEmpty {
                setTokenHeaderValue = tokenPrefix + Approov.string(from: approovResult.status)
            } else {
                setTokenHeaderValue = tokenPrefix + approovResult.token
            }
            
            let traceID = approovResult.traceID
            if let traceHeader = stateQueue.sync(execute: { approovTraceIDHeader }),
               !traceHeader.isEmpty, !traceID.isEmpty {
                hasChanges = true
                setTraceIDHeaderKey = traceHeader
                setTraceIDHeaderValue = traceID
            }
        } else if approovResult.status != .noApproovService,
                  approovResult.status != .unknownURL,
                  approovResult.status != .unprotectedURL {
            // We are proceeding (allowed by mutator) with a failure status.
            // Add the status string to the Approov token header if
            // useApproovStatusIfNoToken is set, so callers can observe it.
            if useStatus {
                hasChanges = true
                setTokenHeaderKey = tokenHeader
                setTokenHeaderValue = tokenPrefix + Approov.string(from: approovResult.status)
            }
        }

        // we only continue additional processing if we had a valid status from Approov, to prevent additional delays
        // by trying to fetch from Approov again and this also protects against header substitutions in domains not
        // protected by Approov and therefore are potentially subject to a MitM.
        if approovResult.status != .success {
            return finalizeResponse()
        }

        // we now deal with any headers substitutions, which may require further fetches but these
        // should be using cached results
        if let requestHeaders = response.request.allHTTPHeaderFields {
            let subsHeadersCopy = stateQueue.sync {
                return substitutionHeaders
            }

            // apply any header substitutions using the mutator policy
            for (header, prefix) in subsHeadersCopy {
                if let headerValue = requestHeaders[header], headerValue.hasPrefix(prefix), headerValue.count > prefix.count {
                    let key = String(headerValue.dropFirst(prefix.count))
                    let approovResults = Approov.fetchSecureStringAndWait(key, nil)

                    // we check if mutator allows processing substitution
                    var fetchString = false
                    do {
                        if try mutator.handleInterceptorHeaderSubstitutionResult(approovResults, header: header) {
                            fetchString = true
                        }
                    } catch let mutatorError as ApproovError {
                        switch mutatorError {
                        case .networkingError:
                            response.decision = .ShouldRetry
                            response.error = mutatorError
                        default:
                            response.decision = .ShouldFail
                            response.error = mutatorError
                        }
                        return response
                    } catch {
                        response.decision = .ShouldFail
                        response.error = ApproovError.permanentError(message: error.localizedDescription)
                        return response
                    }

                    if fetchString {
                        if loggingLevel >= .info {
                            os_log("ApproovService: Substituting header: %@, %@", type: .info, header, Approov.string(from: approovResults.status))
                        }
                        if approovResults.status == ApproovTokenFetchStatus.success {
                            if let secureStringResult = approovResults.secureString {
                                hasChanges = true;
                                setSubstitutionHeaders[header] = prefix + secureStringResult
                            } else {
                                response.decision = .ShouldFail
                                response.error = ApproovError.permanentError(message: "Header substitution: key lookup error")
                                return response
                            }
                        }
                    }
                }
            }
        }

        // we now deal with any query parameter substitutions, which may require further fetches but these
        // should be using cached results
        if let originalURL = request.url {
            let subsQueryParamsCopy = stateQueue.sync {
                return substitutionQueryParams
            }
            var updateURLString = originalURL.absoluteString
            for entry in subsQueryParamsCopy {
                let urlStringRange = NSRange(updateURLString.startIndex..<updateURLString.endIndex, in: updateURLString)
                let regex = try! NSRegularExpression(pattern: #"[\\?&]"# + entry + #"=([^&;]+)"#, options: [])
                let matches: [NSTextCheckingResult] = regex.matches(in: updateURLString, options: [], range: urlStringRange)
                for match: NSTextCheckingResult in matches {
                    // we skip the range at index 0 as this is the match (e.g. ?Api-Key=api_key_placeholder) for the whole
                    // regex, but we only want to replace the query parameter value part (e.g. api_key_placeholder)
                    for rangeIndex in 1..<match.numberOfRanges {
                        // we have found an occurrence of the query parameter to be replaced so we look up the existing
                        // value as a key for a secure string
                        let matchRange = match.range(at: rangeIndex)
                        if let substringRange = Range(matchRange, in: updateURLString) {
                            let queryValue = String(updateURLString[substringRange])
                            let approovResults = Approov.fetchSecureStringAndWait(String(queryValue), nil)
                            
                            if loggingLevel >= .info {
                                os_log("ApproovService: Attempting query parameter substitution: %@, %@", entry,
                                    Approov.string(from: approovResults.status))
                            }

                            var allowSub = false
                            do {
                                allowSub = try mutator.handleInterceptorQueryParamSubstitutionResult(approovResults, queryKey: entry)
                            } catch let mutatorError as ApproovError {
                                switch mutatorError {
                                case .networkingError:
                                    response.decision = .ShouldRetry
                                    response.error = mutatorError
                                default:
                                    response.decision = .ShouldFail
                                    response.error = mutatorError
                                }
                                return response
                            } catch {
                                response.decision = .ShouldFail
                                response.error = ApproovError.permanentError(message: error.localizedDescription)
                                return response
                            }

                            // process the result of the secure string fetch operation
                            if allowSub && approovResults.status == .success {
                                // perform a query substitution
                                if let secureStringResult = approovResults.secureString {
                                    hasChanges = true
                                    queryKeys.append(entry)
                                    updateURLString.replaceSubrange(Range(matchRange, in: updateURLString)!, with: secureStringResult)
                                    updateURL = URL(string: updateURLString)
                                    if updateURL == nil {
                                        response.decision = .ShouldFail
                                        response.error = ApproovError.permanentError(
                                            message: "Query parameter substitution for \(entry): malformed URL \(updateURLString)")
                                        return response
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return finalizeResponse()
    }

    /**
     * Resets all configurable service-layer state (headers, prefixes, substitutions,
     * exclusions and the service mutator) back to their defaults. Acquires `stateQueue`
     * internally, so callers must not already hold it. Initialization flags
     * (`serviceIsInitialized` / `approovEnabled`) are managed separately by the caller.
     */
    private static func resetServiceConfiguration() {
        stateQueue.sync {
            bindingHeader = ""
            approovTokenHeader = "Approov-Token"
            approovTokenPrefix = ""
            approovTraceIDHeader = "Approov-TraceID"
            serviceMutator = ApproovServiceMutatorDefault.shared
            substitutionHeaders = Dictionary()
            substitutionQueryParams = Set()
            exclusionURLRegexs = Dictionary()
            useApproovStatusIfNoToken = false
        }
    }

    /**
     * Resets all service-layer state back to defaults. This is intended for testing only
     * and should never be called in production code.
     */
    static func resetForTesting() {
        initializerQueue.sync {
            serviceIsInitialized = false
            approovEnabled = false
        }
        resetServiceConfiguration()
        loggingLevel = .info
    }
}
