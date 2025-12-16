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

// ApproovService provides a mediation layer to the Approov SDK itself
public class ApproovService {
    // private initializer
    private init() {}

    // the dispatch queue to manage serial access to intializer-modified variables
    private static let initializerQueue = DispatchQueue(label: "ApproovService.initializer", qos: .userInitiated)

    // configuration string used for initialization
    private static var configString: String?

    // status of Approov SDK initialization
    private static var isInitialized = false

    // the dispatch queue to manage serial access to other ApproovService state
    private static let stateQueue = DispatchQueue(label: "ApproovService.state", qos: .userInitiated)

    // if we should proceed on network fail
    private static var proceedOnNetworkFail = false

    // binding header name
    private static var bindingHeader = ""

    // Approov token default header
    private static var approovTokenHeader = "Approov-Token"

    // Approov token custom prefix: any prefix to be added such as "Bearer "
    private static var approovTokenPrefix = ""

    // the target for request processing interceptorExtensions
    private static var interceptorExtensions: ApproovInterceptorExtensions? = nil

    // stores the last ARC value for retrieval
    private static var lastARC: String? = nil

    // map of headers that should have their values substituted for secure strings, mapped to their
    // required prefixes
    private static var substitutionHeaders: Dictionary<String, String> = Dictionary()

    // set of query parameters that may be substituted, specified by the key name
    private static var substitutionQueryParams: Set<String> = Set()

    // map of URL regexs that should be excluded from any Approov protection, mapped to the compiled Pattern
    private static var exclusionURLRegexs: Dictionary<String, NSRegularExpression> = Dictionary()
    /**
     * Initializes the SDK with the config obtained using `approov sdk -getConfigString` or
     * in the original onboarding email. Note the initializer function should only ever be called once.
     * Subsequent calls will be ignored since the ApproovSDK can only be initialized once; if however,
     * an attempt is made to initialize with a different configuration (config) we throw an
     * ApproovException.configurationError. If the Approov SDK fails to be initialized for some other
     * reason, an .initializationError is raised.
     *
     * @param config is the configuration to be used, or an empty string to bypass the actual initialization
     * @param comment is an optional comment to be passed to the SDK
     * @throws ApproovError if there was a problem
     */
    public static func initialize(config: String, comment: String? = nil) throws {
        try initializerQueue.sync  {
            // check if we attempt to use a different configString
            if isInitialized && ((comment?.hasPrefix("reinit")) == nil) {
                // ignore multiple initialization calls that use the same configuration
                if (config != configString) {
                    // throw exception indicating we are attempting to use different config
                    os_log("ApproovService: Attempting to initialize with different configuration", type: .error)
                    throw ApproovError.configurationError(message: "Attempting to initialize with a different configuration")
                }
                os_log("ApproovService: Ignoring multiple ApproovService layer initializations with the same config");
            } else {
                do {
                    if !config.isEmpty {
                        // only initialize with a non-empty string as empty string used to bypass this
                        try Approov.initialize(config, updateConfig: "auto", comment: comment)
                    }
                } catch let error {
                    // If the error is due to the SDK being initilized already, we ignore it otherwise we throw
                    if error.localizedDescription.localizedCaseInsensitiveContains("Approov SDK already initialized") {
                        os_log("ApproovService: Ignoring initialization error in Approov SDK: %@", type: .error, error.localizedDescription)
                        isInitialized = true
                    } else {
                        throw ApproovError.initializationError(message: "Error initializing Approov SDK: \(error.localizedDescription)")
                    }
                }
                isInitialized = true
                configString = config
                Approov.setUserProperty("approov-service-urlsession")
            }
        }
    }

    /**
     * Sets the last ARC code returned by the Approov SDK (thread-safe).
     *
     * - Parameter arc: The ARC code to store (may be nil).
     */
    public static func setLastARC(result: ApproovTokenFetchResult) {
        var arc = ""
        // Return empty string if there are connection problem during fetch
        if(result.status != ApproovTokenFetchStatus.noApproovService
        && result.status != ApproovTokenFetchStatus.noNetwork){
            arc = result.arc
        }
        // Update ARC
        stateQueue.sync {
            lastARC = arc
        }
    }

    /**
     * Gets the last ARC code returned by the Approov SDK (thread-safe).
     *
     * - Returns: The last stored ARC code, or nil if none has been stored.
     */
    public static func getLastARC() -> String? {
        stateQueue.sync {
            lastARC
        }
    }

    /**
     * Sets a flag indicating if the network interceptor should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure. If this is set
     * then your backend API can receive calls without the expected Approov token header
     * being added, or without header/query parameter substitutions being made. Note that
     * this should be used with caution because it may allow a connection to be established
     * before any dynamic pins have been received via Approov, thus potentially opening the
     * channel to a MitM.
     *
     * @param proceed is true if Approov networking fails should allow continuation
     */
    public static func setProceedOnNetworkFailure(proceed: Bool) {
        stateQueue.sync {
            proceedOnNetworkFail = proceed
            os_log("ApproovService: setProceedOnNetworkFailure ", type: .info, proceed)
        }
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
        stateQueue.sync {
            Approov.setDevKey(devKey)
            os_log("ApproovService: setDevKey")
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
            os_log("ApproovService: setApproovHeader: %@", type: .debug, header, prefix)
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
            os_log("ApproovService: setBindingHeader: %@", type: .debug, header)
        }
    }

    /**
     * Sets the interceptor extensions callback handler. This facility was introduced to support
     * message signing that is independent from the rest of the attestation flow. The default
     * ApproovService layer issues no callbacks, provide a non-null ApproovInterceptorExtensions
     * handler to add functionality to the attestation flow.
     *
     * @param callbacks is the configuration used to control message signing. The behaviour of the
     *              provided configuration must remain constant while in use by the ApproovService.
     *              Passing null to this method will disable message signing.
     */
    public static func setApproovInterceptorExtensions(_ callbacks: ApproovInterceptorExtensions?) {
        if callbacks == nil {
            os_log("Interceptor extension disabled", type: .debug)
        } else {
            os_log("Interceptor extension enabled", type: .debug)
        }
        stateQueue.sync {
            interceptorExtensions = callbacks
        }
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
                os_log("ApproovService: addSubstitutionHeader: %@", type: .debug, header)
            } else {
                substitutionHeaders[header] = prefix
                os_log("ApproovService: addSubstitutionHeader: %@ %@", type: .debug, header, prefix!)
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
            os_log("ApproovService: removeSubstitutionHeader: %@", type: .debug, header)
        }
    }

    /**
     * Adds a key name for a query parameter that should be subject to secure strings substitution.
     * This means that if the query parameter is present in a URL then the value will be used as a
     * key to look up a secure string value which will be substituted as the query parameter value
     * instead. This allows easy migration to the use of secure strings. Note that this function
     * should be called on initialization rather than for every request as it will require a new
     * OkHttpClient to be built.
     *
     * @param key is the query parameter key name to be added for substitution
     */
    public static func addSubstitutionQueryParam(key: String) {
        stateQueue.sync {
            substitutionQueryParams.insert(key)
            os_log("ApproovService: addSubstitutionQueryParam: %@", type: .debug, key)
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
            os_log("ApproovService: removeSubstitutionQueryParam: %@", type: .debug, key)
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
                os_log("ApproovService: addExclusionURLRegex: %@", type: .debug, urlRegex)
            } catch {
                os_log("ApproovService: addExclusionURLRegex: %@ error: %@", type: .debug, urlRegex, error.localizedDescription)
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
                os_log("ApproovService: removeExclusionURLRegex: %@", type: .debug, urlRegex)
            }
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
            if isInitialized {
                Approov.fetchToken({(approovResult: ApproovTokenFetchResult) in
                    ApproovService.setLastARC(result: approovResult)
                    if approovResult.status == ApproovTokenFetchStatus.unknownURL {
                        os_log("ApproovService: prefetch: success", type: .debug)
                    } else {
                        os_log("ApproovService: prefetch: %@", type: .debug, Approov.string(from: approovResult.status))
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
        // try to fetch a non-existent secure string in order to check for a rejection
        let approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", nil)
        ApproovService.setLastARC(result: approovResults)
        if approovResults.status == ApproovTokenFetchStatus.unknownKey {
            os_log("ApproovService: precheck: success", type: .debug)
        } else {
            os_log("ApproovService: precheck: %@", type: .debug, Approov.string(from: approovResults.status))
        }

        // process the returned Approov status
        if approovResults.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "precheck: rejected", ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        } else if approovResults.status == ApproovTokenFetchStatus.noNetwork ||
                  approovResults.status == ApproovTokenFetchStatus.poorNetwork ||
                  approovResults.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "precheck network error: " + Approov.string(from: approovResults.status))
        } else if (approovResults.status != ApproovTokenFetchStatus.success) && (approovResults.status != ApproovTokenFetchStatus.unknownKey) {
            // we are unable to get the secure string due to a more permanent error
            throw ApproovError.permanentError(message: "precheck: " + Approov.string(from: approovResults.status))
        }
    }

    /**
     * Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note
     * that different Approov apps on the same device will return a different ID. Moreover, the ID may be
     * changed by an uninstall and reinstall of the app.
     *
     * @return String of the device ID or nil in case of an error
     */
    public static func getDeviceID() -> String? {
        let deviceID = Approov.getDeviceID()
        if (deviceID != nil) {
            os_log("ApproovService: getDeviceID %@", type: .debug, deviceID!)
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
        os_log("ApproovService: setDataHashInToken", type: .debug)
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
        // fetch the Approov token
        let result: ApproovTokenFetchResult = Approov.fetchTokenAndWait(url)
        ApproovService.setLastARC(result: result)
        os_log("ApproovService: fetchToken: %@", type: .debug, Approov.string(from: result.status))

        // process the status
        switch result.status {
        case .success:
            // provide the Approov token result
            return result.token
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            // we are unable to get an Approov token due to network conditions
            throw ApproovError.networkingError(message: "fetchToken network error: " + Approov.string(from: result.status))
        default:
            // we have failed to get an Approov token due to a more permanent error
            throw ApproovError.permanentError(message: "fetchToken: " + Approov.string(from: result.status))
        }
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
        os_log("ApproovService: getAccountMessageSignature", type: .debug)
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
        os_log("ApproovService: getInstallMessageSignature", type: .debug)
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
        // determine the type of operation as the values themselves cannot be logged
        var type = "lookup"
        if newDef != nil {
            type = "definition"
        }

        // try and fetch the secure string
        let approovResult = Approov.fetchSecureStringAndWait(key, newDef)
        ApproovService.setLastARC(result: approovResult)
        os_log("ApproovService: fetchSecureString: %@: %@", type: .info, type, Approov.string(from: approovResult.status))

        // process the returned Approov status
        if approovResult.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "fetchSecureString: rejected", ARC: approovResult.arc,
                                              rejectionReasons: approovResult.rejectionReasons)
        } else if approovResult.status == ApproovTokenFetchStatus.noNetwork ||
                  approovResult.status == ApproovTokenFetchStatus.poorNetwork ||
                  approovResult.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "fetchSecureString network error: " + Approov.string(from: approovResult.status))
        } else if ((approovResult.status != ApproovTokenFetchStatus.success) && (approovResult.status != ApproovTokenFetchStatus.unknownKey)) {
            // we are unable to get the secure string due to a more permanent error
            throw ApproovError.permanentError(message: "fetchSecureString: " + Approov.string(from: approovResult.status))
        }
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
        // fetch the custom JWT
        let approovResult = Approov.fetchCustomJWTAndWait(payload)
        ApproovService.setLastARC(result: approovResult)
        os_log("ApproovService: fetchCustomJWT: %@", type: .info, Approov.string(from: approovResult.status))

        // process the returned Approov status
        if approovResult.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "fetchCustomJWT: rejected", ARC: approovResult.arc,
                                              rejectionReasons: approovResult.rejectionReasons)
        } else if approovResult.status == ApproovTokenFetchStatus.noNetwork ||
                  approovResult.status == ApproovTokenFetchStatus.poorNetwork ||
                  approovResult.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the custom JWT due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "fetchCustomJWT network error: " + Approov.string(from: approovResult.status))
        } else if (approovResult.status != ApproovTokenFetchStatus.success) {
            // we are unable to get the custom JWT due to a more permanent error
            throw ApproovError.permanentError(message: "fetchCustomJWT: " + Approov.string(from: approovResult.status))
        }
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
    static func updateRequestWithApproov(request: URLRequest) -> ApproovUpdateResponse {
        // check if the SDK is not initialized or if the URL matches one of the exclusion regexs and just return if it does
        var changes = ApproovRequestMutations()
        if let url = request.url {
            if !isInitialized {
                os_log("ApproovService: not initialized, forwarding: %@", type: .info, url.absoluteString)
                return ApproovUpdateResponse(request: request, decision: .ShouldIgnore, sdkMessage: "", error: nil)
            }
            if isURLExcluded(url: url) {
                os_log("ApproovService: excluded, forwarding: %@", type: .info, url.absoluteString)
                return ApproovUpdateResponse(request: request, decision: .ShouldIgnore, sdkMessage: "", error: nil)
            }
        } else {
            os_log("ApproovService: no url provided", type: .info)
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
        ApproovService.setLastARC(result: approovResult)
        let hostname = hostnameFromURL(url: request.url!)
        os_log("ApproovService: updateRequest %@: %@", type: .info, hostname, approovResult.loggableToken())

        // log if a configuration update is received and call fetchConfig to clear the update state
        if approovResult.isConfigChanged {
            Approov.fetchConfig()
            os_log("ApproovService: dynamic configuration update received")
        }

        // handle the Approov token fetch response
        response.sdkMessage = Approov.string(from: approovResult.status)
        var hasChanges = false
        var setTokenHeaderKey: String?
        var setTokenHeaderValue: String?
        // All paths through this switch statement must set response.decision
        switch approovResult.status {
        case ApproovTokenFetchStatus.success:
            // go ahead and make the API call and add the Approov token header
            response.decision = .ShouldProceed
            let tokenHeader = stateQueue.sync {
                return approovTokenHeader
            }
            let tokenPrefix = stateQueue.sync {
                return approovTokenPrefix
            }
            hasChanges = true
            setTokenHeaderKey = tokenHeader
            setTokenHeaderValue = tokenPrefix + approovResult.token
        case ApproovTokenFetchStatus.noNetwork,
            ApproovTokenFetchStatus.poorNetwork,
            ApproovTokenFetchStatus.mitmDetected:
            // we are unable to get the Approov token due to network conditions
            if !proceedOnNetworkFail {
                // unless required to proceed; the request can be retried by the user later
                response.decision = .ShouldRetry
                response.error = ApproovError.networkingError(message: response.sdkMessage)
                return response
            }
            // otherwise, proceed with the request but without the Approov token header
            response.decision = .ShouldProceed
        case ApproovTokenFetchStatus.unprotectedURL,
            ApproovTokenFetchStatus.unknownURL,
            ApproovTokenFetchStatus.noApproovService:
            // we proceed but do NOT add the Approov token header to the request headers
            response.decision = .ShouldProceed
        default:
            // we have a more permanent error condition
            response.decision = .ShouldFail
            response.error = ApproovError.permanentError(message: response.sdkMessage)
            return response
        }

        // we only continue additional processing if we had a valid status from Approov, to prevent additional delays
        // by trying to fetch from Approov again and this also protects against header substitutions in domains not
        // protected by Approov and therefore are potentially subject to a MitM.
        if (approovResult.status != .success) && (approovResult.status != .unprotectedURL) {
            return response
        }

        // we now deal with any headers substitutions, which may require further fetches but these
        // should be using cached results
        var setSubstitutionHeaders: [String: String] = [:]
        if let requestHeaders = response.request.allHTTPHeaderFields {
            let subsHeadersCopy = stateQueue.sync {
                return substitutionHeaders
            }
            for (header, prefix) in subsHeadersCopy {
                if let value = requestHeaders[header] {
                    // check if the request contains the header we want to replace
                    if ((value.hasPrefix(prefix)) && (value.count > prefix.count)) {
                        // fetch any secure string keyed from the current value, without any prefix
                        let index = prefix.index(prefix.startIndex, offsetBy: prefix.count)
                        let approovResults = Approov.fetchSecureStringAndWait(String(value.suffix(from:index)), nil)
                        ApproovService.setLastARC(result: approovResults)
                        os_log("ApproovService: Substituting header: %@, %@", type: .info, header, Approov.string(from: approovResults.status))

                        // process the result of the token fetch operation
                        if approovResults.status == ApproovTokenFetchStatus.success {
                            // we add the modified header to the new copy of request
                            if let secureStringResult = approovResults.secureString {
                                hasChanges = true;
                                setSubstitutionHeaders[header] = prefix + secureStringResult
                            } else {
                                // secure string is nil
                                response.decision = .ShouldFail
                                response.error = ApproovError.permanentError(message: "Header substitution: key lookup error")
                                return response
                            }
                        } else if approovResults.status == ApproovTokenFetchStatus.rejected {
                            // if the request is rejected then we provide a special exception with additional information
                            response.decision = .ShouldFail
                            response.error = ApproovError.rejectionError(message: "Header substitution: rejected",
                                                                         ARC: approovResults.arc,
                                                                         rejectionReasons: approovResults.rejectionReasons)
                            return response
                        } else if approovResults.status == ApproovTokenFetchStatus.noNetwork ||
                                  approovResults.status == ApproovTokenFetchStatus.poorNetwork ||
                                  approovResults.status == ApproovTokenFetchStatus.mitmDetected {
                            // we are unable to get the secure string due to network conditions so the request can
                            // be retried by the user later
                            if !proceedOnNetworkFail {
                                response.decision = .ShouldRetry
                                response.error = ApproovError.networkingError(message: "Header substitution: network issue, retry needed")
                                return response
                            }
                        } else if approovResults.status != ApproovTokenFetchStatus.unknownKey {
                            // we have failed to get a secure string with a more serious permanent error
                            response.decision = .ShouldFail
                            response.error = ApproovError.permanentError(message: "Header substitution: " + Approov.string(from: approovResults.status))
                            return response
                        }
                    }
                }
            }
        }

        // we now deal with any query parameter substitutions, which may require further fetches but these
        // should be using cached results
        var updateURL: URL?
        var queryKeys: [String] = []
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
                            ApproovService.setLastARC(result: approovResults)
                            os_log("ApproovService: Substituting query parameter: %@, %@", entry,
                                Approov.string(from: approovResults.status))

                            // process the result of the secure string fetch operation
                            switch approovResults.status {
                            case .success:
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
                            case .rejected:
                                // if the request is rejected then we provide a special exception with additional information
                                response.decision = .ShouldFail
                                response.error = ApproovError.rejectionError(
                                    message: "Query parameter substitution for \(entry) rejected",
                                    ARC: approovResults.arc,
                                    rejectionReasons: approovResults.rejectionReasons
                                )
                                return response
                            case .noNetwork,
                                    .poorNetwork,
                                    .mitmDetected:
                                // we are unable to get the secure string due to network conditions so the request can
                                // be retried by the user later
                                if !proceedOnNetworkFail {
                                    response.decision = .ShouldRetry
                                    response.error = ApproovError.networkingError(message: "Query parameter substitution for " +
                                        "\(entry): network issue, retry needed")
                                    return response
                                }
                            case .unknownKey:
                                // do not modify the URL
                                break
                            default:
                                // we have failed to get a secure string with a more permanent error
                                response.decision = .ShouldFail
                                response.error = ApproovError.permanentError(
                                    message: "Query parameter substitution for \(entry): " +
                                    Approov.string(from: approovResults.status)
                                )
                                return response
                            }
                        }
                    }
                }
            }
        }
        // apply all the changes to the request
        if (hasChanges) {
            if let tokenHeaderKey = setTokenHeaderKey,
               let tokenHeaderValue = setTokenHeaderValue {
                response.request.setValue(tokenHeaderValue, forHTTPHeaderField: tokenHeaderKey)
                changes.setTokenHeaderKey(tokenHeaderKey);
            }
            if (!setSubstitutionHeaders.isEmpty) {
                for (header, value) in setSubstitutionHeaders {
                    response.request.setValue(value, forHTTPHeaderField: header)
                }
                changes.setSubstitutionHeaderKeys(Array(setSubstitutionHeaders.keys))
            }
            if let updateURLString = updateURL?.absoluteString,
               let originalURLString = request.url?.absoluteString {
                if (originalURLString != updateURLString) {
                    response.request.url = updateURL
                    changes.setSubstitutionQueryParamResults(originalURL: originalURLString, substitutionQueryParamKeys: queryKeys);
                }
            }
        }

        // call the processed request callback
        if let interceptorExtensions = ApproovService.interceptorExtensions {
            do {
                response.request = try interceptorExtensions.processedRequest(response.request, changes: changes)
            } catch let error {
                response.decision = .ShouldFail
                response.error = ApproovError.permanentError(
                    message: "Interceptor extension for processed request error: \(error.localizedDescription)")
            }
        }

        return response
    }
}
