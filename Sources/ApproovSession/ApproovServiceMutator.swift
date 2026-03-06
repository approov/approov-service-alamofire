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

import Approov
import Foundation

/**
 * ApproovServiceMutator provides an interface for modifying the behavior of
 * the ApproovService class by overriding the default implementations of the
 * defined callbacks. Opportunities to modify behavior are offered at key
 * points in the service and attestation flows.
 *
 * The protocol provides default implementations for all methods, so
 * implementing classes can choose to override only the methods they are
 * interested in. The default implementations provide standard behavior
 * that is suitable for most use cases and provides backwards compatibility
 * with previous versions of this Approov service layer.
 */
public protocol ApproovServiceMutator {
    /**
     * Decides how to handle the token fetch result from an
     * ApproovService.precheck() operation.
     */
    func handlePrecheckResult(_ approovResults: ApproovTokenFetchResult) throws

    /**
     * Decides how to handle the token fetch result from an
     * ApproovService.fetchToken() operation.
     */
    func handleFetchTokenResult(_ approovResults: ApproovTokenFetchResult) throws

    /**
     * Decides how to handle the token fetch result from an
     * ApproovService.fetchSecureString() operation.
     */
    func handleFetchSecureStringResult(_ approovResults: ApproovTokenFetchResult,
                                       operation: String,
                                       key: String) throws

    /**
     * Decides how to handle the token fetch result from an
     * ApproovService.fetchCustomJWT() operation.
     */
    func handleFetchCustomJWTResult(_ approovResults: ApproovTokenFetchResult) throws

    /**
     * Decides whether a request should be processed in the interceptor or not.
     * Called at the start of the ApproovService interceptor processing.
     */
    func handleInterceptorShouldProcessRequest(_ request: URLRequest) throws -> Bool

    /**
     * Decides how to handle the token fetch result from a call to
     * Approov.fetchTokenAndWait() from within the interceptor.
     */
    func handleInterceptorFetchTokenResult(_ approovResults: ApproovTokenFetchResult,
                                           url: String) throws -> Bool

    /**
     * Decides how to handle the token fetch result while substituting headers
     * from within the interceptor.
     */
    func handleInterceptorHeaderSubstitutionResult(_ approovResults: ApproovTokenFetchResult,
                                                   header: String) throws -> Bool

    /**
     * Decides how to handle the token fetch result while substituting query params
     * from within the interceptor.
     */
    func handleInterceptorQueryParamSubstitutionResult(_ approovResults: ApproovTokenFetchResult,
                                                       queryKey: String) throws -> Bool

    /**
     * Called after Approov has processed a network request, allowing further
     * modifications.
     */
    func handleInterceptorProcessedRequest(_ request: URLRequest,
                                           changes: ApproovRequestMutations) throws -> URLRequest

    /**
     * Decides whether certificate pinning should be applied to a request or not.
     * Called at the start of the ApproovService pinning processing.
     */
    func handlePinningShouldProcessRequest(_ request: URLRequest) -> Bool
}

public extension ApproovServiceMutator {
    func handlePrecheckResult(_ approovResults: ApproovTokenFetchResult) throws {
        let status = approovResults.status
        switch status {
        case .rejected:
            throw ApproovError.rejectionError(message: "precheck: rejected",
                                              ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            throw ApproovError.networkingError(message: "precheck network error: " + Approov.string(from: status))
        case .success,
             .unknownKey:
            return
        default:
            throw ApproovError.permanentError(message: "precheck: " + Approov.string(from: status))
        }
    }

    func handleFetchTokenResult(_ approovResults: ApproovTokenFetchResult) throws {
        let status = approovResults.status
        switch status {
        case .success:
            return
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            throw ApproovError.networkingError(message: "fetchToken network error: " + Approov.string(from: status))
        default:
            throw ApproovError.permanentError(message: "fetchToken: " + Approov.string(from: status))
        }
    }

    func handleFetchSecureStringResult(_ approovResults: ApproovTokenFetchResult,
                                       operation: String,
                                       key: String) throws {
        let status = approovResults.status
        switch status {
        case .rejected:
            throw ApproovError.rejectionError(message: "fetchSecureString \(operation) for \(key): rejected",
                                              ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            throw ApproovError.networkingError(message: "fetchSecureString \(operation) for \(key): " +
                                               Approov.string(from: status))
        case .success,
             .unknownKey:
            return
        default:
            throw ApproovError.permanentError(message: "fetchSecureString \(operation) for \(key): " +
                                              Approov.string(from: status))
        }
    }

    func handleFetchCustomJWTResult(_ approovResults: ApproovTokenFetchResult) throws {
        let status = approovResults.status
        switch status {
        case .rejected:
            throw ApproovError.rejectionError(message: "fetchCustomJWT: rejected",
                                              ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            throw ApproovError.networkingError(message: "fetchCustomJWT network error: " + Approov.string(from: status))
        case .success:
            return
        default:
            throw ApproovError.permanentError(message: "fetchCustomJWT: " + Approov.string(from: status))
        }
    }

    func handleInterceptorShouldProcessRequest(_ request: URLRequest) throws -> Bool {
        guard let url = request.url else {
            throw ApproovError.permanentError(message: "handleInterceptorShouldProcessRequest received a request with no URL")
        }
        let urlString = url.absoluteString
        let urlStringRange = NSRange(urlString.startIndex..<urlString.endIndex, in: urlString)
        for (_, regex) in ApproovService.getExclusionURLRegexs() {
            if regex.firstMatch(in: urlString, options: [], range: urlStringRange) != nil {
                return false
            }
        }
        return true
    }

    func handleInterceptorFetchTokenResult(_ approovResults: ApproovTokenFetchResult,
                                           url: String) throws -> Bool {
        let status = approovResults.status
        switch status {
        case .success:
            return true
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            return false
        case .noApproovService,
             .unknownURL,
             .unprotectedURL:
            return false
        default:
            throw ApproovError.permanentError(message: "Approov token fetch for \(url): " +
                                              Approov.string(from: status))
        }
    }

    func handleInterceptorHeaderSubstitutionResult(_ approovResults: ApproovTokenFetchResult,
                                                   header: String) throws -> Bool {
        let status = approovResults.status
        switch status {
        case .success:
            return true
        case .rejected:
            throw ApproovError.rejectionError(message: "Header substitution for \(header): rejected",
                                              ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            return false
        case .unknownKey:
            return false
        default:
            throw ApproovError.permanentError(message: "Header substitution for \(header): " +
                                              Approov.string(from: status))
        }
    }

    func handleInterceptorQueryParamSubstitutionResult(_ approovResults: ApproovTokenFetchResult,
                                                       queryKey: String) throws -> Bool {
        let status = approovResults.status
        switch status {
        case .success:
            return true
        case .rejected:
            throw ApproovError.rejectionError(message: "Query parameter substitution for \(queryKey): rejected",
                                              ARC: approovResults.arc,
                                              rejectionReasons: approovResults.rejectionReasons)
        case .noNetwork,
             .poorNetwork,
             .mitmDetected:
            return false
        case .unknownKey:
            return false
        default:
            throw ApproovError.permanentError(message: "Query parameter substitution for \(queryKey): " +
                                              Approov.string(from: status))
        }
    }

    func handleInterceptorProcessedRequest(_ request: URLRequest,
                                           changes: ApproovRequestMutations) throws -> URLRequest {
        return request
    }

    func handlePinningShouldProcessRequest(_ request: URLRequest) -> Bool {
        return true
    }
}

public struct ApproovServiceMutatorDefault: ApproovServiceMutator, CustomStringConvertible {
    public static let shared = ApproovServiceMutatorDefault()

    public var description: String {
        return "ApproovServiceMutator.DEFAULT"
    }

    private init() {}
}
