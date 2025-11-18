// MIT License
//
// Copyright (c) 2025-present, Approov Ltd.
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

/**
 * ApproovRequestMutations stores information about changes made to a network request
 * during Approov processing, such as token headers, substituted headers, and query parameters.
 */
public class ApproovRequestMutations {
    private var tokenHeaderKey: String?
    private var traceIDHeaderKey: String?
    private var substitutionHeaderKeys: [String] = []
    private var originalURL: String?
    private var substitutionQueryParamKeys: [String] = []

    /**
     * Gets the header key used for the Approov token.
     *
     * - Returns: The Approov token header key.
     */
    func getTokenHeaderKey() -> String? {
        return tokenHeaderKey
    }

    /**
     * Sets the header key used for the Approov token.
     *
     * - Parameter tokenHeaderKey: The Approov token header key.
     */
    func setTokenHeaderKey(_ tokenHeaderKey: String) {
        self.tokenHeaderKey = tokenHeaderKey
    }

    /**
     * Gets the header key used for the optional Approov TraceID debug header.
     *
     * - Returns: The Approov TraceID header key, or nil if the header was not added.
     */
    func getTraceIDHeaderKey() -> String? {
        return traceIDHeaderKey
    }

    /**
     * Sets the header key used for the optional Approov TraceID debug header.
     *
     * - Parameter traceIDHeaderKey: The Approov TraceID header key.
     */
    func setTraceIDHeaderKey(_ traceIDHeaderKey: String?) {
        self.traceIDHeaderKey = traceIDHeaderKey
    }

    /**
     * Gets the list of headers that were substituted with secure strings.
     *
     * - Returns: The list of substituted header keys.
     */
    func getSubstitutionHeaderKeys() -> [String] {
        return substitutionHeaderKeys
    }

    /**
     * Sets the list of headers that were substituted with secure strings.
     *
     * - Parameter substitutionHeaderKeys: The list of substituted header keys.
     */
    func setSubstitutionHeaderKeys(_ substitutionHeaderKeys: [String]) {
        self.substitutionHeaderKeys = substitutionHeaderKeys
    }

    /**
     * Gets the original URL before any query parameter substitutions.
     *
     * - Returns: The original URL.
     */
    func getOriginalURL() -> String? {
        return originalURL
    }

    /**
     * Gets the list of query parameter keys that were substituted with secure strings.
     *
     * - Returns: The list of substituted query parameter keys.
     */
    func getSubstitutionQueryParamKeys() -> [String] {
        return substitutionQueryParamKeys
    }

    /**
     * Sets the results of query parameter substitutions, including the original URL and the keys of substituted parameters.
     *
     * - Parameters:
     *   - originalURL: The original URL before substitutions.
     *   - substitutionQueryParamKeys: The list of substituted query parameter keys.
     */
    func setSubstitutionQueryParamResults(originalURL: String, substitutionQueryParamKeys: [String]) {
        self.originalURL = originalURL
        self.substitutionQueryParamKeys = substitutionQueryParamKeys
    }
}
