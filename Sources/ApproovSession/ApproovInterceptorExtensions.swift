import Foundation

/**
 * ApproovInterceptorExtensions provides an interface for handling callbacks during
 * the processing of network requests by Approov. It allows further modifications
 * to requests after Approov has applied its changes.
 */
public protocol ApproovInterceptorExtensions {

    /**
     * Called after Approov has processed a network request, allowing further modifications.
     *
     * - Parameters:
     *   - request: The processed request.
     *   - changes: The mutations applied to the request by Approov.
     * - Returns: The modified request.
     * - Throws: An `ApproovException` if there is an error during processing.
     */
    func processedRequest(_ request: URLRequest, changes: ApproovRequestMutations) throws -> URLRequest
}
