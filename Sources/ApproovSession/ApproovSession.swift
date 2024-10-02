// MIT License
//
// Copyright (c) 2016-present, Critical Blue Ltd.
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
import CommonCrypto
import OSLog
import Alamofire
import Approov

/**
 * Intercepts AlamoFire network requests and adds Approov protection.
 *
 * See https://alamofire.github.io/Alamofire/Protocols/RequestInterceptor.html
 */
private class ApproovInterceptor: RequestInterceptor {
    /**
     * Alamofire interceptor protocol
     * https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#adapting-and-retrying-requests-with-requestinterceptor
     */
    public func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        let ApproovUpdateResponse = ApproovService.updateRequestWithApproov(request: urlRequest)
        if (ApproovUpdateResponse.decision == .ShouldProceed) || (ApproovUpdateResponse.decision == .ShouldIgnore) {
            completion(.success(ApproovUpdateResponse.request))
        } else {
            completion(.failure(ApproovUpdateResponse.error!))
        }
    }
}

/**
 * Custom AlamoFire Session implementation that adds Approov protection and dynamic pinning/
 *
 * Alamofire Session class: https://alamofire.github.io/Alamofire/Classes/Session.html
 */
public class ApproovSession: Session {
    public init?(
                configuration: URLSessionConfiguration = URLSessionConfiguration.af.default,
                rootQueue: DispatchQueue = DispatchQueue(label: "approov.service.alamofire.rootQueue"),
                startRequestsImmediately: Bool = true,
                delegate: SessionDelegate? = nil,
                requestQueue: DispatchQueue? = nil,
                serializationQueue: DispatchQueue? = nil,
                interceptor: Interceptor? = nil,
                serverTrustManager: ApproovTrustManager? = nil,
                redirectHandler: RedirectHandler? = nil,
                cachedResponseHandler: CachedResponseHandler? = nil,
                eventMonitors: [EventMonitor] = []) {
        
        var localInterceptor: RequestInterceptor?
        // Create approov interceptor
        let approovInterceptor = ApproovInterceptor()
        if let interceptorWrapper = interceptor {
            // Append the Approov interceptor to the list of adaptors
            let interceptors : [RequestInterceptor] = [approovInterceptor]
            localInterceptor = Interceptor(adapters: interceptorWrapper.adapters, retriers: interceptorWrapper.retriers, interceptors: interceptors)
        } else {
            // If no interceptor is provided, create a new one with the Approov interceptor
            localInterceptor = approovInterceptor
        }
        
        // use any user supplied trust manager - note that this means that Approov pinning
        // will be disabled if so, unless the ApproovTrustManager is used
        var trustManager: ApproovTrustManager?
        if serverTrustManager == nil {
            trustManager = ApproovTrustManager(evaluators: [:])
        } else {
            trustManager = serverTrustManager
        }
        
        // use any user supplied delegate
        var sessionDelegate = delegate
        if (sessionDelegate == nil) {
            sessionDelegate = SessionDelegate()
        }
        
        // we always provide a delegate queue
        let delegateQueue = OperationQueue()
        delegateQueue.underlyingQueue = rootQueue
        delegateQueue.name = "approov.service.alamofire.ApproovSessionQueue"
        delegateQueue.maxConcurrentOperationCount = 1
                    
        // construct the Approov specialized session
        let session = URLSession(configuration: configuration, delegate: sessionDelegate, delegateQueue: delegateQueue)
        super.init(session: session,
                   delegate: sessionDelegate!,
                   rootQueue: rootQueue,
                   startRequestsImmediately: startRequestsImmediately,
                   requestQueue: requestQueue,
                   serializationQueue: serializationQueue,
                   interceptor: localInterceptor,
                   serverTrustManager: trustManager,
                   redirectHandler: redirectHandler,
                   cachedResponseHandler: cachedResponseHandler,
                   eventMonitors: eventMonitors)
    }
}
