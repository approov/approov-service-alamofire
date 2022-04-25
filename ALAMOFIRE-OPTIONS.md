
### Network Retry Options
The `ApproovInterceptor` class implements Alamofire's Interceptor protocol which includes an option to invoke a retry attempt in case the original request failed. We do not implement the retry option in `ApproovInterceptor`, but if you require implementing one, you should mimic the contents of the `adapt()` function and perhaps add some logic regarding retry attempts. See an example [here](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#adapting-and-retrying-requests-with-requestinterceptor).

### ApproovTrustManager
The `ApproovSession` object handles internally the creation of a default `AproovTrustManager`, if one is not provided during initialization. The `AproovTrustManager` then sets the mapping between hosts and evaluators internally. If you wish to use different evaluators for hosts not protected by Approov, you can initialize the `ApproovTrustManager` like so:

```swift
        let evaluators: [String: ServerTrustEvaluating] = [
            "some.other.host.com": RevocationTrustEvaluator(),
            "another.host": PinnedCertificatesTrustEvaluator()
        ]

        let manager = ApproovTrustManager(evaluators: evaluators)
        session = ApproovSession(serverTrustManager: manager)
```

Please note that you do not have to specify the hosts that need to be protected by Approov, they are automatically set for you once a configuration has been fetched from the Approov servers. You can manage (adding and removing) Approov protected domains using the approov [admin tools](https://approov.io/docs/latest/approov-cli-tool-reference/).
By default, the `ApproovTrustManager` verifies all the hosts protected by Approov and any optional hosts provided a mapping to an evaluator has been provided as in the above code snippet. This means that any request to an additional host not known to the Approov SDK nor the `ApproovTrustManager`, lets say `https://approov.io`, will not be evaluated by Alamofire and it will not be protected by Approov. As long as the certificate presented by that host is valid, the connection will most likely go through. If you wish to change this behaviour, you may modify how the `ApproovTrustManager` is initialized in the above code:

```swift
        let evaluators: [String: ServerTrustEvaluating] = [
            "some.other.host.com": RevocationTrustEvaluator(),
            "another.host": PinnedCertificatesTrustEvaluator()
        ]

        let manager = ApproovTrustManager(allHostsMustBeEvaluated: true, evaluators: evaluators)
        session = ApproovSession(serverTrustManager: manager)
```

The `allHostsMustBeEvaluated: true` parameter will evaluate `some.other.host.com` and `another.host` according to the evaluators specified above. The Approov SDK will verify the public key pinning of all the hosts specified using the [admin tools](https://approov.io/docs/latest/approov-cli-tool-reference/) but any connections to additional hosts will be rejected.

### Redirection
If any of the hosts you are protecting with Approov redirects requests to a different host, depending on the `allHostsMustBeEvaluated` option used and described above, you might need to protect both hosts with Approov and/or an evaluator as in the code example above, otherwise the original request might get evaluated and after a redirect is triggered, the target host connection is rejected.

### Alamofire Request
If your code makes use of the default Alamofire Session, like so:

```swift
    AF.request("https://httpbin.org/get").response { response in
        debugPrint(response)
    }
```

all you will need to do to use Approov is to replace the default Session object with the ApproovSession:

```swift
    let approovSession = ApproovSession()
    approovSession!.request("https://httpbin.org/get").responseData{ response in
            debugPrint(response)
    }
```

### Network Delegate

Unfortunately we do not support network delegates in Alamofire. If you wish to use a network delegate and do not mind using apple's URLSession interface, we can offer an `ApproovURLSession` integration that does support network delegates.

Please follow the [Quickstart](https://github.com/approov/quickstart-ios-swift-alamofire) for instructions on usage.
