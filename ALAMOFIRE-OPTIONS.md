
# AlamoFire Options
This provides some other options available with the AlamoFire networking stack.

## Network Retry Options
The `ApproovInterceptor` class implements Alamofire's Interceptor protocol which includes an option to invoke a retry attempt in case the original request failed. We do not implement the retry option in `ApproovInterceptor`, but if you require implementing one, you should mimic the contents of the `adapt()` function and perhaps add some logic regarding retry attempts. See an example [here](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#adapting-and-retrying-requests-with-requestinterceptor).

## Trust Manager
The `ApproovSession` object internally handles the creation of a default `AproovTrustManager` that handles dynamic pinning. You may set your own `ServerTrustManager` during construction like so:

```swift
let session = ApproovSession(serverTrustManager: manager)
```
However, if you do this then Approov dynamic pinning WILL NOT be applied.

An alternative is to use the `ApproovTrustManager` along with your own `ServerTrustEvaluating` implementations as follows:

```swift
let evaluators: [String: ServerTrustEvaluating] = [
    "some.other.host.com": RevocationTrustEvaluator(),
    "another.host": PinnedCertificatesTrustEvaluator()
]
let manager = ApproovTrustManager(allHostsMustBeEvaluated: true, evaluators: evaluators)
let session = ApproovSession(serverTrustManager: manager)
```

This approach will use the Approov dynamic pinning for all hosts that are being [mangaged](https://approov.io/docs/latest/approov-usage-documentation/#managing-api-domains) by Approov. Other host names will be passed to your custom evaluators. If you specify an evaluator that is also managed by Approov, then Approov will take precedence.

### Alamofire Request
If your code makes use of the default Alamofire `Session`, like so:

```swift
AF.request("https://httpbin.org/get").response { response in
    debugPrint(response)
}
```

all you will need to do to use Approov is to replace the default `Session` object with the `ApproovSession`:

```swift
let approovSession = ApproovSession()
approovSession!.request("https://httpbin.org/get").responseData { response in
    debugPrint(response)
}
```

## Network Delegate
You may specify your own network delegate when the `ApproovSession` is constructed as follows:

```swift
let session = ApproovSession(delegate: delegate)
```
