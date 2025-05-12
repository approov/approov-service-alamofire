# Approov Service for Alamofire 

A wrapper for the [Approov SDK](https://github.com/approov/approov-ios-sdk) to enable easy integration when using [`Alamofire`](https://github.com/Alamofire/Alamofire) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

Please see the [Quickstart](https://github.com/approov/quickstart-ios-swift-alamofire) for usage instructions.

## Included 3rd party Source

To support message signing, this repo has adapted code released by a 3rd party developer. The LICENSE file has been copied from the repo into the associated directory listed below:

`approov-service-alamofire/Sources/ApproovSession/util/sig`

* Repo: https://github.com/bspk/httpsig-java
* Commit hash: ffe86ae1d07425f13b018329f51c7a7c0833d71f
* License: MIT
