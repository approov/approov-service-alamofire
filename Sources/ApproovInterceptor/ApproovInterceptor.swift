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
import Alamofire
import Approov


fileprivate struct ApproovData {
    var request:URLRequest
    var decision:ApproovTokenNetworkFetchDecision
    var statusMessage:String
    var error:Error?
}
fileprivate enum ApproovTokenNetworkFetchDecision {
    case ShouldProceed
    case ShouldRetry
    case ShouldFail
}

public final class ApproovTrustEvaluator: ServerTrustEvaluating {
    /* Pin type used in Approov */
    let pinType = "public-key-sha256"
    struct Constants {
        static let rsa2048SPKIHeader:[UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
        static let rsa4096SPKIHeader:[UInt8]  = [
            0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
        ]
        static let ecdsaSecp256r1SPKIHeader:[UInt8]  = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]
        static let ecdsaSecp384r1SPKIHeader:[UInt8]  = [
            0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
            0x00, 0x22, 0x03, 0x62, 0x00
        ]
    }
    // PKI headers for both RSA and ECC
    private static var pkiHeaders = [String:[Int:Data]]()
    /*
     *  Initialize PKI dictionary
     */
    private static func initializePKI() {
        var rsaDict = [Int:Data]()
        rsaDict[2048] = Data(Constants.rsa2048SPKIHeader)
        rsaDict[4096] = Data(Constants.rsa4096SPKIHeader)
        var eccDict = [Int:Data]()
        eccDict[256] = Data(Constants.ecdsaSecp256r1SPKIHeader)
        eccDict[384] = Data(Constants.ecdsaSecp384r1SPKIHeader)
        pkiHeaders[kSecAttrKeyTypeRSA as String] = rsaDict
        pkiHeaders[kSecAttrKeyTypeECSECPrimeRandom as String] = eccDict
    }
    
    init(){
        ApproovTrustEvaluator.initializePKI()
    }
    
    /* ServerTrustEvaluating protocol
     *  https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#evaluating-server-trusts-with-servertrustmanager-and-servertrustevaluating
     */
    public func evaluate(_ trust: SecTrust, forHost host: String) throws {
        
        // check that the hash is the same as at least one of the pins
        guard let approovCertHashes = Approov.getPins(pinType) else {
            throw AFError.serverTrustEvaluationFailed(reason: AFError.ServerTrustFailureReason.noPublicKeysFound)
        }
        
        let pinnedKeysInServerKeys: Bool  = try {
            if let certHashList = approovCertHashes[host] {
                // If the cet has list is empty, it means anything presented to us is valid
                if certHashList.count == 0 {
                    return true
                }
                // We have one or more cert hashes matching the receivers host, compare them
                for serverPublicKey in trust.af.publicKeys {
                    do {
                        let spki = try getSPKIHeader(publicKey: serverPublicKey)
                        let publicKeyHash = sha256(data: spki)
                        let publicKeyHashBase64 = String(data:publicKeyHash.base64EncodedData(), encoding: .utf8)
                        for certHash in certHashList {
                            if publicKeyHashBase64 == certHash {
                                return true
                            }
                        }
                    } catch let error {
                        // Throw to indicate we could not parse SPKI header
                        throw error
                    }
                    
                }
            }
            return false
        }()
        // Throw error if pinned keys do not match current server key
       if !pinnedKeysInServerKeys {
        throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: ApproovError.runtimeError(message: "Approov: Public key for host \(host) does not match any pinned keys in Approov SDK")))
        }
    }
    
    /* Utility */
    func getSPKIHeader(publicKey: SecKey) throws -> Data {
        // get the SPKI header depending on the public key's type and size
        do {
            var spkiHeader = try publicKeyInfoHeaderForKey(publicKey: publicKey)
            // combine the public key header and the public key data to form the public key info
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
                throw ApproovError.runtimeError(message: "Error parsing SPKI header: SecKeyCopyExternalRepresentation key is not exportable")
            }
            spkiHeader.append(publicKeyData as Data)
            return spkiHeader
        } catch let error {
            throw error
        }
    }
    
    /*  SHA256 of given input bytes
     *
     */
    func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    /*
   * gets the subject public key info (SPKI) header depending on a public key's type and size
   */
   func publicKeyInfoHeaderForKey(publicKey: SecKey) throws -> Data {
       guard let publicKeyAttributes = SecKeyCopyAttributes(publicKey) else {
           throw ApproovError.runtimeError(message: "Error parsing SPKI header: SecKeyCopyAttributes failure getting key attributes")
       }
       if let keyType = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeyType as String) {
           if let keyLength = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeySizeInBits as String) {
               // Find the header
               if let spkiHeader:Data = ApproovTrustEvaluator.pkiHeaders[keyType as! String]?[keyLength as! Int] {
                   return spkiHeader
               }
           }
       }
       throw ApproovError.runtimeError(message: "Error parsing SPKI header: unsupported key length or unsupported key type")
   }
}

/*  See https://alamofire.github.io/Alamofire/Classes/ServerTrustManager.html
 *
 */

public class ApproovTrustManager: ServerTrustManager {
    /* Pin type used in Approov */
    let pinType = "public-key-sha256"
    public override init(allHostsMustBeEvaluated: Bool = false, evaluators: [String:ServerTrustEvaluating]?) {
        if evaluators != nil {
            super.init(allHostsMustBeEvaluated: allHostsMustBeEvaluated, evaluators: evaluators!)
        } else {
            super.init(allHostsMustBeEvaluated: allHostsMustBeEvaluated, evaluators: [:])
        }
    }
    
    public override func serverTrustEvaluator(forHost host: String) throws -> ServerTrustEvaluating? {
        if let approovCertHashes = Approov.getPins(pinType){
            let allHosts = approovCertHashes.keys
            /* Get protected api hosts from current configration and check if `host` should be protected
             * Note that is also possible to have defined a host but not set any pins, in which case
             * we treat the host as not protected by Approov and we forward the trust evaluation
             */
            if allHosts.contains(host) {
                // Check if host has at least one set of pins
                if approovCertHashes[host]!.count > 0 {
                    return ApproovTrustEvaluator()
                }
            }
        }
        
        return try super.serverTrustEvaluator(forHost: host)
    }
}

/*  See https://alamofire.github.io/Alamofire/Protocols/RequestInterceptor.html
 *
 */
final class ApproovInterceptor:  RequestInterceptor {
    /* Dynamic configuration string key in user default database */
    public static let kApproovDynamicKey = "approov-dynamic"
    /* Initial configuration string/filename for Approov SDK */
    public static let kApproovInitialKey = "approov-initial"
    /* Initial configuration file extention for Approov SDK */
    public static let kConfigFileExtension = "config"
    /* Status of Approov SDK initialisation */
    private static var approovSDKInitialised = false
    
    init?(prefetchToken: Bool = false, config: String? = nil){
        if !ApproovInterceptor.approovSDKInitialised {
            var configString = config
            // Read initial config file ONLY if short config not provided
            if configString == nil {
                /* Read initial config */
                do {
                    configString = try readInitialApproovConfig()
                } catch let error {
                    debugPrint(error.localizedDescription)
                    return nil
                }
            }
            /* Read dynamic config */
            if configString != nil {
                /* Read dynamic config  */
                let dynamicConfigString = readDynamicApproovConfig()
                /* Initialise Approov SDK */
                do {
                    try Approov.initialize(configString!, updateConfig: dynamicConfigString, comment: nil)
                    ApproovInterceptor.approovSDKInitialised = true
                    /* Save updated SDK config if this is the first ever app launch */
                    if dynamicConfigString == nil {
                        storeDynamicConfig(newConfig: Approov.fetchConfig()!)
                    }
                    if prefetchToken {
                        prefetchApproovToken()
                    }
                } catch let error {
                    debugPrint("Approov: Error initializing Approov SDK: \(error.localizedDescription)")
                    return nil
                }
            } else {
                debugPrint("Approov: FATAL Unable to initialize Approov SDK")
                return nil
            }
        }
    }
    
    // Dispatch queue to manage concurrent access to bindHeader variable
    private static let bindHeaderQueue = DispatchQueue(label: "ApproovSDK.bindHeader", qos: .default, attributes: .concurrent, autoreleaseFrequency: .never, target: DispatchQueue.global())
    private static var _bindHeader = ""
    // Bind Header string
    public static var bindHeader: String {
        get {
            var bindHeader = ""
            bindHeaderQueue.sync {
                bindHeader = _bindHeader
            }
            return bindHeader
        }
        set {
            bindHeaderQueue.async(group: nil, qos: .default, flags: .barrier, execute: {self._bindHeader = newValue})
        }
    }

    // Dispatch queue to manage concurrent access to approovTokenHeader variable
    private static let approovTokenHeaderAndPrefixQueue = DispatchQueue(label: "ApproovSDK.approovTokenHeader", qos: .default, attributes: .concurrent, autoreleaseFrequency: .never, target: DispatchQueue.global())
    /* Approov token default header */
    private static var _approovTokenHeader = "Approov-Token"
    /* Approov token custom prefix: any prefix to be added such as "Bearer " */
    private static var _approovTokenPrefix = ""
    // Approov Token Header String
    public static var approovTokenHeaderAndPrefix: (approovTokenHeader: String, approovTokenPrefix: String) {
        get {
            var approovTokenHeader = ""
            var approovTokenPrefix = ""
            approovTokenHeaderAndPrefixQueue.sync {
                approovTokenHeader = _approovTokenHeader
                approovTokenPrefix = _approovTokenPrefix
        }
        return (approovTokenHeader,approovTokenPrefix)
        }
        set {
            approovTokenHeaderAndPrefixQueue.async(group: nil, qos: .default, flags: .barrier, execute: {(_approovTokenHeader,_approovTokenPrefix) = newValue})
        }
    }
    
    /**
    * Reads any previously-saved dynamic configuration for the Approov SDK. May return 'nil' if a
    * dynamic configuration has not yet been saved by calling saveApproovDynamicConfig().
    */
    func readDynamicApproovConfig() -> String? {
        return UserDefaults.standard.object(forKey: ApproovInterceptor.kApproovDynamicKey) as? String
    }
    
    /*
     *  Reads the initial configuration file for the Approov SDK
     *  The file defined as kApproovInitialKey.kConfigFileExtension
     *  is read from the app bundle main directory
     */
    func readInitialApproovConfig() throws ->  String {
        // Attempt to load the initial config from the app bundle directory
        guard let originalFileURL = Bundle.main.url(forResource: ApproovInterceptor.kApproovInitialKey, withExtension: ApproovInterceptor.kConfigFileExtension) else {
            /*  This is fatal since we can not load the initial configuration file */
            throw ApproovError.initializationFailure(message: "Approov: FATAL unable to load Approov SDK config file from app bundle directories")
        }
        
        // Read file contents
        do {
            let fileExists = try originalFileURL.checkResourceIsReachable()
            if !fileExists {
                throw ApproovError.initializationFailure(message: "Approov: FATAL No initial Approov SDK config file available")
            }
            let configString = try String(contentsOf: originalFileURL)
            return configString
        } catch let error {
            throw ApproovError.initializationFailure(message: "Approov: FATAL Error attempting to read inital configuration for Approov SDK from \(originalFileURL): \(error)")
        }
    }
    
    /**
    * Saves the Approov dynamic configuration to the user defaults database which is persisted
    * between app launches. This should be called after every Approov token fetch where
    * isConfigChanged is set. It saves a new configuration received from the Approov server to
    * the user defaults database so that it is available on app startup on the next launch.
    */
    func storeDynamicConfig(newConfig: String){
        if let updateConfig = Approov.fetchConfig() {
            UserDefaults.standard.set(updateConfig, forKey: ApproovInterceptor.kApproovDynamicKey)
        }
    }
    
    /*
    *  Allows token prefetch operation to be performed as early as possible. This
    *  permits a token to be available while an application might be loading resources
    *  or is awaiting user input. Since the initial token fetch is the most
    *  expensive the prefetch seems reasonable.
    */
    func prefetchApproovToken() {
        if ApproovInterceptor.approovSDKInitialised {
            // We succeeded initializing Approov SDK, fetch a token
            Approov.fetchToken({(approovResult: ApproovTokenFetchResult) in
                // Prefetch done, no need to process response
            }, "approov.io")
        }
    }
    
    /*
     *  Convenience function fetching the Approov token
     *
     */
    fileprivate func fetchApproovToken(request: URLRequest) -> ApproovData {
        var returnData = ApproovData(request: request, decision: .ShouldFail, statusMessage: "", error: nil)
        // Check if Bind Header is set to a non empty String
        if ApproovInterceptor.bindHeader != "" {
            /*  Query the URLSessionConfiguration for user set headers. They would be set like so:
             *  config.httpAdditionalHeaders = ["Authorization Bearer" : "token"]
             *  Since the URLSessionConfiguration is part of the init call and we store its reference
             *  we check for the presence of a user set header there.
             */
            if let aValue = request.value(forHTTPHeaderField: ApproovInterceptor.bindHeader) {
                // Add the Bind Header as a data hash to Approov token
                Approov.setDataHashInToken(aValue)
            } 
        }
        // Invoke fetch token sync
        let approovResult = Approov.fetchTokenAndWait(request.url!.absoluteString)
        // Log result of token fetch
        let aHostname = hostnameFromURL(url: request.url!)
        print("Approov: Approov token for host: \(aHostname) : \(approovResult.loggableToken())")
        if approovResult.isConfigChanged {
            // Store dynamic config file if a change has occurred
            if let newConfig = Approov.fetchConfig() {
                storeDynamicConfig(newConfig: newConfig)
            }
        }
        // Update the message
        returnData.statusMessage = Approov.string(from: approovResult.status)
        switch approovResult.status {
            case ApproovTokenFetchStatus.success:
                // Can go ahead and make the API call with the provided request object
                returnData.decision = .ShouldProceed
                // Set Approov-Token header
                returnData.request.setValue(ApproovInterceptor.approovTokenHeaderAndPrefix.approovTokenPrefix + approovResult.token, forHTTPHeaderField: ApproovInterceptor.approovTokenHeaderAndPrefix.approovTokenHeader)
            case ApproovTokenFetchStatus.noNetwork,
                 ApproovTokenFetchStatus.poorNetwork,
                 ApproovTokenFetchStatus.mitmDetected:
                 // Must not proceed with network request and inform user a retry is needed
                returnData.decision = .ShouldRetry
                let error = ApproovError.runtimeError(message: returnData.statusMessage)
                returnData.error = error
            case ApproovTokenFetchStatus.unprotectedURL,
                 ApproovTokenFetchStatus.unknownURL,
                 ApproovTokenFetchStatus.noApproovService:
                // We do NOT add the Approov-Token header to the request headers
                returnData.decision = .ShouldProceed
            default:
                let error = ApproovError.runtimeError(message: returnData.statusMessage)
                returnData.error = error
                returnData.decision = .ShouldFail
        }// switch
        
        return returnData
    }
    
    /*  Alamofire interceptor protocol
     *https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#adapting-and-retrying-requests-with-requestinterceptor
     */
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        let approovData = fetchApproovToken(request: urlRequest)
        if approovData.decision == .ShouldProceed {
            completion(.success(approovData.request))
        } else {    // .ShouldRetry or .ShouldFail
            completion(.failure(approovData.error!))
        }
    }
}

/*
 *  Approov error conditions
 */
public enum ApproovError: Error {
    case initializationFailure(message: String)
    case configurationFailure(message: String)
    case runtimeError(message: String)
    var localizedDescription: String? {
        switch self {
        case let .initializationFailure(message), let .configurationFailure(message) , let .runtimeError(message):
            return message
        }
    }
}

/*  Alamofire Session class: https://alamofire.github.io/Alamofire/Classes/Session.html
 *  Note that we do not support session delegates with Alamofire. If you wish to use URLSession
 *  and delegate support you can use the ApproovURLSession class
 */
public class ApproovSession: Session {
    
    public init?(prefetchToken: Bool = false,
                 configString: String? = nil,
                configuration: URLSessionConfiguration = URLSessionConfiguration.af.default,
                rootQueue: DispatchQueue = DispatchQueue(label: "org.criticalblue.session.rootQueue"),
                startRequestsImmediately: Bool = true,
                requestQueue: DispatchQueue? = nil,
                serializationQueue: DispatchQueue? = nil,
                serverTrustManager: ApproovTrustManager? = nil,
                redirectHandler: RedirectHandler? = nil,
                cachedResponseHandler: CachedResponseHandler? = nil,
                eventMonitors: [EventMonitor] = []) {
        
        guard let interceptor = ApproovInterceptor(prefetchToken: prefetchToken, config: configString) else {
            return nil
        }
        /* User provided trust manager or we provide a default one */
        var trustManager: ApproovTrustManager?
        if serverTrustManager == nil {
            trustManager = ApproovTrustManager(evaluators: [:])
        } else {
            trustManager = serverTrustManager
        }
        let delegate = SessionDelegate()
        let delegateQueue = OperationQueue()
        delegateQueue.underlyingQueue = rootQueue
        delegateQueue.name = "com.criticalblue.ApproovSessionQueue"
        delegateQueue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: delegateQueue)

        super.init(session: session,
                   delegate: delegate,
                   rootQueue: rootQueue,
                   startRequestsImmediately: startRequestsImmediately,
                   requestQueue: requestQueue,
                   serializationQueue: serializationQueue,
                   interceptor: interceptor,
                   serverTrustManager: trustManager,
                   redirectHandler: redirectHandler,
                   cachedResponseHandler: cachedResponseHandler,
                   eventMonitors: eventMonitors)
    }

    // Bind Header string
    public static var bindHeader: String {
        get {
            ApproovInterceptor.bindHeader
        }
        set {
            ApproovInterceptor.bindHeader = newValue
        }
    }
    // Approov Token Header and Prefix
    public static var approovTokenHeaderAndPrefix: (approovTokenHeader: String, approovTokenPrefix: String) {
        get {
            ApproovInterceptor.approovTokenHeaderAndPrefix
        }
        set {
            ApproovInterceptor.approovTokenHeaderAndPrefix = newValue
        }
    }
}


/*  Host component only gets resolved if the string includes the protocol used
 *  This is not always the case when making requests so a convenience method is needed
 *
 */
func hostnameFromURL(url: URL) -> String {
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
