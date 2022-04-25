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


fileprivate struct ApproovUpdateResponse {
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
                // Actual variable to hold certificate hashes
                var actualCertHashList = certHashList
                // If the cet has list is empty, it means anything presented to us is valid
                if certHashList.count == 0 { // the host is in but no pins defined
                    // if there are no pins and no managed trust allow connection
                    if approovCertHashes["*"] == nil {
                        return true  // We do not pin connection explicitly setting no pins for the host
                    } else {
                        // there are no pins for current host, then we try and use any managed trust roots since "*" is available
                        actualCertHashList = approovCertHashes["*"]!
                    }
                }
                // We have one or more cert hashes matching the receivers host, compare them
                for serverPublicKey in trust.af.publicKeys {
                    do {
                        let spki = try getSPKIHeader(publicKey: serverPublicKey)
                        let publicKeyHash = sha256(data: spki)
                        let publicKeyHashBase64 = String(data:publicKeyHash.base64EncodedData(), encoding: .utf8)
                        for certHash in actualCertHashList {
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
        throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: ApproovError.pinningError(message: "Approov: Public key for host \(host) does not match any pinned keys in Approov SDK")))
        }
    }
    
    /* Utility */
    func getSPKIHeader(publicKey: SecKey) throws -> Data {
        // get the SPKI header depending on the public key's type and size
        do {
            var spkiHeader = try publicKeyInfoHeaderForKey(publicKey: publicKey)
            // combine the public key header and the public key data to form the public key info
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
                throw ApproovError.pinningError(message: "Error parsing SPKI header: SecKeyCopyExternalRepresentation key is not exportable")
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
           throw ApproovError.pinningError(message: "Error parsing SPKI header: SecKeyCopyAttributes failure getting key attributes")
       }
       if let keyType = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeyType as String) {
           if let keyLength = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeySizeInBits as String) {
               // Find the header
               if let spkiHeader:Data = ApproovTrustEvaluator.pkiHeaders[keyType as! String]?[keyLength as! Int] {
                   return spkiHeader
               }
           }
       }
       throw ApproovError.pinningError(message: "Error parsing SPKI header: unsupported key length or unsupported key type")
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
             * we treat the host as not protected by Approov and we forward the trust evaluation. Regardless
             * of the host being present or not, if the managed trust is enabled, we allow the connection 
             * and will verify pins later on
             */
            if allHosts.contains(host) {
                // Check if host has at least one set of pins OR Managed Trust Root is enabled
                if (approovCertHashes[host]!.count > 0) || (allHosts.contains("*")) {
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
private class ApproovInterceptor:  RequestInterceptor {
    
    /*  Alamofire interceptor protocol
     *https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#adapting-and-retrying-requests-with-requestinterceptor
     */
    public func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        let ApproovUpdateResponse = ApproovService.updateRequestWithApproov(request: urlRequest)
        if ApproovUpdateResponse.decision == .ShouldProceed {
            completion(.success(ApproovUpdateResponse.request))
        } else {    // .ShouldRetry or .ShouldFail
            completion(.failure(ApproovUpdateResponse.error!))
        }
    }
}


// The Approov Service class wrapper for the native Approov SDK

public class ApproovService {
    /* Private initializer unavailable */
    private init(){}
    /* Approov config string used to intialize the Interceptor */
    private static var approovConfigStringUsed:String?
    /* The dispatch queue to manage serial access to intializer modified variables */
    private static let initializerQueue = DispatchQueue(label: "ApproovService.initializer")
    /* Status of Approov SDK initialisation */
    private static var approovSDKInitialised = false
    /* map of headers that should have their values substituted for secure strings, mapped to their
     * required prefixes */
    private static var substitutionHeaders:Dictionary<String,String> = Dictionary<String,String>()
    /* The dispatch queue to manage serial access to the substitution headers dictionary */
    private static let substitutionQueue = DispatchQueue(label: "ApproovInterceptor.substitution")
    /* Use log subsystem for info/error */
    private static let log = OSLog(subsystem: "approov-service-alamofire", category: "network")
    // initializes the ApproovService using a config string
    public static func initialize(config: String? = nil) throws {
        do {
            try ApproovService.initializerQueue.sync  {
                if ApproovService.approovSDKInitialised {
                    // We have initialized already, just check if using different config string
                    if config != nil {
                        if config != ApproovService.approovConfigStringUsed {
                            throw ApproovError.initializationError(message: "ApproovInterceptor already initialized with different config")
                        }
                        // We have initialized already, we need another interceptor instance
                    }
                } else {
                    // We are trying to initialize teh Approov SDK
                    if config == nil {
                        // Is not possible to initialize the Approov SDK with no config string
                        throw ApproovError.initializationError(message: "ApproovInterceptor requires config string to intitialize SDK")
                    }
                    /* Initialise Approov SDK */
                    do {
                        try Approov.initialize(config!, updateConfig: "auto", comment: nil)
                        Approov.setUserProperty("approov-service-alamofire")
                        ApproovService.approovSDKInitialised = true
                    } catch let error {
                        throw ApproovError.initializationError(message: "Approov: Error initializing Approov SDK: \(error.localizedDescription)")
                    }
                }
            }
            
        } catch {
            throw ApproovError.initializationError(message: "Approov: Unknown error whilst initializing Approov SDK")
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
    
    
    /*
    *  Allows token prefetch operation to be performed as early as possible. This
    *  permits a token to be available while an application might be loading resources
    *  or is awaiting user input. Since the initial token fetch is the most
    *  expensive the prefetch seems reasonable.
    */
    private static func prefetch() {
        if ApproovService.approovSDKInitialised {
            // We succeeded initializing Approov SDK, fetch a token
            Approov.fetchToken({(approovResult: ApproovTokenFetchResult) in
                // Prefetch done, no need to process response
            }, "approov.io")
        }
    }
    
    /*
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
        if prefix == nil {
            ApproovService.substitutionQueue.sync {
                ApproovService.substitutionHeaders[header] = ""
            }
        } else {
            ApproovService.substitutionQueue.sync {
                ApproovService.substitutionHeaders[header] = prefix
            }
        }
    }
    
    /*
     * Removes the name of a header if it exists from the secure strings substitution dictionary.
     */
     public static func removeSubstitutionHeader(header: String) {
         ApproovService.substitutionQueue.sync {
            if ApproovService.substitutionHeaders[header] != nil {
                ApproovService.substitutionHeaders.removeValue(forKey: header)
            }
        }
    }
    
    /*
     *  Convenience function updating a request with the Approov token
     *
     */
    fileprivate static func updateRequestWithApproov(request: URLRequest) -> ApproovUpdateResponse {
        var returnData = ApproovUpdateResponse(request: request, decision: .ShouldFail, statusMessage: "", error: nil)
        // Check if Bind Header is set to a non empty String
        if ApproovService.bindHeader != "" {
            /*  Query the URLSessionConfiguration for user set headers. They would be set like so:
             *  config.httpAdditionalHeaders = ["Authorization Bearer" : "token"]
             *  Since the URLSessionConfiguration is part of the init call and we store its reference
             *  we check for the presence of a user set header there.
             */
            if let aValue = request.value(forHTTPHeaderField: ApproovService.bindHeader) {
                // Add the Bind Header as a data hash to Approov token
                Approov.setDataHashInToken(aValue)
            }
        }
        // Invoke fetch token sync
        let approovResult = Approov.fetchTokenAndWait(request.url!.absoluteString)
        // Log result of token fetch
        let aHostname = hostnameFromURL(url: request.url!)
        os_log("Approov: fetchApproovToken %@: %@", type: .info, aHostname, approovResult.loggableToken())
        // Update the message
        returnData.statusMessage = Approov.string(from: approovResult.status)
        switch approovResult.status {
            case ApproovTokenFetchStatus.success:
                // Can go ahead and make the API call with the provided request object
                returnData.decision = .ShouldProceed
                // Set Approov-Token header
                returnData.request.setValue(ApproovService.approovTokenHeaderAndPrefix.approovTokenPrefix + approovResult.token, forHTTPHeaderField: ApproovService.approovTokenHeaderAndPrefix.approovTokenHeader)
            case ApproovTokenFetchStatus.noNetwork,
                 ApproovTokenFetchStatus.poorNetwork,
                 ApproovTokenFetchStatus.mitmDetected:
                 // Must not proceed with network request and inform user a retry is needed
                returnData.decision = .ShouldRetry
                let error = ApproovError.networkingError(message: returnData.statusMessage)
                returnData.error = error
                return returnData
            case ApproovTokenFetchStatus.unprotectedURL,
                 ApproovTokenFetchStatus.unknownURL,
                 ApproovTokenFetchStatus.noApproovService:
                // We do NOT add the Approov-Token header to the request headers
                returnData.decision = .ShouldProceed
            default:
                let error = ApproovError.permanentError(message: returnData.statusMessage)
                returnData.error = error
                returnData.decision = .ShouldFail
                return returnData
        }// switch
        
        // we now deal with any header substitutions, which may require further fetches but these
        // should be using cached results
        let isIllegalSubstitution = (approovResult.status == ApproovTokenFetchStatus.unknownURL)
        // Check for the presence of headers
        if let requestHeaders = returnData.request.allHTTPHeaderFields {
            // Make a copy of the original request so we can modify it
            var replacementRequest = returnData.request
            for (key, _) in ApproovService.substitutionHeaders {
                let header = key
                if let prefix = ApproovService.substitutionHeaders[key] {
                    if let value = requestHeaders[header]{
                        // Check if the request contains the header we want to replace
                        if ((value.hasPrefix(prefix)) && (value.count > prefix.count)){
                            let index = prefix.index(prefix.startIndex, offsetBy: prefix.count)
                            let approovResults = Approov.fetchSecureStringAndWait(String(value.suffix(from:index)), nil)
                            os_log("Approov: Substituting header: %@, %@", type: .info, header, Approov.string(from: approovResults.status))
                            // Process the result of the token fetch operation
                            if approovResults.status == ApproovTokenFetchStatus.success {
                                if isIllegalSubstitution {
                                    // don't allow substitutions on unadded API domains to prevent them accidentally being
                                    // subject to a Man-in-the-Middle (MitM) attack
                                    let error = ApproovError.configurationError(message: "Header substitution: API domain unknown")
                                    returnData.error = error
                                    return returnData
                                }
                                // We add the modified header to the new copy of request
                                if let secureStringResult = approovResults.secureString {
                                    replacementRequest.setValue(prefix + secureStringResult, forHTTPHeaderField: key)
                                } else {
                                    // Secure string is nil
                                    let error = ApproovError.permanentError(message: "Header substitution: key lookup error")
                                    returnData.error = error
                                    return returnData
                                }
                            } else if approovResults.status == ApproovTokenFetchStatus.rejected {
                                // if the request is rejected then we provide a special exception with additional information
                                let error = ApproovError.rejectionError(message: "Header substitution: rejected", ARC: approovResults.arc, rejectionReasons: approovResults.rejectionReasons)
                                returnData.error = error
                                return returnData
                            } else if approovResults.status == ApproovTokenFetchStatus.noNetwork ||
                                        approovResults.status == ApproovTokenFetchStatus.poorNetwork ||
                                        approovResults.status == ApproovTokenFetchStatus.mitmDetected {
                                // we are unable to get the secure string due to network conditions so the request can
                                // be retried by the user later
                                let error = ApproovError.networkingError(message: "Header substitution: network issue, retry needed")
                                returnData.error = error
                                return returnData
                            } else if approovResults.status != ApproovTokenFetchStatus.unknownKey {
                                // we have failed to get a secure string with a more serious permanent error
                                let error = ApproovError.permanentError(message: "Header substitution: " + Approov.string(from: approovResults.status))
                                returnData.error = error
                                return returnData
                            }
                        }// if (value)
                    } // if let value
                }// if let prefix
            }// for
            // Replace the modified request headers to the request
            returnData.request = replacementRequest
        }// if let
        
        return returnData
    }
    
    /*
    * Fetches a secure string with the given key. If newDef is not nil then a secure string for
    * the particular app instance may be defined. In this case the new value is returned as the
    * secure string. Use of an empty string for newDef removes the string entry. Note that this
    * call may require network transaction and thus may block for some time, so should not be called
    * from the UI thread. If the attestation fails for any reason then an exception is raised. Note
    * that the returned string should NEVER be cached by your app, you should call this function when
    * it is needed. If the fetch fails for any reason an exception is thrown with description. Exceptions
    * could be due to the feature not being enabled from the CLI tools (ApproovError.configurationError
    * type raised), a rejection throws an Approov.rejectionError type which might include additional
    * information regarding the failure reason. An ApproovError.networkingError exception should allow a
    * retry operation to be performed and finally if some other error occurs an Approov.permanentError
    * is raised.
    *
    * @param key is the secure string key to be looked up
    * @param newDef is any new definition for the secure string, or nil for lookup only
    * @return secure string (should not be cached by your app) or nil if it was not defined or an error ocurred
    * @throws exception with description of cause
    */
    public static func fetchSecureString(key: String, newDef: String?) throws -> String? {
        // determine the type of operation as the values themselves cannot be logged
        var type = "lookup"
        if newDef == nil {
            type = "definition"
        }
        // invoke fetch secure string
        let approovResult = Approov.fetchSecureStringAndWait(key, newDef)
        os_log("Approov: fetchSecureString: %@: %@", type: .info, type, Approov.string(from: approovResult.status))
        // process the returned Approov status
        if approovResult.status == ApproovTokenFetchStatus.disabled {
            throw ApproovError.configurationError(message: "fetchSecureString: secure string feature disabled")
        } else if  approovResult.status == ApproovTokenFetchStatus.badKey {
            throw ApproovError.permanentError(message: "fetchSecureString: secure string unknown key")
        } else if approovResult.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "fetchSecureString: rejected", ARC: approovResult.arc, rejectionReasons: approovResult.rejectionReasons)
        } else if approovResult.status == ApproovTokenFetchStatus.noNetwork ||
                    approovResult.status == ApproovTokenFetchStatus.poorNetwork ||
                    approovResult.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "fetchSecureString: network issue, retry needed")
        } else if ((approovResult.status != ApproovTokenFetchStatus.success) && (approovResult.status != ApproovTokenFetchStatus.unknownKey)){
            // we are unable to get the secure string due to a more permanent error
            throw ApproovError.permanentError(message: "fetchSecureString: " + Approov.string(from: approovResult.status))

        }
        return approovResult.secureString
    }// fetchSecureString
        
/*
    * Fetches a custom JWT with the given payload. Note that this call will require network
    * transaction and thus will block for some time, so should not be called from the UI thread.
    * If the fetch fails for any reason an exception will be thrown. Exceptions could be due to
    * malformed JSON string provided (then a ApproovError.permanentError is raised), the feature not
    * being enabled from the CLI tools (ApproovError.configurationError type raised), a rejection throws
    * a ApproovError.rejectionError type which might include additional information regarding the failure
    * reason. An Approov.networkingError exception should allow a retry operation to be performed. Finally
    * if some other error occurs an Approov.permanentError is raised.
    *
    * @param payload is the marshaled JSON object for the claims to be included
    * @return custom JWT string or nil if an error occurred
    * @throws exception with description of cause
    */
    public static func fetchCustomJWT(payload: String) throws -> String? {
        // fetch the custom JWT
        let approovResult = Approov.fetchCustomJWTAndWait(payload)
        // log result of token fetch operation but do not log the value
        os_log("Approov: fetchCustomJWT: %@", type: .info, Approov.string(from: approovResult.status))
        // process the returned Approov status
        if approovResult.status == ApproovTokenFetchStatus.badPayload {
            throw ApproovError.permanentError(message: "fetchCustomJWT: malformed JSON")
        } else if  approovResult.status == ApproovTokenFetchStatus.disabled {
            throw ApproovError.configurationError(message: "fetchCustomJWT: feature not enabled")
        } else if approovResult.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "fetchCustomJWT: rejected", ARC: approovResult.arc, rejectionReasons: approovResult.rejectionReasons)
        } else if approovResult.status == ApproovTokenFetchStatus.noNetwork ||
                    approovResult.status == ApproovTokenFetchStatus.poorNetwork ||
                    approovResult.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the custom JWT due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "fetchCustomJWT: network issue, retry needed")
        } else if (approovResult.status != ApproovTokenFetchStatus.success){
            // we are unable to get the custom JWT due to a more permanent error
            throw ApproovError.permanentError(message: "fetchCustomJWT: " + Approov.string(from: approovResult.status))
        }
        return approovResult.token
    }

    /*
    * Performs a precheck to determine if the app will pass attestation. This requires secure
    * strings to be enabled for the account, although no strings need to be set up. This will
    * likely require network access so may take some time to complete. It may throw an exception
    * if the precheck fails or if there is some other problem. Exceptions could be due to
    * a rejection (throws a ApproovError.rejectionError) type which might include additional
    * information regarding the rejection reason. An ApproovError.networkingError exception should
    * allow a retry operation to be performed and finally if some other error occurs an
    * ApproovError.permanentError is raised.
    */
    public static func precheck() throws {
        // try to fetch a non-existent secure string in order to check for a rejection
        let approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", nil)
        // process the returned Approov status
        if approovResults.status == ApproovTokenFetchStatus.rejected {
            // if the request is rejected then we provide a special exception with additional information
            throw ApproovError.rejectionError(message: "precheck: rejected", ARC: approovResults.arc, rejectionReasons: approovResults.rejectionReasons)
        } else if approovResults.status == ApproovTokenFetchStatus.noNetwork ||
                    approovResults.status == ApproovTokenFetchStatus.poorNetwork ||
                    approovResults.status == ApproovTokenFetchStatus.mitmDetected {
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw ApproovError.networkingError(message: "precheck: network issue, retry needed")
        } else if (approovResults.status != ApproovTokenFetchStatus.success) && (approovResults.status != ApproovTokenFetchStatus.unknownKey){
            // we are unable to get the secure string due to a more permanent error
            throw ApproovError.permanentError(message: "precheck: " + Approov.string(from: approovResults.status))
        }
    }//precheck
}

/*
 *  Approov error conditions
 */
public enum ApproovError: Error {
    case initializationError(message: String)
    case configurationError(message: String)
    case pinningError(message: String)
    case networkingError(message: String)
    case permanentError(message: String)
    case rejectionError(message: String, ARC: String?, rejectionReasons: String?)
}

/*  Alamofire Session class: https://alamofire.github.io/Alamofire/Classes/Session.html
 *  Note that we do not support session delegates with Alamofire. If you wish to use URLSession
 *  and delegate support you can use the ApproovURLSession class
 */
public class ApproovSession: Session {
    public init?(
                configuration: URLSessionConfiguration = URLSessionConfiguration.af.default,
                rootQueue: DispatchQueue = DispatchQueue(label: "approov.service.alamofire.rootQueue"),
                startRequestsImmediately: Bool = true,
                requestQueue: DispatchQueue? = nil,
                serializationQueue: DispatchQueue? = nil,
                serverTrustManager: ApproovTrustManager? = nil,
                redirectHandler: RedirectHandler? = nil,
                cachedResponseHandler: CachedResponseHandler? = nil,
                eventMonitors: [EventMonitor] = []) {
        
            let interceptor = ApproovInterceptor()
            
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
            delegateQueue.name = "approov.service.alamofire.ApproovSessionQueue"
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
