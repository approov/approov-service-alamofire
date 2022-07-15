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

// custom ApproovTrustEvaluator that performs the default evaluation but also restricts connections
// to the dynamic pins provided by Approov
public final class ApproovTrustEvaluator: ServerTrustEvaluating {
    // subject header bytes for different types of public key
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
    
    // SPKI headers for both RSA and ECC
    private static var pkiHeaders = [String:[Int:Data]]()
    
    /**
     * Initialize SPKI dictionary
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
    
    /**
     * Consttruct a new ApproovTrustEvaluator,.
     */
    init() {
        ApproovTrustEvaluator.initializePKI()
    }
    
    /**
     * SHA256 of given input bytes.
     *
     * @param data is the input data
     * @return SHA256 hash of the data
     */
    private func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    /**
     * Gets the subject public key info (SPKI) header depending on a public key's type and size.
     *
     * @param publicKey is the public key for which the header is being obtained
     * @return the header information
     * @throws if there is a problem
     */
    private func publicKeyInfoHeaderForKey(publicKey: SecKey) throws -> Data {
       guard let publicKeyAttributes = SecKeyCopyAttributes(publicKey) else {
           throw ApproovError.pinningError(message: "Error parsing SPKI header: SecKeyCopyAttributes failure getting key attributes")
       }
       if let keyType = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeyType as String) {
           if let keyLength = (publicKeyAttributes as NSDictionary).value(forKey: kSecAttrKeySizeInBits as String) {
               // find the header
               if let spkiHeader:Data = ApproovTrustEvaluator.pkiHeaders[keyType as! String]?[keyLength as! Int] {
                   return spkiHeader
               }
           }
       }
       throw ApproovError.pinningError(message: "Error parsing SPKI header: unsupported key length or type")
    }
    
    /**
     * Get the SPKI for the given certificate depending on the public key's type and size.
     *
     * @param publicKey is the public key certiticate
     * @return SPKI data
     */
    private func getSPKI(publicKey: SecKey) throws -> Data {
        do {
            // combine the public key header and the public key data to form the public key info
            var spki = try publicKeyInfoHeaderForKey(publicKey: publicKey)
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
                throw ApproovError.pinningError(message: "Error creating SPKI: SecKeyCopyExternalRepresentation key is not exportable")
            }
            spki.append(publicKeyData as Data)
            return spki
        } catch let error {
            throw error
        }
    }
    
    /**
     * Perform a trust evaluation using the ServerTrustEvaluating protocol:
     * https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#evaluating-server-trusts-with-servertrustmanager-and-servertrustevaluating
     *
     * @param trust is the SecTrust to evaluate
     * @param host is the host which to evaluate the SecTrust for
     * @throws if the trust evaluation fails
     */
    public func evaluate(_ trust: SecTrust, forHost host: String) throws {
        // firstly we perform the default evaluation as it must also pass this
        try trust.af.performDefaultValidation(forHost: host)
        
        // get the dynamic pins from Approov
        guard let approovPins = Approov.getPins("public-key-sha256") else {
            // just return if there are no Approov pins (this can happen if Approov is not initialized)
            os_log("ApproovService: pin verification no Approov pins")
            return
        }
        
        // determine if the provided pins match the expected ones
        let isPinMatch: Bool = try {
            if let pins = approovPins[host] {
                // the host pinning is managed by Approov
                var pinsForHost = pins
                if pinsForHost.count == 0 {
                    // there are no pins set for the host so use managed trust roots if available
                    if approovPins["*"] == nil {
                        // there are no managed trust roots so the host is truly unpinned
                        os_log("ApproovService: pin verification %@ no pins", host)
                        return true
                    } else {
                        // use the managed trust roots for pinning
                        pinsForHost = approovPins["*"]!
                    }
                }
                
                // iterate over the certificate chain
                for serverPublicKey in trust.af.publicKeys {
                    do {
                        let spki = try getSPKI(publicKey: serverPublicKey)
                        let publicKeyHash = sha256(data: spki)
                        let publicKeyHashBase64 = String(data:publicKeyHash.base64EncodedData(), encoding: .utf8)
                        for pin in pinsForHost {
                            if publicKeyHashBase64 == pin {
                                os_log("ApproovService: matched pin %@ for %@ from %d pins", pin, host, pinsForHost.count)
                                return true
                            }
                        }
                    } catch let error {
                        // throw to indicate we could not get the SPKI
                        throw error
                    }
                }
                
                // we didn't find any matching pins
                os_log("ApproovService: pin verification failed for %@ with no match for %d pins", host, pinsForHost.count)
                return false
            }
            else {
                // host is not included in the Approov pins and therefore not pinned
                os_log("ApproovService: pin verification %@ unpinned", host)
                return true
            }
        }()
        
        // throw error if pins do not match
        if !isPinMatch {
            throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: ApproovError.pinningError(message:
                "ApproovService: Public key for host \(host) does not match any Approov pins")))
        }
    }
}

/**
 * Custom trust manager to use with Approov that includes dynamic pin checking.
 *
 * See https://alamofire.github.io/Alamofire/Classes/ServerTrustManager.html
 */
public class ApproovTrustManager: ServerTrustManager {
    /**
     * Constructs the ApproovTrustManager.
     *
     * @param allHostsMusttBeEvaluated determines whether all host must be evaluated
     * @param evaluators is the dictionary of policies mapped to a particular host
     */
    public override init(allHostsMustBeEvaluated: Bool = false, evaluators: [String: ServerTrustEvaluating]?) {
        if evaluators != nil {
            super.init(allHostsMustBeEvaluated: allHostsMustBeEvaluated, evaluators: evaluators!)
        } else {
            super.init(allHostsMustBeEvaluated: allHostsMustBeEvaluated, evaluators: [:])
        }
    }
    
    /**
     * Provides the policy for the given host. The ApproovTrustEvaluator is always used for hosts managed by Approov.
     *
     * @param host is the host to be used when searching for a matching policy
     * @return the ServerTrustEvaluating policy to be used
     */
    public override func serverTrustEvaluator(forHost host: String) throws -> ServerTrustEvaluating? {
        if let approovPins = Approov.getPins("public-key-sha256") {
            // if Approov dynamic pins are available then we always use them for domains added to Approov
            if approovPins.keys.contains(host) {
                return ApproovTrustEvaluator()
            }
        }
        return try super.serverTrustEvaluator(forHost: host)
    }
}
