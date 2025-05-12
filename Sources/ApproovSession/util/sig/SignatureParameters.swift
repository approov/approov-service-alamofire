// MIT License
//
// Copyright (c) 2025-present, Critical Blue Ltd.
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
import RawStructuredFieldValues

public class SignatureParameters: CustomStringConvertible {
    private static let SIGNATURE_PARAMS = "@signature-params"

    private static let ALG = "alg"
    private static let CREATED = "created"
    private static let EXPIRES = "expires"
    private static let KEYID = "keyid"
    private static let NONCE = "nonce"
    private static let TAG = "tag"

	// set this to add an extra header to the request that includes the SHA256 of the signature base
	// which can be used to aid debugging on the server side to determine if there is a problem with
	// the reconstruction of the signature base or the verification of the signature.
    private var debugMode: Bool = false

    private var componentIdentifiers: [StringItem] = []

    // This preserves insertion order
    private var componentParameters: OrderedMap<String, Any> = [:]

	/**
	 * Default constructor creates an empty SignatureParameters ready to be populated.
	 */
    init() {
        self.componentIdentifiers = []
        self.componentParameters = [:]
    }

    /**
	 * Copy constructor creates a SignatureParameters instance pre-populated with a copy of all the
	 * component identifiers and parameters from the provided base.
	 *
	 * @param base
	 */
    init(base: SignatureParameters) {
        self.componentIdentifiers = base.componentIdentifiers // Copy the array
        self.componentParameters = base.componentParameters // Copy the dictionary
    }

	/**
	 * @return the componentIdentifiers
	 */
    func getComponentIdentifiers() -> [StringItem] {
        return componentIdentifiers
    }

	/**
	 * @return the parameters
	 */
    func getParameters() -> OrderedMap<String, Any> {
        return componentParameters
    }

	/**
	 * @param parameters the parameters to set
	 */
    func setParameters(_ parameters: OrderedMap<String, Any>) -> SignatureParameters {
        self.componentParameters = parameters
        return self
    }

	/**
	 * Determine if debug mode has been set for this signature parameters instance
	 *
	 * @return true is debug mode is on; false otherwise
	 */
    func isDebugMode() -> Bool {
        return debugMode
    }

	/**
	 * Set the debug mode for this signature parameters
	 *
	 * @param debugMode true to enable; false to disable
	 */
    func setDebugMode(_ debugMode: Bool) {
        self.debugMode = debugMode
    }

	/**
	 * @return the alg
	 */
    func getAlg() -> String? {
        return componentParameters[Self.ALG] as? String
    }

	/**
	 * @param alg the alg to set
	 */
    func setAlg(_ alg: String) -> SignatureParameters {
        componentParameters[Self.ALG] = alg
        return self
    }

	/**
	 * @return the created-at time in seconds since epoch
	 */
    func getCreated() -> Int64? {
        return componentParameters[Self.CREATED] as? Int64
    }

	/**
	 * @param created the created-at time to set
	 */
    func setCreated(_ created: Int64) -> SignatureParameters {
        componentParameters[Self.CREATED] = created
        return self
    }

	/**
	 * @return the expires-at time in seconds since epoch
	 */
    func getExpires() -> Int64? {
        return componentParameters[Self.EXPIRES] as? Int64
    }

	/**
	 * @param expires the expires-at time to set
	 */
    func setExpires(_ expires: Int64) -> SignatureParameters {
        componentParameters[Self.EXPIRES] = expires
        return self
    }

	/**
	 * @param expires the expires to set
	 */
    func getKeyid() -> String? {
        return componentParameters[Self.KEYID] as? String
    }

	/**
	 * @param keyid the keyid to set
	 */
    func setKeyid(_ keyid: String) -> SignatureParameters {
        componentParameters[Self.KEYID] = keyid
        return self
    }

	/**
	 * @return the nonce
	 */
    func getNonce() -> String? {
        return componentParameters[Self.NONCE] as? String
    }

	/**
	 * @param nonce the nonce to set
	 */
    func setNonce(_ nonce: String) -> SignatureParameters {
        componentParameters[Self.NONCE] = nonce
        return self
    }

    /**
     * @return the tag
     */
    func getTag() -> String? {
        return componentParameters[Self.TAG] as? String
    }

    /**
     * @param tag the tag to set
     */
    func setTag(_ tag: String) -> SignatureParameters {
        componentParameters[Self.TAG] = tag
        return self
    }

    /**
     * @param key the key for which to get the custom parameter value
     */
    func getCustomParameter(_ key: String) -> Any? {
        return componentParameters[key]
    }

    enum SignatureParametersError: Error {
        case invalidType(key: String, expectedType: String)
        case encodingFailed(description: String)
        // case unsupportedParameterType(key: String)
    }

    /**
     * @param key the key for which to set the custom parameter value
     * @param value the value to set for the custom parameter
     */
    func setCustomParameter(_ key: String, value: Any) throws -> SignatureParameters {
        switch key {
        case Self.ALG:
            guard let stringValue = value as? String else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "String")
            }
            return setAlg(stringValue)
        case Self.CREATED:
            guard let intValue = value as? Int64 else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "Int64")
            }
            return setCreated(intValue)
        case Self.EXPIRES:
            guard let intValue = value as? Int64 else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "Int64")
            }
            return setExpires(intValue)
        case Self.KEYID:
            guard let stringValue = value as? String else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "String")
            }
            return setKeyid(stringValue)
        case Self.NONCE:
            guard let stringValue = value as? String else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "String")
            }
            return setNonce(stringValue)
        case Self.TAG:
            guard let stringValue = value as? String else {
                throw SignatureParametersError.invalidType(key: key, expectedType: "String")
            }
            return setTag(stringValue)
        default:
            // Allow other keys without type enforcement
            componentParameters[key] = value
            return self
        }
    }

    func toComponentIdentifier() -> StringItem {
        return StringItem(value: Self.SIGNATURE_PARAMS)
    }

    func toComponentValue() throws -> InnerList {
        // Copy the componentIdentifiers
        var identifiers: BareInnerList = BareInnerList()
        for identifier in componentIdentifiers {
            // init(bareItem: RFC9651BareItem, parameters: OrderedMap<String, RFC9651BareItem>)
            let bareItem = RFC9651BareItem.string(identifier.value)
            var bareParams: OrderedMap<String, RFC9651BareItem> = [:]
            for (key, value) in identifier.parameters {
                bareParams[key] = RFC9651BareItem.string(value)
            }
            let item = Item(bareItem: bareItem, parameters: bareParams)
            identifiers.append(item)
        }

        // Copy the componentParameters
        var parameters: OrderedMap<String, RFC9651BareItem> = [:]
        for (key, value) in componentParameters {
            if let boolValue = value as? Bool {
                parameters[key] = RFC9651BareItem.bool(boolValue)
            } else if let intValue = value as? Int64 {
                parameters[key] = RFC9651BareItem.integer(intValue)
            } else if let doubleValue = value as? Double {
                parameters[key] = try RFC9651BareItem.decimal(PseudoDecimal(doubleValue))
            } else if let stringValue = value as? String {
                parameters[key] = RFC9651BareItem.string(stringValue)
            } else if let data = value as? Data {
                parameters[key] = RFC9651BareItem.undecodedByteSequence(data.base64EncodedString())
            } else if let date = value as? Date {
                parameters[key] = RFC9651BareItem.date(Int64(date.timeIntervalSince1970))
            } else {
                throw ApproovError.permanentError(message: "Unsupported component parameter type: \(type(of: value))")
            }
        }

        // Assemble the result
        let componentValue = InnerList(bareInnerList: identifiers, parameters: parameters)
        return componentValue
    }

    /**
     * Check if a component identifier with the given name exists in the list of component identifiers.
     * @param identifier the component identifier to check
     * @return true if the component identifier exists; false otherwise
     */
    func containsComponentIdentifier(_ identifier: String) -> Bool {
        let predicate: (StringItem) -> Bool = { existingIdentifier in
            return existingIdentifier.value == identifier
        }
        return componentIdentifiers.contains(where: predicate)
    }

	/**
	 * Add a component without parameters.
	 */
    func addComponentIdentifier(_ identifier: String) -> SignatureParameters {
        let normalizedIdentifier = identifier.starts(with: "@") ? identifier : identifier.lowercased()
        let stringItem = StringItem(value: normalizedIdentifier, parameters: [:])
        componentIdentifiers.append(stringItem)
        return self
    }

    /**
     * Check if a component identifier exists in the list of component identifiers.
     * @param identifier the component identifier to check
     * @return true if the component identifier exists; false otherwise
     */
    func containsComponentIdentifier(_ identifier: StringItem) -> Bool {
        // where predicate: (Element) throws -> Bool
        let predicate: (StringItem) -> Bool = { existingIdentifier in
            return existingIdentifier.value == identifier.value && existingIdentifier.parameters == identifier.parameters
        }
        return componentIdentifiers.contains(where: predicate)
    }

    /**
     * Add a component with optional parameters. Field components are assumed to be already set to lowercase.
     */
    func addComponentIdentifier(_ identifier: StringItem) -> SignatureParameters {
        componentIdentifiers.append(identifier)
        return self
    }

    public var description: String {
        do {
            var serializer = StructuredFieldValueSerializer()
            let itemOrInnerList = ItemOrInnerList.innerList(try toComponentValue())
            let serializedValue = try serializer.writeListFieldValue([itemOrInnerList])
            guard let description = String(data: Data(serializedValue), encoding: .utf8) else {
                throw SignatureParametersError.encodingFailed(description: "UTF-8 encoding failed")
            }
            return "SignatureParameters: \(description)"
        } catch let error {
            return "SignatureParameters: \(error.localizedDescription)"
        }
    }
}
