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
import RawStructuredFieldValues


// Gets items from the request
protocol ComponentProvider {
    // Component Identifiers
    static var DC_METHOD: String { get }
    static var DC_AUTHORITY: String { get }
    static var DC_SCHEME: String { get }
    static var DC_TARGET_URI: String { get }
    static var DC_REQUEST_TARGET: String { get }
    static var DC_PATH: String { get }
    static var DC_QUERY: String { get }
    static var DC_QUERY_PARAM: String { get }

    // For requests
    func getMethod() -> String
    func getAuthority() -> String
    func getScheme() -> String
    func getTargetUri() -> String
    func getRequestTarget() -> String
    func getPath() -> String
    func getQuery() -> String
    func getQueryParam(name: String) -> String?
    func hasBody() -> Bool

    // Fields
    func hasField(name: String) -> Bool
    func getField(name: String) -> String?
    static func combineFieldValues(fields: [String]?) -> String?

    func getComponentValue(componentIdentifier: StringItem) throws -> String?
}

enum ComponentProviderError: Error {
    case missingParameter(String)
    case unknownComponent(String)
    case invalidFieldValue(String)
}

extension ComponentProvider {

    // Defaults for component identifiers
    static var DC_METHOD: String { "@method" }
    static var DC_AUTHORITY: String { "@authority" }
    static var DC_SCHEME: String { "@scheme" }
    static var DC_TARGET_URI: String { "@target-uri" }
    static var DC_REQUEST_TARGET: String { "@request-target" }
    static var DC_PATH: String { "@path" }
    static var DC_QUERY: String { "@query" }
    static var DC_QUERY_PARAM: String { "@query-param" }

    static func combineFieldValues(fields: [String]?) -> String? {
        guard let fields = fields else {
            return nil
        }

        var result = [String]()
        for field in fields {
            let trimmedField = field.trimmingCharacters(in: .whitespacesAndNewlines)
            let replacedField = trimmedField.replacingOccurrences(of: "\\s*\\r\\n\\s*", with: " ", options: .regularExpression)
            result.append(replacedField)
        }
        return result.isEmpty ? nil : result.joined(separator: ", ")
    }

    func getComponentValue(componentIdentifier: StringItem) throws -> String? {
        let baseIdentifier = componentIdentifier.value
        if baseIdentifier.starts(with: "@") {
            // Derived component
            switch baseIdentifier {
            case Self.DC_METHOD:
                return getMethod()
            case Self.DC_AUTHORITY:
                return getAuthority()
            case Self.DC_SCHEME:
                return getScheme()
            case Self.DC_TARGET_URI:
                return getTargetUri()
            case Self.DC_REQUEST_TARGET:
                return getRequestTarget()
            case Self.DC_PATH:
                return getPath()
            case Self.DC_QUERY:
                return getQuery()
            case Self.DC_QUERY_PARAM:
                if let nameParameter = componentIdentifier.parameters["name"] {
                    return getQueryParam(name: nameParameter)
                } else {
                    throw ComponentProviderError.missingParameter("'name' parameter of \(baseIdentifier) is required")
                }
            default:
                throw ComponentProviderError.unknownComponent("Unknown derived component: \(baseIdentifier)")
            }
        } else {
            if let keyParameter = componentIdentifier.parameters["key"] {
                if let fieldValue = getField(name: baseIdentifier),
                   let fieldValueData = fieldValue.data(using: .utf8) {
                    // Parse the field as a dictionary
                    var parser = StructuredFieldValueParser(fieldValueData)
                    let parsed = try parser.parseDictionaryFieldValue()
                    if let dictionaryValue = parsed[keyParameter] {
                        var serializer = StructuredFieldValueSerializer()
                        switch dictionaryValue {
                        case .item(let item):
                            let serializedValue = try serializer.writeItemFieldValue(item)
                            return String(data: Data(serializedValue), encoding: .utf8)
                        case .innerList(let innerList):
                            let itemOrInnerList = ItemOrInnerList.innerList(innerList)
                            let serializedValue = try serializer.writeListFieldValue([itemOrInnerList])
                            return String(data: Data(serializedValue), encoding: .utf8)
                        }
                    }
                    throw ComponentProviderError.unknownComponent("Field value for \(baseIdentifier) not found")
                }
                throw ComponentProviderError.missingParameter("'key' parameter of \(baseIdentifier) is required")
            } else if componentIdentifier.parameters["sf"] != nil {
                switch (baseIdentifier) {
                case "accept", "accept-ch", "accept-encoding", "accept-language", "accept-patch", "accept-ranges",
                    "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers",
                    "access-control-request-headers", "alpn", "allow", "cache-status", "connection",
                    "content-encoding", "content-language", "content-length", "example-list", "proxy-status",
                    "te", "timing-allow-origin", "trailer", "transfer-encoding", "variant-key", "vary",
                    "x-list", "x-list-a", "x-list-b", "x-xss-protection":
                    // List
                    if let fieldValue = getField(name: baseIdentifier),
                       let fieldValueData = fieldValue.data(using: .utf8) {
                        var parser = StructuredFieldValueParser(fieldValueData)
                        let parsed = try parser.parseListFieldValue()
                        var serializer = StructuredFieldValueSerializer()
                        let serializedValue = try serializer.writeListFieldValue(parsed)
                        return String(data: Data(serializedValue), encoding: .utf8)
                    }
                    throw ComponentProviderError.invalidFieldValue("Field \(baseIdentifier) is not a structured field")
                case "alt-svc", "cache-control", "cdn-cache-control", "example-dict", "expect-ct", "keep-alive",
                     "pragma", "prefer", "preference-applied", "priority", "signature", "signature-input",
                     "surrogate-control", "variants", "x-dictionary":
                    // Dictionary
                    if let fieldValue = getField(name: baseIdentifier),
                       let fieldValueData = fieldValue.data(using: .utf8) {
                        var parser = StructuredFieldValueParser(fieldValueData)
                        let parsed = try parser.parseDictionaryFieldValue()
                        var serializer = StructuredFieldValueSerializer()
                        let serializedValue = try serializer.writeDictionaryFieldValue(parsed)
                        return String(data: Data(serializedValue), encoding: .utf8)
                    }
                    throw ComponentProviderError.invalidFieldValue("Field \(baseIdentifier) is not a structured field")
                case "access-control-allow-credentials", "access-control-allow-origin", "access-control-max-age",
                     "access-control-request-method", "age", "alt-used", "content-type", "cross-origin-resource-policy",
                     "example-boolean", "example-bytesequence", "example-decimal", "example-integer", "example-string",
                     "example-token", "expect", "host", "origin", "retry-after", "x-content-type-options", "x-frame-options":
                    // Item
                    if let fieldValue = getField(name: baseIdentifier),
                       let fieldValueData = fieldValue.data(using: .utf8) {
                        var parser = StructuredFieldValueParser(fieldValueData)
                        let parsed = try parser.parseItemFieldValue()
                        var serializer = StructuredFieldValueSerializer()
                        let serializedValue = try serializer.writeItemFieldValue(parsed)
                        return String(data: Data(serializedValue), encoding: .utf8)
                    }
                    throw ComponentProviderError.invalidFieldValue("Field \(baseIdentifier) is not a structured field")
                default:
                    throw ComponentProviderError.invalidFieldValue("Field \(baseIdentifier) is not a structured field")
                }
            } else {
                // Regular field
                if let fieldValue = getField(name: baseIdentifier) {
                    return fieldValue
                }
                throw ComponentProviderError.unknownComponent("Field value for \(baseIdentifier) not found")
            }
        }
    }
}
