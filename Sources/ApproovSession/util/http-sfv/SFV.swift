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

import RawStructuredFieldValues
import Foundation

public class SFV {

    static func serializeStringItem(item: StringItem) throws -> String? {
        var serializer = StructuredFieldValueSerializer()
        let serialized = try serializer.writeItemFieldValue(item.item)
        let string = String(data: Data(serialized), encoding: .utf8)
        return string
    }

    static func serializeList(list: InnerList) throws -> String? {
        var serializer = StructuredFieldValueSerializer()
        let itemOrInnerList = ItemOrInnerList.innerList(list)
        let serialized = try serializer.writeListFieldValue([itemOrInnerList])
        let string = String(data: Data(serialized), encoding: .utf8)
        return string
    }

    // Method to serialize dictionary entry of sigId: signatureBase64 of type String: UndecodedByteSequence
    static func serializeDictionary(key: String, data: Data) throws -> String?
    {
        var serializer = StructuredFieldValueSerializer()
        let dataBase64: String = data.base64EncodedString()
        let dictionary: OrderedMap<String, ItemOrInnerList> =
            [key: ItemOrInnerList.item(Item(bareItem: RFC9651BareItem.undecodedByteSequence(dataBase64), parameters: [:]))]
        let serialized: [UInt8] = try serializer.writeDictionaryFieldValue(dictionary)
        let string = String(data: Data(serialized), encoding: .utf8)
        return string
    }

    // Method to serialize dictionary entry of key: sigParams of type String: InnerList
    static func serializeDictionary(key: String, innerList: InnerList) throws -> String? {
        var serializer = StructuredFieldValueSerializer()
        let dictionary: OrderedMap<String, ItemOrInnerList> = [key: ItemOrInnerList.innerList(innerList)]
        let serialized = try serializer.writeDictionaryFieldValue(dictionary)
        let string = String(data: Data(serialized), encoding: .utf8)
        return string
    }
}
