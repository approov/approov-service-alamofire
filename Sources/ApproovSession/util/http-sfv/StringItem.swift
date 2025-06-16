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

/**
 * A StringItem is a structured field value item that represents a string with optional parameters.
 */
public struct StringItem {
    var item: Item

    public init(value: String) {
        item = Item(bareItem: RFC9651BareItem.string(value), parameters: [:])
    }

    public init(value: String, parameters: OrderedMap<String, RFC9651BareItem>) {
        item = Item(bareItem: RFC9651BareItem.string(value), parameters: parameters)
    }

    var value: String {
        switch item.rfc9651BareItem {
        case .string(let string):
            let check: String = string
            return check
        default:
            return ""
        }
    }

    var parameters: OrderedMap<String, String> {
        var paramsAsStrings = OrderedMap<String, String>()
        for (key, value) in item.rfc9651Parameters {
            switch value {
            case .string(let string):
                paramsAsStrings[key] = string
            default:
                continue
            }
        }
        return paramsAsStrings
    }
}
