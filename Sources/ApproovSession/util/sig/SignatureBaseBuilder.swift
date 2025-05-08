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

class SignatureBaseBuilder {
    private let sigParams: SignatureParameters
    private let ctx: ComponentProvider

    init(sigParams: SignatureParameters, ctx: ComponentProvider) {
        self.sigParams = sigParams
        self.ctx = ctx
    }

    func createSignatureBase() throws -> String {
        var base = ""

        for componentIdentifier in sigParams.getComponentIdentifiers() {
            if let componentValue = try ctx.getComponentValue(componentIdentifier: componentIdentifier) {
                // Write out the line to the base
                guard let compIdString = try SFV.serializeStringItem(item: componentIdentifier) else {
                    throw ApproovError.permanentError(message: "Failed to serialize component identifier: \(componentIdentifier)")
                }
                base += "\(compIdString): \(componentValue)\n"
            } else {
                throw ApproovError.permanentError(message: "Couldn't find required component value for identifier: \(componentIdentifier)")
            }
        }

        // Add the signature parameters line
        // Serialize the signature parameters component identifier
        guard let sigParamsIdString = try SFV.serializeStringItem(item: sigParams.toComponentIdentifier()) else {
            throw ApproovError.permanentError(message: "Failed to serialize signature parameters component identifier")
        }

        // Serialize the signature params dictionary returned by toComponentValue()
        guard let sigParamsString = try SFV.serializeList(list: sigParams.toComponentValue()) else {
            throw ApproovError.permanentError(message: "Failed to serialize signature parameters component value")
        }
        base += "\(sigParamsIdString): \(sigParamsString)"

        return base
    }
}
