
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
