import XCTest
import Foundation
@testable import ApproovAFSession
import Approov
import MiniSDKTestSupport

/// Integration tests for the ApproovService Alamofire service layer.
///
/// Tests are organized to match the sections defined in TESTING_REQUIREMENTS.md
/// from the core-service-layers-testing repository.
///
/// - SeeAlso: `TESTING_REQUIREMENTS.md` in core-service-layers-testing
final class ApproovAFSessionMiniSDKTests: XCTestCase {
    private let validInitialConfig = "#cb-ivol#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo="

    override func setUpWithError() throws {
        try super.setUpWithError()
        MiniSDKAttesterProxyController.reset()
        ApproovService.resetForTesting()
        ApproovService.setLoggingLevel(.off)
        try ApproovService.initialize(config: validInitialConfig, comment: "reinit-alamofire-tests")
    }

    override func tearDown() {
        ApproovService.setServiceMutator(nil)
        MiniSDKAttesterProxyController.reset()
        ApproovService.resetForTesting()
        super.tearDown()
    }

    // MARK: - §1 Initialization
    // TESTING_REQUIREMENTS.md §1

    /// §1 Valid Configuration
    func testInitializeWithValidConfig() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: validInitialConfig, comment: nil)
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertTrue(ApproovService.isApproovEnabled())
    }

    /// §1 Empty Configuration (Valid Comment)
    func testInitializeWithEmptyConfigBypassMode() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: "", comment: "some-comment")
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertFalse(ApproovService.isApproovEnabled())
    }

    /// §1 Empty Configuration (Empty Comment)
    func testInitializeWithEmptyConfigEmptyComment() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: "", comment: nil)
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertFalse(ApproovService.isApproovEnabled())
    }

    /// §1 Empty Then Valid Configuration
    func testInitializeEmptyThenValidUpgrade() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: "", comment: nil)
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertFalse(ApproovService.isApproovEnabled())

        try ApproovService.initialize(config: validInitialConfig, comment: nil)
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertTrue(ApproovService.isApproovEnabled())
    }

    /// §1 Empty Configuration after Valid Configuration
    func testInitializeValidThenEmptyIgnored() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: validInitialConfig, comment: nil)
        XCTAssertTrue(ApproovService.isApproovEnabled())

        // This should be silently ignored
        try ApproovService.initialize(config: "", comment: nil)
        XCTAssertTrue(ApproovService.isApproovEnabled())
    }

    /// §1 Same Config Re-initialization
    func testInitializeSameConfigReinit() throws {
        XCTAssertNoThrow(try ApproovService.initialize(config: validInitialConfig, comment: nil))
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertTrue(ApproovService.isApproovEnabled())
    }

    /// §1 Different Non-empty Config Re-initialization
    func testInitializeDifferentConfigRejectsAndPreservesState() throws {
        let differentConfig = "#cb-other#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo="
        XCTAssertThrowsError(try ApproovService.initialize(config: differentConfig, comment: nil)) { error in
            guard case ApproovError.initializationError = error else {
                return XCTFail("Expected initializationError, got \(error)")
            }
        }
        // State must be preserved from the original initialization
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertTrue(ApproovService.isApproovEnabled())
    }

    /// §1 Service Mutator Reset
    func testInitializeResetsMutatorToDefault() throws {
        struct TestMutator: ApproovServiceMutator {}
        ApproovService.setServiceMutator(TestMutator())
        XCTAssertTrue(ApproovService.getServiceMutator() is TestMutator)

        try ApproovService.initialize(config: validInitialConfig, comment: "reinit-mutator-test")
        XCTAssertTrue(ApproovService.getServiceMutator() is ApproovServiceMutatorDefault)
    }

    /// §1 SDK and Service Layer Initialization Behaviour — guards
    func testSDKMethodsGuardedWhenNotEnabled() throws {
        ApproovService.resetForTesting()
        try ApproovService.initialize(config: "", comment: nil)
        XCTAssertTrue(ApproovService.isInitialized())
        XCTAssertFalse(ApproovService.isApproovEnabled())

        // These should return nil/empty without calling the SDK
        XCTAssertEqual(ApproovService.getLastARC(), "")
        XCTAssertNil(ApproovService.getDeviceID())
        XCTAssertNil(ApproovService.getAccountMessageSignature(message: "test"))
        XCTAssertNil(ApproovService.getInstallMessageSignature(message: "test"))

        // These should throw
        XCTAssertThrowsError(try ApproovService.precheck())
        XCTAssertThrowsError(try ApproovService.fetchToken(url: "https://example.com"))
        XCTAssertThrowsError(try ApproovService.fetchSecureString(key: "test", newDef: nil))
        XCTAssertThrowsError(try ApproovService.fetchCustomJWT(payload: "{}"))
    }
}
