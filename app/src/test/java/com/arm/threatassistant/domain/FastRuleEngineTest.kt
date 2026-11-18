package com.arm.threatassistant.domain

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.detection.ruleengine.*
import com.arm.threatassistant.domain.model.AnalysisInput

/**
 * Unit tests for Phase 3A FastRuleEngine.
 *
 * These tests exercise pure Kotlin logic only and do not require the Android
 * framework. They verify detection across all five rule categories, false
 * positive resistance, case/punctuation/whitespace tolerance, Unicode
 * handling, deduplication, and the absence of an authoritative verdict.
 */
class FastRuleEngineTest {

    private val engine = FastRuleEngine

    // ---- Helpers ----

    private fun input(text: String): AnalysisInput = AnalysisInput(messageText = text)

    private fun ruleIds(result: RuleDetectionResult): Set<String> =
        result.signals.map { it.ruleId }.toSet()

    private fun categories(result: RuleDetectionResult): Set<RuleCategory> =
        result.categoriesDetected

    private fun hasRule(result: RuleDetectionResult, ruleId: String): Boolean =
        result.signals.any { it.ruleId == ruleId }

    private fun assertSignalProperties(signal: DetectionSignal, expectedRuleId: String) {
        assertNotNull(signal.signalId)
        assertEquals(expectedRuleId, signal.ruleId)
        assertNotNull(signal.description)
        assertFalse(signal.matchedText.isBlank())
        assertTrue(signal.severity == DetectionSeverity.LOW ||
            signal.severity == DetectionSeverity.MEDIUM ||
            signal.severity == DetectionSeverity.HIGH)
        assertEquals("FastRuleEngine", signal.detectorId)
        assertEquals("1.0.0", signal.detectorVersion)
    }

    // ---- Category A: Urgency and coercion ----

    @Test
    fun urgencyImmediateActionRequiredIsDetected() {
        val result = engine.detect(input("Immediate action required on your account."))
        assertTrue("Expected urg_001, got ${ruleIds(result)}", hasRule(result, "urg_001"))
        assertSignalProperties(result.signals.first { it.ruleId == "urg_001" }, "urg_001")
    }

    @Test
    fun urgencyAccountBlockedTodayIsDetected() {
        val result = engine.detect(input("Your account will be blocked today if you do not act."))
        assertTrue("Expected urg_002, got ${ruleIds(result)}", hasRule(result, "urg_002"))
    }

    @Test
    fun urgencyActWithin24HoursIsDetected() {
        val result = engine.detect(input("Act within 24 hours to avoid service loss."))
        assertTrue("Expected urg_004, got ${ruleIds(result)}", hasRule(result, "urg_004"))
    }

    @Test
    fun urgencyFailureToRespondSuspensionIsDetected() {
        val result = engine.detect(input("Failure to respond will result in suspension of your account."))
        assertTrue("Expected urg_005, got ${ruleIds(result)}", hasRule(result, "urg_005"))
    }

    @Test
    fun urgencyUrgentVerificationIsDetected() {
        val result = engine.detect(input("Urgent verification required for your profile."))
        assertTrue("Expected urg_003, got ${ruleIds(result)}", hasRule(result, "urg_003"))
    }

    // ---- Category B: Credential requests ----

    @Test
    fun credentialEnterYourPasswordIsDetected() {
        val result = engine.detect(input("Enter your password to continue."))
        assertTrue("Expected cred_001, got ${ruleIds(result)}", hasRule(result, "cred_001"))
    }

    @Test
    fun credentialShareYourOtpIsDetected() {
        val result = engine.detect(input("Share your OTP with us to verify your identity."))
        assertTrue("Expected cred_003, got ${ruleIds(result)}", hasRule(result, "cred_003"))
    }

    @Test
    fun credentialConfirmYourPinIsDetected() {
        val result = engine.detect(input("Confirm your PIN immediately."))
        assertTrue("Expected cred_004, got ${ruleIds(result)}", hasRule(result, "cred_004"))
    }

    @Test
    fun credentialUpdateLoginDetailsIsDetected() {
        val result = engine.detect(input("Please update login details on the portal."))
        assertTrue("Expected cred_005, got ${ruleIds(result)}", hasRule(result, "cred_005"))
    }

    @Test
    fun credentialOtpVerificationRequiredIsDetected() {
        val result = engine.detect(input("OTP verification required for account access."))
        assertTrue("Expected cred_007, got ${ruleIds(result)}", hasRule(result, "cred_007"))
    }

    // ---- Category C: Financial impersonation ----

    @Test
    fun financialImpersonationThisIsYourBankIsDetected() {
        val result = engine.detect(input("This is your bank. Please verify your details."))
        assertTrue("Expected fin_001, got ${ruleIds(result)}", hasRule(result, "fin_001"))
    }

    @Test
    fun financialImpersonationPaymentServiceTeamIsDetected() {
        val result = engine.detect(input("This is the payment service team calling about your account."))
        assertTrue("Expected fin_004, got ${ruleIds(result)}", hasRule(result, "fin_004"))
    }

    @Test
    fun financialImpersonationCustomerSupportIsDetected() {
        val result = engine.detect(input("Customer support team requires your verification."))
        assertTrue("Expected fin_006, got ${ruleIds(result)}", hasRule(result, "fin_006"))
    }

    // ---- Category D: Payment demands ----

    @Test
    fun paymentDemandPayImmediatelyIsDetected() {
        val result = engine.detect(input("Pay immediately to avoid account closure."))
        assertTrue("Expected pay_001, got ${ruleIds(result)}", hasRule(result, "pay_001"))
    }

    @Test
    fun paymentDemandTransferMoneyToAvoidPenaltiesIsDetected() {
        val result = engine.detect(input("Transfer money to avoid penalties on your account."))
        assertTrue("Expected pay_002, got ${ruleIds(result)}", hasRule(result, "pay_002"))
    }

    @Test
    fun paymentDemandProcessingFeeIsDetected() {
        val result = engine.detect(input("Pay a processing fee to release your funds."))
        assertTrue("Expected pay_003, got ${ruleIds(result)}", hasRule(result, "pay_003"))
    }

    @Test
    fun paymentDemandRefundProcessingFeeIsDetected() {
        val result = engine.detect(input("Unexpected refund processing fee of Rs 500 applies."))
        assertTrue("Expected pay_005, got ${ruleIds(result)}", hasRule(result, "pay_005"))
    }

    // ---- Category E: Account suspension threats ----

    @Test
    fun suspensionBankAccountSuspensionIsDetected() {
        val result = engine.detect(input("Your bank account suspension is imminent."))
        assertTrue("Expected susp_001, got ${ruleIds(result)}", hasRule(result, "susp_001"))
    }

    @Test
    fun suspensionAccountDeactivationIsDetected() {
        val result = engine.detect(input("Your account will be deactivated within 2 hours."))
        assertTrue("Expected susp_002, got ${ruleIds(result)}", hasRule(result, "susp_002"))
    }

    @Test
    fun suspensionKycExpirationIsDetected() {
        val result = engine.detect(input("KYC expiration notice: your KYC has expired."))
        assertTrue("Expected susp_003, got ${ruleIds(result)}", hasRule(result, "susp_003"))
    }

    @Test
    fun suspensionSimBlockingIsDetected() {
        val result = engine.detect(input("SIM blocking warning: your SIM will be blocked."))
        assertTrue("Expected susp_004, got ${ruleIds(result)}", hasRule(result, "susp_004"))
    }

    // ---- Multiple indicators in one message ----

    @Test
    fun multipleIndicatorsAllDetected() {
        val text = "This is your bank. Your account will be blocked today. Share your OTP immediately. Pay a processing fee to avoid suspension. Your account will be suspended if you do not respond."
        val result = engine.detect(input(text))
        assertTrue("Expected at least 4 signals, got ${result.signalCount}: ${ruleIds(result)}", result.signalCount >= 4)
        assertTrue(categories(result).contains(RuleCategory.FINANCIAL_IMPERSONATION))
        assertTrue(categories(result).contains(RuleCategory.URGENCY_AND_COERCION))
        assertTrue(categories(result).contains(RuleCategory.CREDENTIAL_REQUEST))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertTrue(categories(result).contains(RuleCategory.ACCOUNT_SUSPENSION))
    }

    // ---- Indian SMS scam examples (evaluation examples, not assumptions) ----

    @Test
    fun fakeBankKycUpdateSms() {
        // Representative Indian fake bank KYC update scam SMS.
        val text = "Dear customer, your SBI account KYC has expired. Complete KYC verification immediately or your account will be suspended. Click http://fake-kyc.example.in"
        val result = engine.detect(input(text))
        assertTrue("Expected KYC expiration signal, got ${ruleIds(result)}", hasRule(result, "susp_003"))
        assertTrue("Expected account will be suspended signal, got ${ruleIds(result)}", hasRule(result, "susp_006"))
        assertTrue(categories(result).contains(RuleCategory.ACCOUNT_SUSPENSION))
    }

    @Test
    fun upiPaymentScamSms() {
        // Representative UPI payment scam SMS.
        val text = "Your UPI payment of Rs 5000 is pending. Pay a processing fee of Rs 100 to release funds. Pay immediately or transaction will be cancelled."
        val result = engine.detect(input(text))
        assertTrue("Expected processing fee signal, got ${ruleIds(result)}", hasRule(result, "pay_003"))
        assertTrue("Expected pay immediately signal, got ${ruleIds(result)}", hasRule(result, "pay_001"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
    }

    @Test
    fun fakeElectricityBillSuspensionSms() {
        // Representative fake electricity bill suspension SMS.
        val text = "Your electricity bill is unpaid. Your account will be blocked today if you do not pay. Pay now to avoid service termination. Pay immediately."
        val result = engine.detect(input(text))
        assertTrue("Expected service termination signal, got ${ruleIds(result)}", hasRule(result, "susp_005"))
        assertTrue("Expected account blocked today signal, got ${ruleIds(result)}", hasRule(result, "urg_002"))
        assertTrue("Expected pay immediately signal, got ${ruleIds(result)}", hasRule(result, "pay_001"))
        assertTrue(categories(result).contains(RuleCategory.ACCOUNT_SUSPENSION))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
    }

    @Test
    fun courierDeliveryFeeScamSms() {
        // Representative courier delivery fee scam SMS.
        val text = "Your courier delivery is held. Pay a processing fee of Rs 200 to release your package. Pay now to avoid return to sender."
        val result = engine.detect(input(text))
        assertTrue("Expected processing fee signal, got ${ruleIds(result)}", hasRule(result, "pay_003"))
        assertTrue("Expected pay now to avoid signal, got ${ruleIds(result)}", hasRule(result, "pay_006"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
    }

    @Test
    fun otpTheftSms() {
        // Representative OTP theft SMS.
        val text = "Your OTP verification is required. Share your OTP with our agent to verify your bank account. Enter your password to complete."
        val result = engine.detect(input(text))
        assertTrue("Expected share your OTP signal, got ${ruleIds(result)}", hasRule(result, "cred_003"))
        assertTrue("Expected enter your password signal, got ${ruleIds(result)}", hasRule(result, "cred_001"))
        assertTrue(categories(result).contains(RuleCategory.CREDENTIAL_REQUEST))
    }

    @Test
    fun fakeLoanProcessingFeeSms() {
        // Representative fake loan processing fee scam SMS.
        val text = "Congratulations! Your loan is approved. Pay a processing fee of Rs 2000 to disburse funds. Transfer money immediately to avoid cancellation."
        val result = engine.detect(input(text))
        assertTrue("Expected processing fee signal, got ${ruleIds(result)}", hasRule(result, "pay_003"))
        assertTrue("Expected transfer funds immediately signal, got ${ruleIds(result)}", hasRule(result, "pay_008"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
    }

    // ---- Legitimate banking messages (false positive resistance) ----

    @Test
    fun legitimateBankTransactionAlertDoesNotTrigger() {
        // Legitimate transaction alert: mentions bank, account, payment but no coercion/credential demand.
        val text = "Your account ending in 4321 was credited with Rs 2,500.00 on 12-Jan-2024. Available balance: Rs 12,450.00."
        val result = engine.detect(input(text))
        assertEquals("Expected no signals for legitimate transaction alert, got ${ruleIds(result)}", 0, result.signalCount)
    }

    @Test
    fun legitimateOtpNotificationDoesNotTriggerCredentialRule() {
        // Legitimate OTP notification (bank sends OTP, does not ask for it).
        val text = "Your OTP for login is 123456. Do not share this OTP with anyone. Bank will never ask for your OTP."
        val result = engine.detect(input(text))
        // The message warns against sharing OTP and does not request credentials or payment.
        assertFalse("cred_003 should not fire on OTP warning message, got ${ruleIds(result)}", hasRule(result, "cred_003"))
        assertFalse("cred_001 should not fire on OTP warning message, got ${ruleIds(result)}", hasRule(result, "cred_001"))
    }

    @Test
    fun legitimatePaymentNotificationDoesNotTrigger() {
        val text = "UPI payment of Rs 500.00 received from Ramesh Kumar. Transaction ID: UPI123456789. Amount credited to your account."
        val result = engine.detect(input(text))
        assertEquals("Expected no signals for legitimate UPI credit, got ${ruleIds(result)}", 0, result.signalCount)
    }

    @Test
    fun legitimateBankKycReminderWithoutThreatDoesNotTriggerSuspension() {
        // A legitimate KYC reminder that states facts without threats or demands.
        val text = "KYC documents are required for all accounts as per RBI guidelines. Visit your branch with valid ID proof."
        val result = engine.detect(input(text))
        // "kyc" alone without "expiration", "expired", or "required immediately" should not fire susp_003.
        assertFalse("susp_003 should not fire on factual KYC reminder, got ${ruleIds(result)}", hasRule(result, "susp_003"))
        assertEquals("Expected no signals for factual KYC reminder, got ${ruleIds(result)}", 0, result.signalCount)
    }

    // ---- Case insensitivity ----

    @Test
    fun mixedCaseMatching() {
        val result = engine.detect(input("IMMEDIATE ACTION REQUIRED on your ACCOUNT."))
        assertTrue("Expected urg_001 for uppercase input, got ${ruleIds(result)}", hasRule(result, "urg_001"))
    }

    @Test
    fun mixedCaseCredentialMatching() {
        val result = engine.detect(input("Share Your OtP With Us Now."))
        assertTrue("Expected cred_003 for mixed case input, got ${ruleIds(result)}", hasRule(result, "cred_003"))
    }

    // ---- Punctuation variations ----

    @Test
    fun punctuationVariationsAreTolerated() {
        val result = engine.detect(input("Act, within 24 hours! Or else..."))
        assertTrue("Expected urg_004 despite punctuation, got ${ruleIds(result)}", hasRule(result, "urg_004"))
    }

    @Test
    fun punctuationVariationsCredential() {
        val result = engine.detect(input("Enter your password... now!"))
        assertTrue("Expected cred_001 despite punctuation, got ${ruleIds(result)}", hasRule(result, "cred_001"))
    }

    // ---- Whitespace variations ----

    @Test
    fun extraWhitespaceIsTolerated() {
        val result = engine.detect(input("Act   within   24   hours   to   avoid   penalties."))
        assertTrue("Expected urg_004 despite extra whitespace, got ${ruleIds(result)}", hasRule(result, "urg_004"))
    }

    @Test
    fun newlineAndTabWhitespaceIsTolerated() {
        val result = engine.detect(input("Share\tyour\nOTP\nwith\nus."))
        assertTrue("Expected cred_003 despite newline/tab whitespace, got ${ruleIds(result)}", hasRule(result, "cred_003"))
    }

    // ---- Unicode and invisible characters ----

    @Test
    fun unicodeTextIsHandled() {
        val text = "Your \u092E\u0930\u094D\u092A\u093E\u0924 account will be blocked today." // Hindi "bank" in Devanagari + urgency phrase
        val result = engine.detect(input(text))
        // Urgency phrase in English should still be detected.
        assertTrue("Expected urg_002 for mixed Unicode text, got ${ruleIds(result)}", hasRule(result, "urg_002"))
    }

    @Test
    fun invisibleCharactersDoNotBreakMatching() {
        // Zero-width space between words should not prevent phrase matching after punctuation stripping.
        val text = "Act\u200Bwithin\u200B24\u200Bhours to avoid issues."
        val result = engine.detect(input(text))
        assertTrue("Expected urg_004 despite zero-width spaces, got ${ruleIds(result)}", hasRule(result, "urg_004"))
        // Original input must be preserved with invisible characters.
        val inputWithOriginal = AnalysisInput(messageText = text, normalizedText = text)
        assertEquals(text, inputWithOriginal.messageText)
    }

    @Test
    fun zeroWidthCharactersRecordedButNotRemovedFromOriginal() {
        val text = "Hello\u200BWorld"
        val inputObj = AnalysisInput(messageText = text)
        val result = engine.detect(inputObj)
        assertEquals(text, inputObj.messageText)
    }

    // ---- Empty messages ----

    @Test
    fun emptyMessageReturnsNoSignals() {
        val result = engine.detect(input(""))
        assertEquals(0, result.signalCount)
        assertFalse(result.hasSignals())
    }

    @Test
    fun whitespaceOnlyMessageReturnsNoSignals() {
        val result = engine.detect(input("   \n\t  "))
        assertEquals(0, result.signalCount)
        assertFalse(result.hasSignals())
    }

    // ---- Long messages ----

    @Test
    fun longMessageIsHandledWithoutCrash() {
        val longText = "x".repeat(50_000) + " Share your OTP with us immediately."
        val result = engine.detect(input(longText))
        assertTrue("Expected cred_003 in long message, got ${ruleIds(result)}", hasRule(result, "cred_003"))
    }

    @Test
    fun longMessageWithNoSignals() {
        val longText = "Your account ending in 4321 was credited with Rs 2,500.00 on 12-Jan-2024. ".repeat(2000)
        val result = engine.detect(input(longText))
        assertEquals("Expected no signals for long legitimate text, got ${ruleIds(result)}", 0, result.signalCount)
    }

    // ---- Duplicate detection prevention ----

    @Test
    fun duplicateSignalsAreSuppressed() {
        // Same phrase repeated multiple times should produce one signal per rule.
        val text = "Share your OTP with us. Share your OTP with us. Share your OTP with us."
        val result = engine.detect(input(text))
        val cred003Signals = result.signals.filter { it.ruleId == "cred_003" }
        assertEquals("Expected exactly 1 cred_003 signal (deduped), got ${cred003Signals.size}", 1, cred003Signals.size)
    }

    @Test
    fun differentRulesCanFireIndependently() {
        // Different rules on the same text each produce a signal.
        val text = "Share your OTP immediately. Act within 24 hours. Pay now to avoid suspension."
        val result = engine.detect(input(text))
        assertTrue("Expected at least 3 signals from different rules, got ${result.signalCount}", result.signalCount >= 3)
        assertTrue(hasRule(result, "cred_003"))
        assertTrue(hasRule(result, "urg_004"))
        assertTrue(hasRule(result, "pay_006"))
    }

    // ---- Result properties ----

    @Test
    fun resultHasDetectorMetadata() {
        val result = engine.detect(input("Share your OTP immediately."))
        assertEquals("FastRuleEngine", result.detectorId)
        assertEquals("1.0.0", result.detectorVersion)
    }

    @Test
    fun resultSignalPropertiesAreComplete() {
        val result = engine.detect(input("Your account will be blocked today."))
        assertTrue(result.hasSignals())
        val signal = result.signals.first { it.ruleId == "urg_002" }
        assertSignalProperties(signal, "urg_002")
        assertEquals(RuleCategory.URGENCY_AND_COERCION, signal.category)
        assertEquals(DetectionSeverity.HIGH, signal.severity)
    }

    @Test
    fun categoriesDetectedReflectsSignals() {
        val result = engine.detect(input("Share your OTP immediately. Pay now."))
        assertTrue(categories(result).contains(RuleCategory.CREDENTIAL_REQUEST))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertFalse(categories(result).contains(RuleCategory.ACCOUNT_SUSPENSION))
    }

    @Test
    fun noVerdictIsGenerated() {
        // FastRuleEngine must not produce a verdict; RuleDetectionResult has
        // no verdict field by design. Verification is structural: the result
        // carries only signals and detector metadata, and AnalysisResult is
        // never constructed or modified by this engine.
        val result = engine.detect(input("Share your OTP immediately."))
        assertNotNull(result.signals)
        assertNotNull(result.detectorId)
        assertNotNull(result.detectorVersion)
        assertEquals("FastRuleEngine", result.detectorId)
        assertEquals("1.0.0", result.detectorVersion)
        // RuleDetectionResult intentionally exposes no verdict property; its
        // public API is limited to signals + detector metadata.
    }

    @Test
    fun zeroWidthCharactersInsideWordsDoNotHideOtpRequest() {
        val text = "Sh​are yo‌ur O‍TP to un⁠block your acc​ount"
        val input = com.arm.threatassistant.domain.normalization.InputNormalizer.normalize(AnalysisInput(messageText = text))
        val result = FastRuleEngine.detect(input)
        assertTrue(result.signals.any { it.ruleId == "cred_003" })
    }

    // ---- Roadmap 2.5: scam-rule gap coverage ----

    @Test
    fun otpOrPinSharingWithoutArticleIsDetected() {
        val result = engine.detect(input("Dear user, send OTP to 9876543210 to verify your reward."))
        assertTrue("Expected cred_009, got ${ruleIds(result)}", hasRule(result, "cred_009"))
        assertTrue(categories(result).contains(RuleCategory.CREDENTIAL_REQUEST))
        assertEquals(DetectionSeverity.HIGH, result.signals.first { it.ruleId == "cred_009" }.severity)
    }

    @Test
    fun upiCollectRequestTrickIsDetected() {
        val result = engine.detect(input("Approve the request to receive Rs 2000. Enter pin to receive money."))
        assertTrue("Expected pay_009, got ${ruleIds(result)}", hasRule(result, "pay_009"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertEquals(DetectionSeverity.HIGH, result.signals.first { it.ruleId == "pay_009" }.severity)
    }

    @Test
    fun apkInstallLureIsDetected() {
        val result = engine.detect(input("Download the APK and install this app to update KYC."))
        assertTrue("Expected cred_010, got ${ruleIds(result)}", hasRule(result, "cred_010"))
        assertTrue(categories(result).contains(RuleCategory.CREDENTIAL_REQUEST))
        assertEquals(DetectionSeverity.HIGH, result.signals.first { it.ruleId == "cred_010" }.severity)
    }

    @Test
    fun digitalArrestThreatIsDetected() {
        val result = engine.detect(input("This is a CBI officer. A digital arrest warrant is issued because narcotics found in your parcel."))
        assertTrue("Expected urg_008, got ${ruleIds(result)}", hasRule(result, "urg_008"))
        assertTrue(categories(result).contains(RuleCategory.URGENCY_AND_COERCION))
        assertEquals(DetectionSeverity.HIGH, result.signals.first { it.ruleId == "urg_008" }.severity)
    }

    @Test
    fun refundTrickIsDetected() {
        val result = engine.detect(input("Your refund has been initiated. Click here to claim your refund now."))
        assertTrue("Expected pay_010, got ${ruleIds(result)}", hasRule(result, "pay_010"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertEquals(DetectionSeverity.MEDIUM, result.signals.first { it.ruleId == "pay_010" }.severity)
    }

    @Test
    fun taskOrProfitGroupScamIsDetected() {
        val result = engine.detect(input("Part time job offer: earn Rs 500 daily income by liking YouTube videos on our telegram task."))
        assertTrue("Expected pay_011, got ${ruleIds(result)}", hasRule(result, "pay_011"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertEquals(DetectionSeverity.MEDIUM, result.signals.first { it.ruleId == "pay_011" }.severity)
    }

    @Test
    fun electricityDisconnectionThreatIsDetected() {
        val result = engine.detect(input("Electricity will be disconnected tonight. Pay now to keep your power on."))
        assertTrue("Expected susp_008, got ${ruleIds(result)}", hasRule(result, "susp_008"))
        assertTrue(categories(result).contains(RuleCategory.ACCOUNT_SUSPENSION))
        assertEquals(DetectionSeverity.HIGH, result.signals.first { it.ruleId == "susp_008" }.severity)
    }

    @Test
    fun courierCustomsFeeScamIsDetected() {
        val result = engine.detect(input("Your parcel is on hold due to customs duty. Update your address to release it."))
        assertTrue("Expected pay_012, got ${ruleIds(result)}", hasRule(result, "pay_012"))
        assertTrue(categories(result).contains(RuleCategory.PAYMENT_DEMAND))
        assertEquals(DetectionSeverity.MEDIUM, result.signals.first { it.ruleId == "pay_012" }.severity)
    }

    @Test
    fun hinglishUrgencyIsDetected() {
        val result = engine.detect(input("Aapka account band ho jayega. Turant KYC update karein."))
        assertTrue("Expected urg_009, got ${ruleIds(result)}", hasRule(result, "urg_009"))
        assertTrue(categories(result).contains(RuleCategory.URGENCY_AND_COERCION))
        assertEquals(DetectionSeverity.MEDIUM, result.signals.first { it.ruleId == "urg_009" }.severity)
    }

    @Test
    fun legitimateOtpSmsProducesNoHighSignal() {
        val result = engine.detect(input("Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank"))
        val highSignals = result.signals.filter { it.severity == DetectionSeverity.HIGH }
        assertTrue("Expected no HIGH signal, got ${highSignals.map { it.ruleId }}", highSignals.isEmpty())
        assertFalse("cred_009 should not fire on an OTP notification", hasRule(result, "cred_009"))
    }

    @Test
    fun legitimateParcelDeliverySmsProducesNoHighSignal() {
        val result = engine.detect(input("Your parcel was delivered today. Thanks for shopping."))
        assertTrue(
            "Expected no HIGH signal, got ${result.signals.filter { it.severity == DetectionSeverity.HIGH }.map { it.ruleId }}",
            result.signals.none { it.severity == DetectionSeverity.HIGH }
        )
        assertFalse(hasRule(result, "pay_012"))
    }

    @Test
    fun legitimateElectricityPaidSmsProducesNoHighSignal() {
        val result = engine.detect(input("Electricity bill of Rs 820 paid successfully."))
        assertTrue(
            "Expected no HIGH signal, got ${result.signals.filter { it.severity == DetectionSeverity.HIGH }.map { it.ruleId }}",
            result.signals.none { it.severity == DetectionSeverity.HIGH }
        )
        assertFalse(hasRule(result, "susp_008"))
    }

    @Test
    fun sbiKycOtpScamProducesCredentialRequestSignal() {
        val text = "Dear SBI customer, your KYC expires today. Share OTP to avoid account block"
        val result = engine.detect(input(text))
        assertTrue(
            "Expected a CREDENTIAL_REQUEST signal, got ${ruleIds(result)}",
            result.signals.any { it.category == RuleCategory.CREDENTIAL_REQUEST }
        )
        assertTrue("Expected cred_009, got ${ruleIds(result)}", hasRule(result, "cred_009"))
    }

    @Test
    fun bankWarningNotToShareOtpIsNotACredentialRequest() {
        for (text in listOf(
            "Your OTP is 482913. Never share OTP with anyone. -SBI",
            "Do not share OTP or PIN with anyone, bank never asks for it.",
            "Don't share OTP with callers. -HDFC Bank"
        )) {
            val result = engine.detect(input(text))
            assertFalse("Unexpected cred_009 for '$text'", hasRule(result, "cred_009"))
        }
    }

    @Test
    fun hinglishAapkaDoesNotTriggerApkRule() {
        val result = engine.detect(input("Namaste, aapka electricity bill Rs 3,842 generate ho gaya hai."))
        assertFalse("Unexpected cred_010, got ${ruleIds(result)}", hasRule(result, "cred_010"))
        val scam = engine.detect(input("Download SBI Rewards.apk now to redeem points"))
        assertTrue("Expected cred_010, got ${ruleIds(scam)}", hasRule(scam, "cred_010"))
    }
}
