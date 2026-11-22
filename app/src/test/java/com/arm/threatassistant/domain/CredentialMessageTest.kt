package com.arm.threatassistant.domain

import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.detection.ruleengine.FastRuleEngine
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModelLoader
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.detection.urldetection.UrlSpecialistDetector
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.domain.normalization.InputNormalizer
import com.arm.threatassistant.presentation.result.ReasonId
import com.arm.threatassistant.presentation.result.ReasonMapper
import com.arm.threatassistant.presentation.result.RiskHighlighter
import com.arm.threatassistant.sms.SensitiveSmsFilter
import com.arm.threatassistant.sms.SmsAlertPolicy
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialMessageTest {
    private val classifier = SmsSpecialistClassifier.fromModel(
        SmsClassifierModelLoader.parse(File("src/main/assets/sms_classifier_model.json").readText())
    )

    @Test fun remindersAndRequestsThroughTheShippedDetector() {
        val cases = listOf(
            false to "Security reminder from the office. Never share your OTP, password or PIN with anyone.",
            false to "Your OTP is 482615. Do not share it with anyone.",
            false to "Never share your PIN with anyone.",
            false to "We never ask you to share your OTP.",
            false to "Apna OTP kisi ko mat bhejo.",
            false to "Security reminder: OTP share mat karo.",
            false to "Apna OTP kabhi share na karein.",
            true to "Someone is using your card. Reply with your OTP and PIN immediately to block the transaction.",
            true to "Never share your OTP with strangers. Share your OTP with our agent.",
            true to "Your OTP is 482615. Never share your OTP with anyone except our agent.",
            true to "Your OTP is 482615. Reply with the code to cancel this transaction.",
            true to "Aapka OTP 482615 hai. Apna OTP abhi bhejo.",
            true to "OTP share mat karo. Verification ke liye OTP share karo.",
            true to "Your OTP is 482615. Never share your PIN. Your account will be blocked. Verify at https://kyc-check.example/login"
        )
        val failures = mutableListOf<String>()
        for ((warning, message) in cases) {
            val input = InputNormalizer.normalize(AnalysisInput(messageText = message))
            val rules = FastRuleEngine.detect(input)
            val prediction = classifier.classify(input)
            val result = RiskPolicyEngine.assess(rules, prediction, UrlSpecialistDetector.detect(input), AnalysisStatus.COMPLETED)
            val warned = SmsAlertPolicy.shouldAlert(result.verdict)
            if (warned != warning || (warning && SensitiveSmsFilter.shouldSkip(message))) {
                failures += "$message -> ${result.verdict}, rules=${rules.signals.map { it.ruleId }}, " +
                    "classifier=${prediction.threatScore}, skipped=${SensitiveSmsFilter.shouldSkip(message)}"
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test fun highlightsOnlyTheActionableRequestAndSelectsDisclosureAdvice() {
        for ((text, expected) in listOf(
            "Never share your OTP. Share your OTP with our agent." to "Share your OTP",
            "OTP share mat karo. Verification ke liye OTP share karo." to "OTP share karo",
            "Reply with your OTP and PIN immediately." to "Reply with your OTP and PIN"
        )) {
            val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
            val spans = RiskHighlighter.spans(text, rules.signals.map { it.matchedText })
            assertEquals(listOf(expected), spans.map { text.substring(it.start, it.end) })
            assertEquals(text.lastIndexOf(expected, ignoreCase = true), spans.single().start)
            assertEquals(ReasonId.SECRET_DISCLOSURE, ReasonMapper.map(rules, null, null).first())
        }
    }
}
