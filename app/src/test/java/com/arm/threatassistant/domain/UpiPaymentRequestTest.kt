package com.arm.threatassistant.domain

import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.detection.ruleengine.FastRuleEngine
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModelLoader
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.presentation.result.ReasonId
import com.arm.threatassistant.presentation.result.ReasonMapper
import com.arm.threatassistant.presentation.result.RiskHighlighter
import com.arm.threatassistant.sms.SensitiveSmsFilter
import com.arm.threatassistant.sms.SmsAlertPolicy
import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UpiPaymentRequestTest {
    private val classifier = SmsSpecialistClassifier.fromModel(
        SmsClassifierModelLoader.parse(File("src/main/assets/sms_classifier_model.json").readText())
    )

    @Test fun bothPhrasesExplainOneWarning() {
        val cases = listOf(
            Triple("₹500 cashback is waiting. Approve this ₹500 payment request to receive it.",
                "cashback is waiting", "Approve this ₹500 payment request"),
            Triple("₹500 cashback pending. Approve the ₹500 collect request to receive it.",
                "cashback pending", "Approve the ₹500 collect request"),
            Triple("Cashback lene ke liye UPI PIN daalo aur payment approve karo.",
                "Cashback lene ke liye", "UPI PIN daalo aur payment approve karo"),
            Triple("Approve the UPI request to receive your refund.",
                "Approve the UPI request", "to receive your refund"),
            Triple("₹500 refund pending. Please enter your UPI PIN.",
                "refund pending", "enter your UPI PIN")
        )
        for ((text, first, second) in cases) {
            val input = AnalysisInput(messageText = text)
            val rules = FastRuleEngine.detect(input)
            val evidence = rules.signals.single { it.ruleId == "pay_009" }
            val spans = RiskHighlighter.spans(text, emptyList(), evidence.originalRanges)
            assertEquals(text, listOf(first, second), spans.map { text.substring(it.start, it.end) })
            assertEquals(ReasonId.UPI_PAYMENT_MISMATCH, ReasonMapper.map(rules, null, null).first())
            assertFalse(text, SensitiveSmsFilter.shouldSkip(text))
            val result = RiskPolicyEngine.assess(rules, classifier.classify(input), null, AnalysisStatus.COMPLETED)
            assertTrue(text, SmsAlertPolicy.shouldAlert(result.verdict))
            assertEquals(evidence.description, result.evidenceSummary.first())
        }
    }

    @Test fun receiptsAndOrdinaryPaymentsStayQuiet() {
        for (text in listOf(
            "₹500 refund credited to your account. No action needed.",
            "Approve the collect request for your groceries.",
            "Refund aa gaya hai. Koi action zaroori nahi.",
            "Refund credited. Your electricity bill payment request is available in the app."
        )) {
            val input = AnalysisInput(messageText = text)
            val rules = FastRuleEngine.detect(input)
            val result = RiskPolicyEngine.assess(rules, classifier.classify(input), null, AnalysisStatus.COMPLETED)
            assertFalse("$text -> $result", SmsAlertPolicy.shouldAlert(result.verdict))
        }
    }

    @Test fun negatedObligationRemindersAreNotEvidence() {
        for (text in listOf(
            "You should never have to enter your UPI PIN to receive a refund.",
            "You do not have to approve the payment to receive your refund."
        )) {
            val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
            assertFalse(text, rules.signals.any { it.isUpiPaymentMismatch })
        }
    }

    @Test fun emphaticWarningOnPrivateOtpKeepsTheMessageOutOfAnalysis() {
        val text = "Your OTP is 482615. Don't ever enter your UPI PIN to receive a refund."
        assertTrue(SensitiveSmsFilter.shouldSkip(text))
        val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
        assertFalse(rules.signals.any { it.isUpiPaymentMismatch })
    }

    @Test fun positiveImperativeAfterNegatedReminderIsTheOnlyEvidence() {
        val reminder = "You should never have to enter your UPI PIN to receive a refund."
        val imperative = "Approve this payment request to receive your refund."
        val text = "$reminder $imperative"
        val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
        val evidence = rules.signals.single { it.ruleId == "pay_009" }
        val spans = RiskHighlighter.spans(text, emptyList(), evidence.originalRanges)
        assertEquals(
            listOf("Approve this payment request", "to receive your refund"),
            spans.map { text.substring(it.start, it.end) }
        )
        assertTrue(text, spans.all { it.start >= reminder.length })
    }

    @Test fun unrelatedWordsAfterNegationDoNotSuppressTheRealAction() {
        val text = "You do not have to wait, approve this payment request to receive your refund."
        val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
        val evidence = rules.signals.single { it.ruleId == "pay_009" }
        val spans = RiskHighlighter.spans(text, emptyList(), evidence.originalRanges)
        assertEquals(
            listOf("approve this payment request", "to receive your refund"),
            spans.map { text.substring(it.start, it.end) }
        )
    }

    @Test fun warningsAndUnrelatedClausesAreNotEvidenceOfAPaymentMismatch() {
        for (text in listOf(
            "Never enter your UPI PIN to receive a refund.",
            "You do not need to authorize a payment to receive a refund.",
            "We never ask you to approve the payment request to receive your refund.",
            "Refund pending. Do not approve this payment request.",
            "Cashback lene ke liye UPI PIN mat daalo.",
            "Refund pending. Your library books are ready. Approve this payment request for lunch.",
            "Approve the payment for groceries and earn cashback on your purchase.",
            "Refund pending. Enter your PIN to log in and view its status."
        )) {
            val rules = FastRuleEngine.detect(AnalysisInput(messageText = text))
            assertFalse(text, rules.signals.any { it.isUpiPaymentMismatch })
        }
    }
}
