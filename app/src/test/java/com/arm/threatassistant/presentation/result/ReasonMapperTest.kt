package com.arm.threatassistant.presentation.result

import com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSignal
import com.arm.threatassistant.domain.detection.ruleengine.RuleCategory
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierStatus
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionCategory
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionSeverity
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReasonMapperTest {

    private fun ruleSignal(
        category: RuleCategory,
        severity: DetectionSeverity = DetectionSeverity.HIGH
    ) = DetectionSignal(
        signalId = "signal",
        category = category,
        ruleId = "rule",
        description = "description",
        matchedText = "text",
        severity = severity,
        detectorId = "detector",
        detectorVersion = "1"
    )

    private fun ruleResult(vararg signals: DetectionSignal) = RuleDetectionResult(
        signals = signals.toList(),
        detectorId = "detector",
        detectorVersion = "1"
    )

    private fun urlSignal(
        category: UrlDetectionCategory,
        severity: UrlDetectionSeverity = UrlDetectionSeverity.HIGH
    ) = UrlDetectionSignal(
        signalId = "signal",
        category = category,
        severity = severity,
        description = "description",
        matchedUrl = "https://example.test",
        matchedComponent = null,
        detectorId = "detector",
        detectorVersion = "1"
    )

    private fun urlResult(vararg signals: UrlDetectionSignal) = UrlDetectionResult(
        urls = emptyList(),
        signals = signals.toList(),
        detectorId = "detector",
        detectorVersion = "1"
    )

    private fun classifier(label: String?) = SmsClassifierResult(
        status = SmsClassifierStatus.AVAILABLE,
        predictedLabel = label,
        threatScore = 0.9,
        isCalibrated = false,
        modelVersion = "1",
        detectorId = "detector",
        detectorVersion = "1",
        contributingFeatures = null,
        errorMessage = null
    )

    @Test
    fun noEvidenceMeansNoReasons() {
        assertTrue(ReasonMapper.map(null, null, null).isEmpty())
        assertTrue(ReasonMapper.map(null, null, classifier("SAFE")).isEmpty())
    }

    @Test
    fun mapsRuleCategoriesToPlainReasons() {
        val reasons = ReasonMapper.map(
            ruleResult(
                ruleSignal(RuleCategory.URGENCY_AND_COERCION),
                ruleSignal(RuleCategory.CREDENTIAL_REQUEST),
                ruleSignal(RuleCategory.FINANCIAL_IMPERSONATION)
            ),
            null,
            null
        )

        assertEquals(
            listOf(
                ReasonId.CREDENTIAL_REQUEST,
                ReasonId.FINANCIAL_IMPERSONATION,
                ReasonId.URGENCY_AND_COERCION
            ),
            reasons
        )
    }

    @Test
    fun urlCategoriesAreGroupedAndDeduplicated() {
        val reasons = ReasonMapper.map(
            null,
            urlResult(
                urlSignal(UrlDetectionCategory.SUSPICIOUS_TLD),
                urlSignal(UrlDetectionCategory.HOMOGRAPH_ATTACK),
                urlSignal(UrlDetectionCategory.URL_SHORTENER),
                urlSignal(UrlDetectionCategory.IP_BASED_URL)
            ),
            null
        )

        assertEquals(
            listOf(ReasonId.FAKE_LINK, ReasonId.SHORT_LINK, ReasonId.UNUSUAL_LINK),
            reasons
        )
    }

    @Test
    fun ordersByStrongestSignalSeverityThenHarmPriority() {
        val reasons = ReasonMapper.map(
            ruleResult(
                ruleSignal(RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.LOW),
                ruleSignal(RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.HIGH),
                ruleSignal(RuleCategory.PAYMENT_DEMAND, DetectionSeverity.MEDIUM)
            ),
            null,
            null
        )

        assertEquals(
            listOf(
                ReasonId.URGENCY_AND_COERCION,
                ReasonId.PAYMENT_DEMAND,
                ReasonId.ACCOUNT_SUSPENSION
            ),
            reasons
        )
    }

    @Test
    fun capsAtThreeReasons() {
        val reasons = ReasonMapper.map(
            ruleResult(
                ruleSignal(RuleCategory.URGENCY_AND_COERCION),
                ruleSignal(RuleCategory.CREDENTIAL_REQUEST),
                ruleSignal(RuleCategory.FINANCIAL_IMPERSONATION),
                ruleSignal(RuleCategory.PAYMENT_DEMAND),
                ruleSignal(RuleCategory.ACCOUNT_SUSPENSION)
            ),
            null,
            null
        )

        assertEquals(ReasonMapper.MAX_REASONS, reasons.size)
    }

    @Test
    fun classifierWordingIsOnlyUsedWhenThereIsNoOtherReason() {
        val fallback = ReasonMapper.map(null, null, classifier("THREAT"))
        assertEquals(listOf(ReasonId.SCAM_WORDING), fallback)

        val withRuleReason = ReasonMapper.map(
            ruleResult(ruleSignal(RuleCategory.CREDENTIAL_REQUEST)),
            null,
            classifier("THREAT")
        )
        assertFalse(withRuleReason.contains(ReasonId.SCAM_WORDING))
    }
}
