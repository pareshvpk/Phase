package com.arm.threatassistant.presentation.result

import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity
import com.arm.threatassistant.domain.detection.ruleengine.RuleCategory
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionCategory
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionSeverity

/**
 * Short, plain-language reasons shown under "Why we think so".
 *
 * The mapper is deliberately independent of Android resources so it can be
 * unit-tested. [labelRes] keeps the string lookup next to the mapping.
 */
enum class ReasonId {
    UPI_PAYMENT_MISMATCH,
    SECRET_DISCLOSURE,
    CREDENTIAL_REQUEST,
    FINANCIAL_IMPERSONATION,
    PAYMENT_DEMAND,
    ACCOUNT_SUSPENSION,
    URGENCY_AND_COERCION,
    FAKE_LINK,
    FAKE_WEBSITE,
    SHORT_LINK,
    UNUSUAL_LINK,
    SCAM_WORDING;

    /** Stable identifier persisted with same-day alerts. */
    val stableId: String
        get() = name

    companion object {
        fun fromId(id: String?): ReasonId? = entries.firstOrNull { it.name == id }
    }
}

val ReasonId.labelRes: Int
    get() = when (this) {
        ReasonId.UPI_PAYMENT_MISMATCH -> R.string.reason_upi_mismatch
        ReasonId.SECRET_DISCLOSURE -> R.string.reason_disclosure
        ReasonId.CREDENTIAL_REQUEST -> R.string.reason_credential
        ReasonId.FINANCIAL_IMPERSONATION -> R.string.reason_financial
        ReasonId.PAYMENT_DEMAND -> R.string.reason_payment
        ReasonId.ACCOUNT_SUSPENSION -> R.string.reason_suspension
        ReasonId.URGENCY_AND_COERCION -> R.string.reason_urgency
        ReasonId.FAKE_LINK -> R.string.reason_fake_link
        ReasonId.FAKE_WEBSITE -> R.string.reason_fake_website
        ReasonId.SHORT_LINK -> R.string.reason_short_link
        ReasonId.UNUSUAL_LINK -> R.string.reason_unusual_link
        ReasonId.SCAM_WORDING -> R.string.reason_scam_wording
    }

/**
 * Converts detection evidence into at most three user-facing reasons.
 *
 * Reasons are de-duplicated, ordered by the strongest matching signal severity,
 * and then by a fixed harm priority so the order is deterministic.
 */
object ReasonMapper {

    const val MAX_REASONS = 3

    fun map(
        ruleResult: RuleDetectionResult?,
        urlResult: UrlDetectionResult?,
        classifierResult: SmsClassifierResult?
    ): List<ReasonId> {
        val severities = mutableMapOf<ReasonId, Int>()

        ruleResult?.signals?.forEach { signal ->
            val reason = when (signal.ruleId) {
                "cred_003", "cred_004", "cred_006", "cred_009" -> ReasonId.SECRET_DISCLOSURE
                else -> if (signal.isUpiPaymentMismatch) ReasonId.UPI_PAYMENT_MISMATCH else signal.category.toReason()
            }
            severities[reason] = maxOf(severities[reason] ?: 0, signal.severity.rank())
        }
        urlResult?.signals?.forEach { signal ->
            val reason = signal.category.toReason()
            severities[reason] = maxOf(severities[reason] ?: 0, signal.severity.rank())
        }

        if (severities.isEmpty() && classifierResult?.isThreat == true) {
            severities[ReasonId.SCAM_WORDING] = 1
        }

        if (ReasonId.SECRET_DISCLOSURE in severities) severities.remove(ReasonId.CREDENTIAL_REQUEST)
        if (ReasonId.UPI_PAYMENT_MISMATCH in severities) severities.remove(ReasonId.PAYMENT_DEMAND)
        return severities.entries
            .sortedWith(
                compareByDescending<Map.Entry<ReasonId, Int>> { it.value }
                    .thenByDescending { it.key.priority }
            )
            .map { it.key }
            .take(MAX_REASONS)
    }
}

private fun RuleCategory.toReason(): ReasonId = when (this) {
    RuleCategory.URGENCY_AND_COERCION -> ReasonId.URGENCY_AND_COERCION
    RuleCategory.CREDENTIAL_REQUEST -> ReasonId.CREDENTIAL_REQUEST
    RuleCategory.FINANCIAL_IMPERSONATION -> ReasonId.FINANCIAL_IMPERSONATION
    RuleCategory.PAYMENT_DEMAND -> ReasonId.PAYMENT_DEMAND
    RuleCategory.ACCOUNT_SUSPENSION -> ReasonId.ACCOUNT_SUSPENSION
}

private fun UrlDetectionCategory.toReason(): ReasonId = when (this) {
    UrlDetectionCategory.SUSPICIOUS_TLD,
    UrlDetectionCategory.SUSPICIOUS_DOMAIN,
    UrlDetectionCategory.SUSPICIOUS_SUBDOMAIN,
    UrlDetectionCategory.HOMOGRAPH_ATTACK,
    UrlDetectionCategory.MISLEADING_STRUCTURE -> ReasonId.FAKE_LINK

    UrlDetectionCategory.ML_PHISHING_HOST -> ReasonId.FAKE_WEBSITE

    UrlDetectionCategory.URL_SHORTENER -> ReasonId.SHORT_LINK

    UrlDetectionCategory.IP_BASED_URL,
    UrlDetectionCategory.UNUSUAL_PORT,
    UrlDetectionCategory.ENCODED_CHARACTERS,
    UrlDetectionCategory.EXCESSIVE_LENGTH -> ReasonId.UNUSUAL_LINK
}

private fun DetectionSeverity.rank(): Int = when (this) {
    DetectionSeverity.LOW -> 1
    DetectionSeverity.MEDIUM -> 2
    DetectionSeverity.HIGH -> 3
}

private fun UrlDetectionSeverity.rank(): Int = when (this) {
    UrlDetectionSeverity.LOW -> 1
    UrlDetectionSeverity.MEDIUM -> 2
    UrlDetectionSeverity.HIGH -> 3
}

private val ReasonId.priority: Int
    get() = when (this) {
        ReasonId.UPI_PAYMENT_MISMATCH -> 102
        ReasonId.SECRET_DISCLOSURE -> 101
        ReasonId.CREDENTIAL_REQUEST -> 100
        ReasonId.FINANCIAL_IMPERSONATION -> 90
        ReasonId.PAYMENT_DEMAND -> 80
        ReasonId.ACCOUNT_SUSPENSION -> 70
        ReasonId.URGENCY_AND_COERCION -> 60
        ReasonId.FAKE_LINK -> 55
        ReasonId.FAKE_WEBSITE -> 56
        ReasonId.SHORT_LINK -> 50
        ReasonId.UNUSUAL_LINK -> 40
        ReasonId.SCAM_WORDING -> 10
    }
