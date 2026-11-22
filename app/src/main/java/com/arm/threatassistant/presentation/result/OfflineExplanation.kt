package com.arm.threatassistant.presentation.result

import android.content.Context
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel

/**
 * The fixed localized explanation shown to users when the Llama feature is off
 * or unavailable, built from the same [ReasonMapper] reasons shown under "Why
 * we think so". Also supplies the "What to do" items used by [AdviceGuard].
 */
object OfflineExplanation {

    fun build(context: Context, reasons: List<ReasonId>): String {
        if (reasons.isEmpty()) return ""
        if (ReasonId.UPI_PAYMENT_MISMATCH in reasons) return context.getString(R.string.upi_mismatch_explanation)
        val separator = context.getString(R.string.offline_explanation_separator)
        val joined = reasons.joinToString(separator) { context.getString(it.labelRes) }
        return context.getString(R.string.offline_explanation_template, joined)
    }

    fun safeStepsFor(context: Context, verdict: ThreatVerdictLevel, reasons: List<ReasonId> = emptyList()): List<String> {
        if (ReasonId.UPI_PAYMENT_MISMATCH in reasons) {
            return listOf(
                context.getString(R.string.action_upi_decline),
                context.getString(R.string.action_upi_verify),
                context.getString(R.string.action_upi_paid)
            )
        }
        if (ReasonId.SECRET_DISCLOSURE in reasons) {
            return listOf(
                context.getString(R.string.action_disclosure_private),
                context.getString(R.string.action_disclosure_verify),
                context.getString(R.string.action_disclosure_shared)
            )
        }
        val specific = when (verdict) {
            ThreatVerdictLevel.HIGH_RISK -> listOf(
                context.getString(R.string.action_high_risk_1),
                context.getString(R.string.action_high_risk_2),
                context.getString(R.string.action_high_risk_3)
            )
            ThreatVerdictLevel.SUSPICIOUS -> listOf(
                context.getString(R.string.action_suspicious_1),
                context.getString(R.string.action_suspicious_2),
                context.getString(R.string.action_suspicious_3)
            )
            ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> listOf(
                context.getString(R.string.action_insufficient_1),
                context.getString(R.string.action_insufficient_2),
                context.getString(R.string.action_safe_1)
            )
            ThreatVerdictLevel.SAFE -> listOf(
                context.getString(R.string.action_safe_1),
                context.getString(R.string.action_suspicious_2),
                context.getString(R.string.action_suspicious_3)
            )
        }
        return specific.distinct().take(3)
    }
}
