package com.arm.threatassistant.sms

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel

/**
 * Pure alerting policy for incoming SMS.
 *
 * Only messages with a [ThreatVerdictLevel.HIGH_RISK] or
 * [ThreatVerdictLevel.SUSPICIOUS] verdict produce a notification. SAFE and
 * INSUFFICIENT_EVIDENCE messages stay silent.
 */
object SmsAlertPolicy {

    fun shouldAlert(verdict: ThreatVerdictLevel): Boolean {
        return verdict == ThreatVerdictLevel.HIGH_RISK ||
            verdict == ThreatVerdictLevel.SUSPICIOUS
    }

    /**
     * Registered-sender aware overload (Roadmap 2.6).
     *
     * Senders that are not registered business headers behave exactly like
     * [shouldAlert]. For a registered DLT header a SUSPICIOUS verdict caused
     * only by link/URL signals stays silent: an alert requires a HIGH_RISK
     * verdict, or SUSPICIOUS backed by a high-severity rule signal or by the
     * classifier.
     */
    fun shouldAlert(
        verdict: ThreatVerdictLevel,
        sender: String?,
        hasHighSeverityRule: Boolean,
        classifierSaysScam: Boolean
    ): Boolean {
        if (!RegisteredSender.isBusinessHeader(sender)) {
            return shouldAlert(verdict)
        }
        return when (verdict) {
            ThreatVerdictLevel.HIGH_RISK -> true
            ThreatVerdictLevel.SUSPICIOUS -> hasHighSeverityRule || classifierSaysScam
            else -> false
        }
    }
}
