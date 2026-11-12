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
}
