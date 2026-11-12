package com.arm.threatassistant.sms

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsAlertPolicyTest {

    @Test
    fun `high risk alerts`() {
        assertTrue(SmsAlertPolicy.shouldAlert(ThreatVerdictLevel.HIGH_RISK))
    }

    @Test
    fun `suspicious alerts`() {
        assertTrue(SmsAlertPolicy.shouldAlert(ThreatVerdictLevel.SUSPICIOUS))
    }

    @Test
    fun `safe stays silent`() {
        assertFalse(SmsAlertPolicy.shouldAlert(ThreatVerdictLevel.SAFE))
    }

    @Test
    fun `insufficient evidence stays silent`() {
        assertFalse(SmsAlertPolicy.shouldAlert(ThreatVerdictLevel.INSUFFICIENT_EVIDENCE))
    }
}
