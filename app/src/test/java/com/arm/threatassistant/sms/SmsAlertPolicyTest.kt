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

    @Test
    fun `non business sender behaves like the plain policy`() {
        val phone = "+919876543210"
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.HIGH_RISK, phone, false, false
            )
        )
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, phone, false, false
            )
        )
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SAFE, phone, true, true
            )
        )
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, phone, true, true
            )
        )
    }

    @Test
    fun `null and blank senders behave like the plain policy`() {
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, null, false, false
            )
        )
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, "   ", false, false
            )
        )
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SAFE, null, true, true
            )
        )
    }

    @Test
    fun `business header high risk always alerts`() {
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.HIGH_RISK, "AX-HDFCBK", false, false
            )
        )
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.HIGH_RISK, "jd-amazon-t", false, false
            )
        )
    }

    @Test
    fun `business header suspicious with high severity rule alerts`() {
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, "VM-SBIINB", true, false
            )
        )
    }

    @Test
    fun `business header suspicious with scam classifier alerts`() {
        assertTrue(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, "BZ-PAYTMB-S", false, true
            )
        )
    }

    @Test
    fun `business header suspicious from links only stays silent`() {
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SUSPICIOUS, "AX-HDFCBK", false, false
            )
        )
    }

    @Test
    fun `business header safe and insufficient stay silent`() {
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.SAFE, "AX-HDFCBK", true, true
            )
        )
        assertFalse(
            SmsAlertPolicy.shouldAlert(
                ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, "AX-HDFCBK", true, true
            )
        )
    }
}
