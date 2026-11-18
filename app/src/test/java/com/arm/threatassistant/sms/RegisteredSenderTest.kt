package com.arm.threatassistant.sms

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RegisteredSenderTest {

    @Test
    fun `valid DLT business headers are recognised`() {
        assertTrue(RegisteredSender.isBusinessHeader("AX-HDFCBK"))
        assertTrue(RegisteredSender.isBusinessHeader("VM-SBIINB"))
        assertTrue(RegisteredSender.isBusinessHeader("JD-AMAZON-T"))
        assertTrue(RegisteredSender.isBusinessHeader("BZ-PAYTMB-S"))
    }

    @Test
    fun `headers are trimmed and upper cased before matching`() {
        assertTrue(RegisteredSender.isBusinessHeader("  AX-HDFCBK  "))
        assertTrue(RegisteredSender.isBusinessHeader("ax-hdfcbk"))
        assertTrue(RegisteredSender.isBusinessHeader("vm-sbiinb"))
        assertTrue(RegisteredSender.isBusinessHeader(" jd-amazon-t"))
    }

    @Test
    fun `phone numbers are not business headers`() {
        assertFalse(RegisteredSender.isBusinessHeader("+919876543210"))
        assertFalse(RegisteredSender.isBusinessHeader("9876543210"))
        assertFalse(RegisteredSender.isBusinessHeader("112"))
        assertFalse(RegisteredSender.isBusinessHeader("+91 98765 43210"))
    }

    @Test
    fun `null and blank senders are not business headers`() {
        assertFalse(RegisteredSender.isBusinessHeader(null))
        assertFalse(RegisteredSender.isBusinessHeader(""))
        assertFalse(RegisteredSender.isBusinessHeader("   "))
        assertFalse(RegisteredSender.isBusinessHeader("\t"))
    }

    @Test
    fun `malformed headers are rejected`() {
        assertFalse(RegisteredSender.isBusinessHeader("A-HDFCBK"))
        assertFalse(RegisteredSender.isBusinessHeader("ABC-HDFCBK"))
        assertFalse(RegisteredSender.isBusinessHeader("AX-HDFC"))
        assertFalse(RegisteredSender.isBusinessHeader("AX-HDFCBKXYZW"))
        assertFalse(RegisteredSender.isBusinessHeader("AX-HDFCBK-XY"))
        assertFalse(RegisteredSender.isBusinessHeader("AXHDFCBK"))
        assertFalse(RegisteredSender.isBusinessHeader("AX-HDFCBK-1"))
        assertFalse(RegisteredSender.isBusinessHeader("HDFCBK"))
        assertFalse(RegisteredSender.isBusinessHeader("AX HCFBK"))
    }
}
