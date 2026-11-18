package com.arm.threatassistant.sms

/**
 * Roadmap 2.6 — recognition of registered Indian business (DLT) senders.
 *
 * Indian businesses send SMS from TRAI DLT headers such as `AX-HDFCBK`,
 * `VM-SBIINB`, `JD-AMAZON-T` or `BZ-PAYTMB-S`. Their genuine messages often
 * contain links, so link-only signals must not raise a false alert for them.
 *
 * A header is `^[A-Z]{2}-[A-Z0-9]{5,9}(-[A-Z])?$` after trimming and
 * upper-casing. Phone numbers (`+91…`, plain digits) and blank/null input are
 * never business headers.
 */
object RegisteredSender {

    private val BUSINESS_HEADER = Regex("^[A-Z]{2}-[A-Z0-9]{5,9}(-[A-Z])?$")

    fun isBusinessHeader(sender: String?): Boolean {
        if (sender == null) return false
        val normalized = sender.trim().uppercase()
        if (normalized.isEmpty()) return false
        return BUSINESS_HEADER.matches(normalized)
    }
}
