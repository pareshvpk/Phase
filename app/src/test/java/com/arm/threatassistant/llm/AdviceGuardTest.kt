package com.arm.threatassistant.llm

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdviceGuardTest {

    private val fallback = "This message looks suspicious. Never share your OTP or PIN with anyone."
    private val safeSteps = listOf(
        "Don't click links or reply",
        "Never share your OTP or PIN",
        "Block and report the sender"
    )

    @Test
    fun refusalWithCannotIsReplacedByFallback() {
        val text = "I cannot provide an explanation of the risks of a specific message. " +
            "If you need help with messaging, I can provide general guidance. Would that help?"
        assertEquals(fallback, AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps))
    }

    @Test
    fun refusalWithCantIsReplacedByFallback() {
        val text = "I cannot provide information or guidance on how to respond to a high-risk message. " +
            "Is there something else I can help you with?"
        assertEquals(fallback, AdviceGuard.guard(text, ThreatVerdictLevel.SUSPICIOUS, "en", fallback, safeSteps))
    }

    @Test
    fun hindiVerdictContradictionIsReplacedByFallback() {
        val text = "इस संदेश को संदिग्ध नहीं है क्योंकि यह आपके संदेश को संदिग्ध नहीं है"
        assertEquals(fallback, AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "hi", fallback, safeSteps))
    }

    @Test
    fun goodOutputIsKeptAndStepsAreAppended() {
        val text = "This message threatens to block your SBI account and asks for your OTP. " +
            "Banks never ask for OTPs by SMS. Do not click the link or reply."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertTrue(result.contains("This message threatens to block your SBI account and asks for your OTP"))
        assertTrue(result.contains("Banks never ask for OTPs by SMS"))
        assertTrue(result.contains("Do not click the link or reply"))
        assertTrue(result.contains("1. Don't click links or reply"))
        assertTrue(result.contains("2. Never share your OTP or PIN"))
        assertTrue(result.contains("3. Block and report the sender"))
    }

    @Test
    fun clickSentenceIsDroppedNegatedClickIsKept() {
        val text = "Click the link now to verify your account. Do not click unknown links. Your account needs attention."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertFalse(result.contains("Click the link now to verify your account"))
        assertTrue(result.contains("Do not click unknown links"))
        assertTrue(result.contains("Your account needs attention"))
    }

    @Test
    fun hindiNegatedClickIsKept() {
        val text = "लिंक पर क्लिक न करें। ओटीपी साझा न करें। आपका फोन चार्ज पर है।"
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "hi", fallback, safeSteps)

        assertTrue(result.contains("लिंक पर क्लिक न करें"))
        assertTrue(result.contains("ओटीपी साझा न करें"))
        assertTrue(result.contains("आपका फोन चार्ज पर है"))
    }

    @Test
    fun hindiNonNegatedClickIsDropped() {
        val text = "लिंक पर क्लिक करें। आपका पैसा बैंक में है। फोन चार्ज पर है।"
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "hi", fallback, safeSteps)

        assertFalse(result.contains("लिंक पर क्लिक करें"))
        assertTrue(result.contains("आपका पैसा बैंक में है"))
        assertTrue(result.contains("फोन चार्ज पर है"))
    }

    @Test
    fun tamilNegatedClickIsKept() {
        val text = "இணைப்பை கிளிக் செய்ய வேண்டாம். நேற்று மழை பெய்தது."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "ta", fallback, safeSteps)

        assertTrue(result.contains("இணைப்பை கிளிக் செய்ய வேண்டாம்"))
        assertTrue(result.contains("நேற்று மழை பெய்தது"))
    }

    @Test
    fun tamilNonNegatedClickIsDropped() {
        val text = "இணைப்பை கிளிக் செய்யவும். நேற்று மழை பெய்தது. இன்று வானம் தெளிவாக உள்ளது."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "ta", fallback, safeSteps)

        assertFalse(result.contains("இணைப்பை கிளிக் செய்யவும்"))
        assertTrue(result.contains("நேற்று மழை பெய்தது"))
        assertTrue(result.contains("இன்று வானம் தெளிவாக உள்ளது"))
    }

    @Test
    fun urlAndPhoneSentencesAreDropped() {
        val text = "Visit http://scam.example.com now. Call +91-9876543210 immediately. " +
            "Your account needs attention. The sender is pretending to be your bank."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertFalse(result.contains("http://scam.example.com"))
        assertFalse(result.contains("+91-9876543210"))
        assertTrue(result.contains("Your account needs attention"))
    }

    @Test
    fun repeatedSentencesAreCollapsedToFallback() {
        val text = "Your account is at risk. Your account is at risk. Your account is at risk."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertEquals(fallback, result) // only one distinct sentence remains -> below the minimum
    }

    @Test
    fun absoluteClaimsAreSoftened() {
        val text = "This is 100% definitely a scam. It is guaranteed not to be safe."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertFalse(result.contains("100%"))
        assertFalse(result.contains("definitely"))
        assertFalse(result.contains("guaranteed"))
    }

    @Test
    fun safeStepsAreAppendedOnlyOnce() {
        val text = "This message threatens to block your SBI account and asks for your OTP. " +
            "Your account needs attention. The sender is pretending to be your bank."
        val first = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)
        val second = AdviceGuard.guard(first, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        // Steps are appended once to the guarded text.
        assertEquals(1, countOccurrences(first, "1. Don't click links or reply"))
        assertEquals(1, countOccurrences(first, "2. Never share your OTP or PIN"))
        assertEquals(1, countOccurrences(first, "3. Block and report the sender"))
        // Re-guarding does not duplicate them beyond a single occurrence each.
        assertTrue(countOccurrences(second, "Don't click links or reply") <= 1)
        assertTrue(countOccurrences(second, "Never share your OTP or PIN") <= 1)
        assertTrue(countOccurrences(second, "Block and report the sender") <= 1)
    }

    @Test
    fun tooFewSentencesReturnsFallback() {
        val text = "Click here now."
        assertEquals(fallback, AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps))
    }

    @Test
    fun realBulletAnswerIsKeptAndCleaned() {
        val text = "This message is HIGH_RISK because it:  * Threatens you with a serious situation (your KYC is about " +
            "to expire and your account will be blocked) * Requests sensitive information (your OTP) to update your " +
            "KYC * Uses a URL that may be fake or malicious (http://sbi-kyc-update.in/verify)  To stay safe, you " +
            "should:  * Do not respond to the message by sharing your OTP or clicking any links * Delete the message"
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)

        assertFalse(result == fallback)
        assertFalse(result.contains("*"))
        assertFalse(result.contains("http"))
        assertFalse(result.contains("HIGH_RISK"))
        assertTrue(result.contains("Threatens you with a serious situation"))
        assertTrue(result.contains("Delete the message"))
    }

    @Test
    fun cutOffBulletAnswerKeepsAbbreviationsAndQuotes() {
        val text = "This message is SUSPICIOUS because it: * Requests money for a prize you never entered " +
            "(e.g. \"Congratulations! You won Rs. 5,000\") * Pushes you to act quickly before a deadline *"
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.SUSPICIOUS, "en", fallback, safeSteps)

        assertFalse(result == fallback)
        assertFalse(result.contains("*"))
        assertFalse(result.contains("SUSPICIOUS"))
        assertTrue(result.contains("e.g. \"Congratulations! You won Rs. 5,000\""))
        assertTrue(result.contains("Pushes you to act quickly before a deadline."))
    }

    @Test
    fun stayingSafeIsNotAVerdictContradiction() {
        val text = "This message asks for your OTP. To stay safe, delete it and block the sender."
        val result = AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps)
        assertTrue(result.startsWith("This message asks for your OTP."))
    }

    @Test
    fun claimThatMessageIsSafeIsReplacedByFallback() {
        val text = "This message is safe. You can ignore the warning."
        assertEquals(fallback, AdviceGuard.guard(text, ThreatVerdictLevel.HIGH_RISK, "en", fallback, safeSteps))
    }

    private fun countOccurrences(text: String, needle: String): Int {
        var count = 0
        var index = text.indexOf(needle)
        while (index >= 0) {
            count += 1
            index = text.indexOf(needle, index + needle.length)
        }
        return count
    }
}
