package com.arm.threatassistant.sms

/**
 * Classifies legitimate private SMS that can be dropped before analysis.
 *
 * OTP, transaction and credential messages are always dropped before
 * analysis. There are two exceptions, and such a message is still
 * analyzed:
 * 1. the message asks the user to share/send a code, PIN or password;
 * 2. the message contains a link together with reward wording
 *    (receive, claim, win, prize...).
 */
object SensitiveSmsFilter {

    private val SECRET_REQUEST = Regex(
        """(share|send|forward|tell|provide|give|submit|enter|reply with)\b.{0,40}\b(otp|code|pin|password|cvv|passcode)"""
    )
    private val NEGATED_PREFIX = Regex("""(do not|don't|dont|never|not)\s+$""")
    private val LINK = Regex("""https?://|www\.|\b[a-z0-9-]+\.(com|in|net|org|info|xyz|top|link|co|io|ly|me|app|site|online|click|live|shop|cc|ru|cn|tk)\b""")
    private val REWARD_LURE = Regex("""\b(receive|claim|redeem|collect|win|won|winner|prize|lottery|reward|rewards|gift|bonus|free|jackpot|lucky)\b""")

    private val OTP_KEYWORDS = listOf(
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "security code",
        "login code",
        "auth code",
        "authentication code",
        "passcode",
        "2fa",
        "is your code",
        "code is"
    )
    private val OTP_CODE_WORD = Regex("""\bcode\b""")
    private val OTP_CODE = Regex("""\b\d{4,8}\b|\b\d{3}[- ]\d{3}\b""")
    private val CREDENTIALS = Regex(
        """\b(password|passwd|pwd|username|user id|userid|login id|mpin|tpin|temporary password|pin)\s*(is|:|-|=)\s*\S+"""
    )
    private val MONEY_AMOUNT = Regex(
        """(?:rs\.?|inr|₹|usd|\$)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:rs\.?|inr|₹|usd|\$)"""
    )
    private val TRANSACTION_KEYWORDS = listOf(
        "debited",
        "credited",
        "withdrawn",
        "deposited",
        "spent",
        "paid",
        "received",
        "transferred",
        "txn",
        "transaction",
        "purchase",
        "payment of",
        "available balance",
        "avl bal",
        "a/c",
        "acct",
        "upi"
    )

    fun classify(body: String): SensitiveSmsKind? {
        if (body.isBlank()) return null

        val lower = body.lowercase()
        if (hasSecretRequest(lower)) return null
        if (hasRewardLure(lower)) return null

        if (hasOtpSignal(lower)) return SensitiveSmsKind.OTP
        if (CREDENTIALS.containsMatchIn(lower)) return SensitiveSmsKind.CREDENTIALS
        if (hasTransactionSignal(lower)) return SensitiveSmsKind.TRANSACTION
        return null
    }

    fun shouldSkip(body: String): Boolean = classify(body) != null

    private fun hasSecretRequest(lower: String): Boolean {
        for (match in SECRET_REQUEST.findAll(lower)) {
            val prefixStart = maxOf(0, match.range.first - 15)
            val prefix = lower.substring(prefixStart, match.range.first)
            if (NEGATED_PREFIX.containsMatchIn(prefix)) continue
            return true
        }
        return false
    }

    private fun hasRewardLure(lower: String) = LINK.containsMatchIn(lower) && REWARD_LURE.containsMatchIn(lower)

    private fun hasOtpSignal(lower: String): Boolean {
        val hasKeyword = OTP_KEYWORDS.any { lower.contains(it) } || OTP_CODE_WORD.containsMatchIn(lower)
        return hasKeyword && OTP_CODE.containsMatchIn(lower)
    }

    private fun hasTransactionSignal(lower: String): Boolean {
        val hasAmount = MONEY_AMOUNT.containsMatchIn(lower)
        return hasAmount && TRANSACTION_KEYWORDS.any { lower.contains(it) }
    }
}

enum class SensitiveSmsKind { OTP, TRANSACTION, CREDENTIALS }
