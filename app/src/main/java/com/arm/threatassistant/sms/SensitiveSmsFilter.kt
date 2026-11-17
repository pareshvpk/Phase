package com.arm.threatassistant.sms

/**
 * Classifies legitimate private SMS that can be dropped before analysis.
 *
 * Genuine OTP, transaction and credential messages are dropped before
 * analysis. Borderline or scammy messages are moved into analysis instead
 * of being dropped outright. There are two exceptions, and such a message
 * is still analyzed:
 * 1. the message asks the user to share/send a code, PIN or password;
 * 2. the message contains a link together with reward wording
 *    (receive, claim, win, prize...).
 *
 * A scam override takes precedence over every skip rule: messages that
 * pair account-threat/urgency language with a callback number, or that
 * use explicit scam framing (digital arrest, legal action, etc.), are
 * never skipped so the rule engine and classifier can evaluate them.
 */
object SensitiveSmsFilter {

    private val SECRET_REQUEST = Regex(
        """(share|send|forward|tell|provide|give|submit|enter|reply with)\b.{0,40}\b(otp|code|pin|password|cvv|passcode)"""
    )
    private val NEGATED_PREFIX = Regex("""(do not|don't|dont|never|not)\s+$""")
    private val LINK = Regex("""https?://|www\.|\b[a-z0-9-]+\.(com|in|net|org|info|xyz|top|link|co|io|ly|me|app|site|online|click|live|shop|cc|ru|cn|tk)\b""")
    private val REWARD_LURE = Regex("""\b(receive|claim|redeem|collect|win|won|winner|prize|lottery|reward|rewards|gift|bonus|free|jackpot|lucky)\b""")

    private val SCAM_PHRASES = Regex(
        """\b(digital arrest|legal action|court case|police case|cyber crime|money mule|fraud alert|suspicious activity|unauthorized transaction|unauthorised transaction)\b"""
    )
    private val STRONG_LURE = Regex("""\b(won|winner|prize|lottery|jackpot|lucky draw)\b""")
    private val LINK_CALL_TO_ACTION = Regex("""\b(join|activate|withdraw|withdrawal|claim|redeem|unlock)\b""")
    private val THREAT_WORDS = listOf(
        "will be blocked", "will be suspended", "will be deactivated",
        "account will be", "call officer"
    )
    private val CALLBACK_NUMBER = Regex("""\b\d{10}\b|\b\d{3}[- ]\d{7}\b|\b1800\d{7}\b|\b1930\b""")

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
        // Possessive [\d,]*+ and the lookbehind keep this linear: a long digit run
        // used to be re-scanned from every position (5,000 digits took ~1 s).
        """(?:rs\.?|inr|₹|usd|\$)\s?\d[\d,]*+(?:\.\d+)?|(?<![\d,])\d[\d,]*+(?:\.\d+)?\s?(?:rs\.?|inr|₹|usd|\$)"""
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
        if (hasScamOverride(lower)) return null

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

    /**
     * Returns true when the message shows scam indicators that override the
     * OTP / transaction skip rules, so the message is sent to analysis
     * instead of being dropped outright.
     */
    private fun hasScamOverride(lower: String): Boolean {
        if (SCAM_PHRASES.containsMatchIn(lower)) return true
        // Prize/lottery wording never appears in genuine OTP or bank alerts, link or not
        // (e.g. "you won a £1000 prize ... call 0906...").
        if (STRONG_LURE.containsMatchIn(lower)) return true
        // "Rs.15,000 credited ... join now / activate / withdraw: sr3.in/..." looks like a
        // transaction alert but asks the user to act through a link.
        if (LINK.containsMatchIn(lower) && LINK_CALL_TO_ACTION.containsMatchIn(lower)) return true
        val hasThreat = THREAT_WORDS.any { lower.contains(it) }
        return hasThreat && CALLBACK_NUMBER.containsMatchIn(lower)
    }

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
