package com.arm.threatassistant.domain.detection.ruleengine

/** A promise of incoming funds directly linked to an instruction authorizing a debit. */
internal object UpiPaymentRequest {
    const val RULE_ID = "pay_009"
    const val EXPLANATION = "It promises money coming in, but asks you to authorize a payment going out."

    private const val AMOUNT = """(?:₹|rs\.?|inr)\s*\d[\d,]*(?:\.\d{1,2})?"""
    private const val REWARD = """(?:cash\s?back|refund)"""
    private const val PENDING = """$REWARD(?:\s+of\s+$AMOUNT)?\s+(?:(?:is|abhi)\s+)?(?:pending|waiting|ready|available)\b"""
    private const val RECEIVE = """(?:to\s+)?(?:receive|claim|get|collect)\s+(?:(?:your|the|a)\s+)?(?:$AMOUNT(?:\s+$REWARD)?|$REWARD|money)\b"""
    private const val HINGLISH = """$REWARD\s+(?:lene|paane|pane|receive\s+karne|claim\s+karne)\s+ke\s+liye"""
    private const val PROMISE = """(?:$PENDING|$RECEIVE|$HINGLISH)"""
    private const val APPROVE = """(?:approve|accept|authori[sz]e)\s+(?:(?:this|the|your|a)\s+)?(?:$AMOUNT\s+)?(?:upi\s+)?(?:(?:payment|collect)\s+request|payment|mandate|request)\b"""
    private const val ENTER_PIN = """(?:enter\s+(?:(?:your|the|a)\s+)?upi\s+pin|upi\s+pin\s+(?:daalo|dalo|dalein|darj\s+karein))\b"""
    private const val APPROVE_HI = """(?:payment|(?:collect|payment)\s+request)\s+(?:ko\s+)?(?:approve|accept)\s+(?:karo|karein)\b"""
    private const val ACTION = """(?:$APPROVE|$ENTER_PIN(?:\s+aur\s+$APPROVE_HI)?|$APPROVE_HI)"""
    // Only join adjacent instructions. A receipt and an unrelated payment are insufficient.
    private const val JOIN = """[\s.,!;:–—-]+(?:please\s+|kripya\s+)?"""
    private val pairs = listOf(
        Regex("""\b($PROMISE)$JOIN($ACTION)""", RegexOption.IGNORE_CASE),
        Regex("""\b($ACTION)$JOIN($PROMISE)""", RegexOption.IGNORE_CASE)
    )
    private const val NEGATION_WINDOW = 160
    private val negativePrefix = Regex(
        """\b(?:not|never|don['’]?t|(?:no|not)\s+need\s+to|(?:never|not|don['’]?t|no)\s+(?:have|need)\s+to|(?:not|never)\s+(?:ask(?:s)?\s+you|required)\s+to|mat|na)(?:\s+ever)?(?:\s+$ACTION)?\s*$""",
        RegexOption.IGNORE_CASE
    )

    fun evidence(text: String): List<IntRange> {
        for (pattern in pairs) {
            for (match in pattern.findAll(text)) {
                val groups = match.groups
                val first = groups[1]!!.range
                val second = groups[2]!!.range
                val prefix = text.substring(maxOf(0, match.range.first - NEGATION_WINDOW), match.range.first)
                if (!negativePrefix.containsMatchIn(prefix)) {
                    return listOf(first, second)
                }
            }
        }
        return emptyList()
    }
}
