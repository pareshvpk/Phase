package com.arm.threatassistant.domain.detection.ruleengine

/** Only mask the instruction to keep a credential private. Other clauses remain evidence. */
internal object CredentialLanguage {
    private const val SECRET = """(?:otp|(?:upi\s+)?pin|password|cvv|passcode|verification\s+code|security\s+code)"""
    private const val SEPARATOR = """(?:\s*,\s*(?:(?:or|and)\s+)?|\s+(?:or|and)\s+)"""
    private const val SECRETS = """$SECRET(?:$SEPARATOR$SECRET){0,4}"""
    private const val VERB = """(?:share|send|forward|disclose|give|reveal|tell|provide|reply\s+with)"""
    private const val HINDI_VERB = """(?:bhej(?:o|en|ein|na)|bata(?:o|na|yein)|dena|dijiye|karo|karein|karna)"""
    private const val OBJECT = """(?:apna\s+)?$SECRET\s+(?:kisi\s+ko\s+)?(?:kabhi\s+)?"""
    private val reminder = Regex(
        """\b(?:(?:never|do\s+not|don['’]?t)\s+(?:ever\s+)?(?:ask(?:s)?\s+you\s+to\s+)?$VERB\s+(?:(?:your|the|any)\s+)?$SECRETS""" +
            """|$OBJECT(?:share\s+)?(?:mat|na|nahi)\s+(?:share\s+)?$HINDI_VERB)\b""",
        RegexOption.IGNORE_CASE
    )

    // The same request must reach both the rule engine and the incoming-message privacy gate.
    const val HINGLISH_REQUEST = """\b(?:apna\s+)?(?:otp|pin|password)\s+(?:abhi\s+)?(?:bhejo|bhejein|batao|batayein|share\s+(?:karo|karein))\b"""
    val hinglishRequest = Regex(HINGLISH_REQUEST, RegexOption.IGNORE_CASE)
    const val REPLY_REQUEST = """\breply\s+with\s+(?:(?:your|the)\s+)?(?:otp|pin|password|passcode|verification\s+code|security\s+code)(?:\s+(?:and|or)\s+(?:your\s+)?(?:otp|pin|password))?\b"""
    const val SHARE_REQUEST = """\b(?:share|send|forward|give|tell)\s+(?:(?:me|us)\s+)?(?:your|the)\s+$SECRET\b"""

    // "Never share your OTP with anyone except our agent" still asks for disclosure.
    private val exception = Regex(
        """(?:\s+with\s+(?:anyone|anybody|others))?[\s,]*+(?:except|unless|apart\s+from)\b""",
        RegexOption.IGNORE_CASE
    )

    fun hasExceptionAfter(text: String, end: Int): Boolean = exception.matchesAt(text, end)

    /** Spaces preserve offsets into the original for the result highlighter. */
    fun maskReminders(text: String): String = reminder.replace(text) { match ->
        if (hasExceptionAfter(text, match.range.last + 1)) match.value else " ".repeat(match.value.length)
    }
}
