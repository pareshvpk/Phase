package com.arm.threatassistant.llm

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import kotlin.text.Regex

/**
 * Post-filter for the final Llama explanation text.
 *
 * Pure Kotlin with no Android imports, so it can be unit-tested on the JVM.
 * The detection verdict is authoritative: anything that contradicts it, or that
 * tells the user to click links, call numbers, reply or share codes, is removed
 * or replaced by the fixed localized fallback.
 */
object AdviceGuard {

    private const val MAX_SENTENCES = 6
    private const val MIN_SENTENCES = 2

    private val specialTokenRegex = Regex("<\\|[^|]+\\|>")
    private val urlRegex = Regex("""https?://\S+|www\.\S+""", RegexOption.IGNORE_CASE)
    private val phoneRegex = Regex(
        """\b\+?\d{1,3}[\s.\-]?\(?\d{2,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}\b"""
    )

    /**
     * Guards `text` (the raw, possibly streamed Llama output) and returns the
     * text that may be shown in the `Done` state.
     *
     * @param fallback the fixed localized explanation (built from ReasonMapper
     * reasons) returned when the text must not be shown as-is.
     * @param safeSteps the existing "What to do" items for the verdict, appended
     * as numbered lines when the text does not already contain them.
     */
    fun guard(
        text: String,
        verdict: ThreatVerdictLevel,
        languageTag: String,
        fallback: String,
        safeSteps: List<String>
    ): String {
        val cleaned = replaceVerdictEnums(removeSpecialTokens(text))
            .replace(urlRegex, "the link")
        if (cleaned.isBlank()) return fallback

        val lower = cleaned.lowercase()
        if (isRefusal(lower)) return fallback
        if (verdict == ThreatVerdictLevel.HIGH_RISK || verdict == ThreatVerdictLevel.SUSPICIOUS) {
            if (contradictsVerdict(lower, languageTag)) return fallback
        }

        val kept = dropCutOffEnding(splitIntoSentences(cleaned), cleaned)
            .map { it.trim() }
            .filter { it.any(Char::isLetter) }
            .filter { keepSentence(it, languageTag) }
            .map { softenClaims(it) }
            .filter { it.any(Char::isLetter) }
            .distinct()
            .take(MAX_SENTENCES)

        if (kept.size < MIN_SENTENCES) return fallback

        val stop = if (languageTag.startsWith("hi")) "।" else "."
        val body = kept.joinToString(" ") { s ->
            if (s.last() in ".!?।:\"”'") s else s + stop
        }
        return appendSafeStepsIfMissing(body, safeSteps)
    }

    /** Removes chat special tokens; keeps line breaks so bullets can be detected. */
    private fun removeSpecialTokens(text: String): String =
        text.replace("\r\n", "\n")
            .replace(specialTokenRegex, " ")
            .replace(Regex("[ \\t]+\\n"), "\n")
            .trim()

    private fun replaceVerdictEnums(text: String): String =
        text.replace("HIGH_RISK", "dangerous")
            .replace("INSUFFICIENT_EVIDENCE", "unclear")
            .replace("SUSPICIOUS", "suspicious")
            .replace(Regex("\\bSAFE\\b"), "safe")

    private fun isRefusal(lower: String): Boolean =
        listOf(
            "i cannot", "i can't", "i am unable", "i'm unable", "as an ai",
            "मैं नहीं कर सकता", "என்னால் முடியாது"
        ).any { lower.contains(it) }

    private fun contradictsVerdict(lower: String, languageTag: String): Boolean {
        // Only claims that the message itself is fine; "to stay safe" must not count.
        if (englishSafeClaim.containsMatchIn(lower)) return true
        val common = listOf("not a scam", "not suspicious", "not dangerous", "nothing to worry")
        val hindi = listOf("संदिग्ध नहीं", "सुरक्षित है")
        val tamil = listOf("பாதுகாப்பானது", "மோசடி இல்லை")
        val keywords = common + when (languageTag.take(2)) {
            "hi" -> hindi
            "ta" -> tamil
            else -> emptyList()
        }
        return keywords.any { lower.contains(it) }
    }

    private val englishSafeClaim = Regex(
        """\b(is|looks|seems|appears|appears to be)\s+(safe|legitimate|genuine|harmless)\b(?!\s+to\b)"""
    )

    // "*" / "•" start a bullet anywhere; "-" and "1." only at line start or after 2+ spaces.
    private val bulletRegex = Regex("""(?:^|\s)[*•]+\s*|(?:^|\n|\s{2,})(?:-|\d{1,2}[.)])\s+""")
    private val abbreviations = listOf("e.g.", "E.g.", "i.e.", "I.e.", "Rs.", "etc.", "approx.", "No.")
    private const val DOT_MARK = '\u0000'

    /**
     * Splits on bullets, line breaks and sentence-ending punctuation. Dots inside
     * known abbreviations or numbers, and punctuation inside quotes, never split.
     */
    private fun splitIntoSentences(text: String): List<String> {
        var protectedText = text
        for (abbr in abbreviations) {
            protectedText = protectedText.replace(abbr, abbr.replace('.', DOT_MARK))
        }
        val pieces = mutableListOf<String>()
        for (line in protectedText.replace(bulletRegex, "\n").split('\n')) {
            val current = StringBuilder()
            var inQuote = false
            for (i in line.indices) {
                val c = line[i]
                current.append(c)
                when {
                    c == '"' -> inQuote = !inQuote
                    c == '“' -> inQuote = true
                    c == '”' -> inQuote = false
                    !inQuote && c in ".!?।" && (i + 1 == line.length || line[i + 1].isWhitespace()) -> {
                        pieces += current.toString()
                        current.clear()
                    }
                }
            }
            pieces += current.toString()
        }
        return pieces
            .map { it.replace(DOT_MARK, '.').trim().trimEnd('*', '•', '-').trim() }
            .filter { it.isNotEmpty() }
    }

    private val describingPhrases = listOf(
        "asks you to", "asking you to", "wants you to", "tells you to", "telling you to",
        "urges you to", "pressures you to", "tries to get you to", "trick you into", "tricks you into"
    )

    /** Drops the last piece when generation stopped mid-sentence (token cap). */
    private fun dropCutOffEnding(pieces: List<String>, text: String): List<String> {
        val last = text.trimEnd().lastOrNull() ?: return pieces
        val complete = last in ".!?।\"”')"
        // Bullet lists normally end without a full stop; only prose is checked.
        val isList = bulletRegex.containsMatchIn(text)
        return if (!complete && !isList && pieces.size > 1) pieces.dropLast(1) else pieces
    }

    private fun keepSentence(sentence: String, languageTag: String): Boolean {
        val lower = sentence.lowercase()
        if (urlRegex.containsMatchIn(lower) || phoneRegex.containsMatchIn(lower)) {
            return false
        }
        val negations = negationWords(languageTag)
        if (negations.any { lower.contains(it) }) return true
        // Describing what the scammer wants ("it asks you to share your OTP") is not advice.
        if (languageTag.startsWith("en") && describingPhrases.any { lower.contains(it) }) return true
        return !triggerWords(languageTag).any { lower.contains(it) }
    }

    private fun softenClaims(sentence: String): String =
        sentence
            .replace(Regex("\\b100\\s?%"), "")
            .replace(Regex("\\bdefinitely\\b", RegexOption.IGNORE_CASE), "")
            .replace(Regex("\\bguaranteed\\b", RegexOption.IGNORE_CASE), "")
            .replace(Regex("\\s+"), " ")
            .trim()

    private fun appendSafeStepsIfMissing(body: String, safeSteps: List<String>): String {
        val steps = safeSteps.take(3).filter { it.isNotBlank() }
        if (steps.isEmpty()) return body
        val lower = body.lowercase()
        if (steps.all { lower.contains(it.lowercase()) }) return body
        val numbered = steps.mapIndexed { i, step -> "${i + 1}. $step" }.joinToString("\n")
        return "$body\n\n$numbered"
    }

    private fun triggerWords(languageTag: String): List<String> = when (languageTag.take(2)) {
        "hi" -> listOf(
            "क्लिक", "कॉल", "जवाब", "साझा", "शेयर", "otp",
            "लिंक खोलें", "लिंक पर जाएं", "लिंक कॉपी", "लिंक टाइप", "लिंक खोल"
        )
        "ta" -> listOf(
            "கிளிக்", "அழை", "பதில்", "பகிர்",
            "இணைப்பைத் திற", "இணைப்பை திற", "இணைப்பை நகலெடு"
        )
        else -> listOf(
            "click", "tap",
            "open a link", "open the link", "open link", "click the link", "tap the link",
            "click on", "tap on", "visit",
            // Instructions to retype or copy a link into a browser are not safe advice.
            "type the url", "type the link", "type this link", "type this url",
            "enter the url", "enter the link", "open the url", "open the website",
            "open this link", "open this url", "go to the link", "go to the url",
            "go to the website", "go to this address", "copy the link", "copy the url",
            "copy this link", "paste the link", "paste the url",
            "call", "dial",
            "reply", "reply now", "reply with",
            "share your otp", "send your otp", "give your otp", "reply with your otp",
            "share your pin", "send your pin", "give your pin",
            "share your password", "send your password", "give your password",
            "share your code", "send your code", "give your code"
        )
    }

    private fun negationWords(languageTag: String): List<String> = when (languageTag.take(2)) {
        "hi" -> listOf("न", "मत", "नहीं")
        "ta" -> listOf("வேண்டாம்", "கூடாது")
        else -> listOf("do not", "don't", "never", "not ")
    }
}
