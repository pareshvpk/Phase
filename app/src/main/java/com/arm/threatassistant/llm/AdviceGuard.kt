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
        val cleaned = removeSpecialTokens(text)
        if (cleaned.isBlank()) return fallback

        val lower = cleaned.lowercase()
        if (isRefusal(lower)) return fallback
        if (verdict == ThreatVerdictLevel.HIGH_RISK || verdict == ThreatVerdictLevel.SUSPICIOUS) {
            if (contradictsVerdict(lower, languageTag)) return fallback
        }

        val kept = splitIntoSentences(cleaned)
            .filter { it.isNotBlank() }
            .map { it.trim() }
            .filter { keepSentence(it, languageTag) }
            .map { softenClaims(it) }
            .distinct()
            .take(MAX_SENTENCES)

        if (kept.size < MIN_SENTENCES) return fallback

        val body = kept.joinToString(" ")
        return appendSafeStepsIfMissing(body, safeSteps)
    }

    private fun removeSpecialTokens(text: String): String =
        text.replace(specialTokenRegex, " ").replace(Regex("\\s+"), " ").trim()

    private fun isRefusal(lower: String): Boolean =
        listOf(
            "i cannot", "i can't", "i am unable", "i'm unable", "as an ai",
            "मैं नहीं कर सकता", "என்னால் முடியாது"
        ).any { lower.contains(it) }

    private fun contradictsVerdict(lower: String, languageTag: String): Boolean {
        val common = listOf("safe", "not a scam", "not suspicious", "legitimate", "not dangerous")
        val hindi = listOf("संदिग्ध नहीं", "सुरक्षित है")
        val tamil = listOf("பாதுகாப்பானது", "மோசடி இல்லை")
        val keywords = common + when (languageTag.take(2)) {
            "hi" -> hindi
            "ta" -> tamil
            else -> emptyList()
        }
        return keywords.any { lower.contains(it) }
    }

    private fun splitIntoSentences(text: String): List<String> {
        val normalized = text.replace(Regex("[.!?।]"), "\n")
        return normalized.lines().map { it.trim() }
    }

    private fun keepSentence(sentence: String, languageTag: String): Boolean {
        val lower = sentence.lowercase()
        if (urlRegex.containsMatchIn(lower) || phoneRegex.containsMatchIn(lower)) {
            return false
        }
        val negations = negationWords(languageTag)
        if (negations.any { lower.contains(it) }) return true
        return !triggerWords(languageTag).any { lower.contains(it) }
    }

    private fun softenClaims(sentence: String): String =
        sentence
            .replace(Regex("\\b100%\\b", RegexOption.IGNORE_CASE), "")
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
        "hi" -> listOf("क्लिक", "कॉल", "जवाब", "साझा", "शेयर", "otp")
        "ta" -> listOf("கிளிக்", "அழை", "பதில்", "பகிர்")
        else -> listOf(
            "click", "tap",
            "open a link", "open the link", "open link", "click the link", "tap the link",
            "click on", "tap on", "visit",
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
