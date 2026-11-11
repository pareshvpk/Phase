package com.arm.threatassistant.domain.normalization

import com.arm.threatassistant.domain.model.AnalysisInput
import java.net.URI
import java.util.regex.Pattern

/**
 * Phase 2 input normalizer.
 *
 * Produces a normalized representation of raw user input for subsequent
 * analysis. The original input is always preserved; nothing is silently
 * removed, no classification is performed, and no network access is made.
 *
 * Responsibilities:
 *  - Unicode normalization (NFC).
 *  - Detection (recording only) of zero-width / invisible Unicode characters.
 *  - URL extraction with java.net.URI parsing; hostnames extracted separately.
 *  - Phone number extraction (best effort).
 *  - Safe handling of malformed URLs and extremely long text.
 */
object InputNormalizer {

    // Zero-width / invisible / directional formatting code points that may be
    // used to obfuscate content. These are detected and recorded, never removed.
    private val INVISIBLE_CODE_POINTS = setOf(
        0x200B, // ZERO WIDTH SPACE
        0x200C, // ZERO WIDTH NON-JOINER
        0x200D, // ZERO WIDTH JOINER
        0x200E, // LEFT-TO-RIGHT MARK
        0x200F, // RIGHT-TO-LEFT MARK
        0x202A, // LEFT-TO-RIGHT EMBEDDING
        0x202B, // RIGHT-TO-LEFT EMBEDDING
        0x202C, // POP DIRECTIONAL FORMATTING
        0x202D, // LEFT-TO-RIGHT OVERRIDE
        0x202E, // RIGHT-TO-LEFT OVERRIDE
        0x2060, // WORD JOINER
        0x2061, // FUNCTION APPLICATION
        0x2062, // INVISIBLE TIMES
        0x2063, // INVISIBLE SEPARATOR
        0x2064, // INVISIBLE PLUS
        0xFEFF, // ZERO WIDTH NO-BREAK SPACE (BOM)
        0x00AD, // SOFT HYPHEN
        0xFFF9, // INTERLINEAR ANNOTATION ANCHOR
        0xFFFA, // INTERLINEAR ANNOTATION SEPARATOR
        0xFFFB  // INTERLINEAR ANNOTATION TERMINATOR
    )

    // Matches http/https URLs and bare www. host references.
    private val URL_PATTERN = Pattern.compile(
        """\b(?:https?://|www\.)[\w~:/?#\[\]@!$&'()*+,;=.-]+""",
        Pattern.CASE_INSENSITIVE
    )

    // Best-effort phone number pattern: optional leading +, digits, spaces,
    // dashes, dots and parentheses. Requires at least 7 digits.
    private val PHONE_PATTERN = Pattern.compile(
        """\+?\d[\d() .-]{6,}\d"""
    )

    private val MAX_INPUT_LENGTH = 100_000

    /**
     * Result of normalizing a single input.
     */
    data class NormalizedResult(
        /** NFC-normalized text (original preserved by caller via AnalysisInput.messageText). */
        val normalizedText: String,
        /** Raw URL strings extracted from the text. */
        val extractedUrls: List<String>,
        /** Hostnames parsed from the extracted URLs. */
        val extractedHosts: List<String>,
        /** Best-effort phone numbers extracted from the text. */
        val extractedPhones: List<String>,
        /** Warnings describing transformations or anomalies detected. */
        val warnings: List<String>
    )

    /**
     * Normalizes [text] and returns a [NormalizedResult].
     *
     * The original text is never modified or truncated by this method. Callers
     * are responsible for storing [AnalysisInput.messageText] separately.
     */
    fun normalize(text: String): NormalizedResult {
        val warnings = mutableListOf<String>()

        // Guard against extremely long input without losing data.
        val bounded = if (text.length > MAX_INPUT_LENGTH) {
            warnings.add("Input length ${text.length} exceeds recommended limit ${MAX_INPUT_LENGTH}; analyzed in full.")
            text
        } else {
            text
        }

        // Detect invisible / zero-width characters; record but do not remove.
        val invisibleFound = bounded.toCharArray().filter { it.code in INVISIBLE_CODE_POINTS }
        if (invisibleFound.isNotEmpty()) {
            val distinct = invisibleFound.distinct().sortedBy { it.code }
                .joinToString { "U+${Integer.toHexString(it.code).uppercase()}" }
            warnings.add("Zero-width or invisible Unicode characters detected: $distinct")
        }

        // Unicode normalization (NFC) for consistent subsequent analysis.
        val normalized = java.text.Normalizer.normalize(bounded, java.text.Normalizer.Form.NFC)

        // Extract URLs and hostnames.
        val urls = mutableListOf<String>()
        val hosts = mutableListOf<String>()
        val matcher = URL_PATTERN.matcher(normalized)
        while (matcher.find()) {
            val candidate = matcher.group()
            try {
                val uri = URI(candidate)
                if (uri.scheme != null && uri.host != null) {
                    urls.add(candidate)
                    hosts.add(uri.host)
                }
            } catch (_: Exception) {
                // Malformed URL: skip safely, do not crash.
            }
        }

        // Extract phone numbers (best effort).
        val phones = mutableListOf<String>()
        val phoneMatcher = PHONE_PATTERN.matcher(normalized)
        while (phoneMatcher.find()) {
            phones.add(phoneMatcher.group())
        }

        return NormalizedResult(
            normalizedText = normalized,
            extractedUrls = urls,
            extractedHosts = hosts,
            extractedPhones = phones,
            warnings = warnings
        )
    }

    /**
     * Applies normalization to an [AnalysisInput], returning a copy with the
     * normalized text, extracted entities, and warnings populated. The original
     * [messageText] is preserved unchanged.
     */
    fun normalize(input: AnalysisInput): AnalysisInput {
        val result = normalize(input.messageText)
        return input.copy(
            normalizedText = result.normalizedText,
            extractedUrls = result.extractedUrls,
            extractedHosts = result.extractedHosts,
            extractedPhones = result.extractedPhones,
            normalizationWarnings = result.warnings,
            processingMetadata = input.processingMetadata + mapOf(
                "normalizedLength" to result.normalizedText.length.toString(),
                "urlCount" to result.extractedUrls.size.toString(),
                "phoneCount" to result.extractedPhones.size.toString(),
                "warningCount" to result.warnings.size.toString()
            )
        )
    }
}
