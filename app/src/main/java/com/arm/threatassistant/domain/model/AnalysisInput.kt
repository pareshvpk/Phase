package com.arm.threatassistant.domain.model

/**
 * The user-supplied text to be analysed, extended in Phase 2 to carry the
 * original text plus the normalized representation and any extracted entities.
 *
 * [messageText] is the original, unmodified input and is always preserved.
 * [normalizedText], [extractedUrls], [extractedHosts], [extractedPhones] and
 * [normalizationWarnings] are populated by [com.arm.threatassistant.domain.normalization.InputNormalizer].
 * [source] identifies how the input was provided (manual, share sheet, process text).
 *
 * This is a pure domain definition. No validation, detection or risk calculation
 * is performed here. All fields are serializable as plain Kotlin data so the
 * model can later be embedded in a versioned evidence schema.
 */
data class AnalysisInput(
    val messageText: String,
    val normalizedText: String? = null,
    val source: InputSource = InputSource.MANUAL,
    val extractedUrls: List<String> = emptyList(),
    val extractedHosts: List<String> = emptyList(),
    val extractedPhones: List<String> = emptyList(),
    val normalizationWarnings: List<String> = emptyList(),
    val processingMetadata: Map<String, String> = emptyMap()
)
