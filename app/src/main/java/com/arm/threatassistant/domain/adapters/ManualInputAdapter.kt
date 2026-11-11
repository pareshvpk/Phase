package com.arm.threatassistant.domain.adapters

import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource

/**
 * Adapter for text entered or pasted directly in the application.
 *
 * - Rejects empty or whitespace-only input.
 * - Applies a configurable maximum length limit without splitting
 *   multi-byte UTF-8 sequences (limits are applied in code points).
 * - Returns structured input only; no detection is performed.
 */
class ManualInputAdapter private constructor(private val maxLength: Int) : InputAdapter {

    constructor() : this(5000)

    override fun adapt(rawText: String): AnalysisInput? {
        if (rawText.isBlank()) {
            return null
        }

        val trimmed = rawText.trim()
        if (trimmed.isEmpty()) {
            return null
        }

        val limited = takeByCodePoints(trimmed, maxLength)

        return AnalysisInput(
            messageText = limited,
            source = InputSource.MANUAL,
            processingMetadata = mapOf(
                "adapter" to "ManualInputAdapter",
                "originalLength" to rawText.length.toString(),
                "truncated" to (limited.length < trimmed.length).toString()
            )
        )
    }

    private fun takeByCodePoints(text: String, maxCodePoints: Int): String {
        if (text.codePointCount(0, text.length) <= maxCodePoints) {
            return text
        }
        var index = 0
        var remaining = maxCodePoints
        while (remaining > 0 && index < text.length) {
            index = text.offsetByCodePoints(index, 1)
            remaining--
        }
        return text.substring(0, index)
    }
}
