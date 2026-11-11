package com.arm.threatassistant.domain.adapters

import android.content.Intent
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource

/**
 * Adapter for content selected in another application and sent via
 * ACTION_PROCESS_TEXT (mimeType text/plain).
 *
 * - Allows users to select text in another app and send it to
 *   Android Threat Assistant.
 * - Handles missing selected text safely by returning null.
 * - Requires no additional permissions.
 * - Returns structured input only; no detection is performed.
 */
class ProcessTextAdapter private constructor(private val maxLength: Int) : InputAdapter {

    constructor() : this(5000)

    /**
     * Extracts selected text from an [Intent] and adapts it.
     * Returns null when the intent carries no usable text.
     */
    fun adaptFromIntent(intent: Intent): AnalysisInput? {
        val text = intent.getStringExtra(Intent.EXTRA_PROCESS_TEXT)
        return adapt(text ?: "")
    }

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
            source = InputSource.PROCESS_TEXT,
            processingMetadata = mapOf(
                "adapter" to "ProcessTextAdapter",
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
