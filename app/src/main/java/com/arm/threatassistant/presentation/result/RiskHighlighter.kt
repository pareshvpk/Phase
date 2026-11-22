package com.arm.threatassistant.presentation.result

import com.arm.threatassistant.domain.detection.ruleengine.CredentialLanguage

data class HighlightSpan(val start: Int, val end: Int)

object RiskHighlighter {

    const val MAX_SPANS = 30

    private const val MIN_PHRASE_LENGTH = 3

    fun spans(message: String, phrases: List<String>, exactRanges: List<IntRange> = emptyList()): List<HighlightSpan> {
        if (message.isEmpty()) return emptyList()

        return try {
            val searchable = CredentialLanguage.maskReminders(message)
            val found = exactRanges.filter { it.first >= 0 && it.last < message.length && !it.isEmpty() }
                .mapTo(mutableListOf()) { HighlightSpan(it.first, it.last + 1) }
            for (phrase in phrases) {
                val trimmed = phrase.trim()
                if (trimmed.length < MIN_PHRASE_LENGTH) continue

                val verbatim = findAll(searchable, verbatimRegex(trimmed))
                if (verbatim.isNotEmpty()) {
                    found.addAll(verbatim)
                    continue
                }

                val tolerant = tolerantPattern(trimmed) ?: continue
                found.addAll(findAll(searchable, Regex(tolerant, RegexOption.IGNORE_CASE)))
            }
            merge(found).take(MAX_SPANS)
        } catch (ignored: RuntimeException) {
            emptyList()
        }
    }

    private fun verbatimRegex(phrase: String): Regex =
        Regex(Regex.escape(phrase), RegexOption.IGNORE_CASE)

    private fun tolerantPattern(phrase: String): String? {
        val words = phrase.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (words.size < 2) return null
        return words.joinToString("\\s+") { Regex.escape(it) }
    }

    private fun findAll(message: String, regex: Regex): List<HighlightSpan> =
        regex.findAll(message)
            .filter { it.value.isNotEmpty() }
            .map { HighlightSpan(it.range.first, it.range.last + 1) }
            .toList()

    private fun merge(spans: List<HighlightSpan>): List<HighlightSpan> {
        if (spans.isEmpty()) return emptyList()
        val sorted = spans.sortedWith(compareBy({ it.start }, { it.end }))
        val merged = mutableListOf<HighlightSpan>()
        for (span in sorted) {
            if (span.start < 0 || span.end <= span.start) continue
            val last = merged.lastOrNull()
            if (last != null && span.start <= last.end) {
                if (span.end > last.end) {
                    merged[merged.size - 1] = HighlightSpan(last.start, span.end)
                }
            } else {
                merged.add(span)
            }
        }
        return merged
    }
}
