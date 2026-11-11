package com.arm.threatassistant.domain.adapters

import com.arm.threatassistant.domain.model.AnalysisInput

/**
 * Converts raw text from a specific ingestion source into a structured
 * [AnalysisInput] without performing any detection or risk calculation.
 *
 * Implementations reject empty or whitespace-only input by returning null.
 */
interface InputAdapter {
    fun adapt(rawText: String): AnalysisInput?
}
