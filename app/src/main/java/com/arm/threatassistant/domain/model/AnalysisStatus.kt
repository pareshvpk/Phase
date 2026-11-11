package com.arm.threatassistant.domain.model

/**
 * Lifecycle state of a single analysis request.
 *
 * These values describe the UI/analysis pipeline state only. They do not
 * represent a threat verdict and carry no risk calculation.
 */
enum class AnalysisStatus {
    IDLE,
    ANALYZING,
    COMPLETED,
    ERROR
}
