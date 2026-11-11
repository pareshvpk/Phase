package com.arm.threatassistant.domain.model

/**
 * Identifies how an [AnalysisInput] was provided to the application.
 *
 * Phase 2 supports three ingestion paths: manual entry/paste, the Android
 * share sheet (ACTION_SEND) and Process Text (ACTION_PROCESS_TEXT).
 */
enum class InputSource {
    MANUAL,
    SHARE_SHEET,
    PROCESS_TEXT
}
