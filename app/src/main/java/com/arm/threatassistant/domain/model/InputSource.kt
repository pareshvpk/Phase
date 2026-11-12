package com.arm.threatassistant.domain.model

/**
 * Identifies how an [AnalysisInput] was provided to the application.
 *
 * Supports manual entry/paste, the Android share sheet (ACTION_SEND), Process
 * Text (ACTION_PROCESS_TEXT) and opt-in incoming SMS protection.
 */
enum class InputSource {
    MANUAL,
    SHARE_SHEET,
    PROCESS_TEXT,
    SMS
}
