package com.arm.threatassistant.domain.detection.smsclassifier

/**
 * Status of an SMS specialist classifier inference run.
 *
 * [AVAILABLE] — the model loaded successfully and inference produced a result.
 * [UNAVAILABLE] — no model asset is present or the model could not be loaded.
 * [ERROR] — inference failed for an unexpected reason.
 * [UNSUPPORTED_INPUT] — the input cannot be meaningfully classified
 *   (for example, empty or blank text).
 *
 * Note: [UNAVAILABLE] and [ERROR] must never be interpreted as evidence that a
 * message is SAFE. A failed classifier yields no threat signal, not negative
 * threat evidence.
 */
enum class SmsClassifierStatus {
    AVAILABLE,
    UNAVAILABLE,
    ERROR,
    UNSUPPORTED_INPUT
}
