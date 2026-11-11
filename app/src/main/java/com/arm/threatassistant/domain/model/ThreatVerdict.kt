package com.arm.threatassistant.domain.model

/**
 * Future threat verdict categories.
 *
 * These are domain definitions only. No detection or risk calculation is
 * implemented in Phase 1. A verdict of [UNSUPPORTED_INPUT] is reserved for
 * inputs the detection engine cannot meaningfully evaluate (for example,
 * empty or non-textual content).
 */
enum class ThreatVerdict {
    SAFE_UNVERIFIED,
    SUSPICIOUS,
    HIGH_RISK,
    INCONCLUSIVE,
    UNSUPPORTED_INPUT
}
