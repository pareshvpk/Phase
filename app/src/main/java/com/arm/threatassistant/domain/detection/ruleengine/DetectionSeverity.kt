package com.arm.threatassistant.domain.detection.ruleengine

/**
 * Severity of an individual detection signal.
 *
 * Severity reflects how strongly a single matched rule indicates a potential
 * scam, independent of any other signal. The final verdict is determined by
 * the RiskPolicyEngine, not by the FastRuleEngine.
 */
enum class DetectionSeverity {
    LOW,
    MEDIUM,
    HIGH
}
