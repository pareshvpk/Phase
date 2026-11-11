package com.arm.threatassistant.domain.detection.ruleengine

/**
 * Independent rule categories used by [FastRuleEngine].
 *
 * Each category captures a distinct class of suspicious SMS patterns. Rules
 * are defined per category and signals are tagged with their category so the
 * RiskPolicyEngine can weigh them independently in a later phase.
 */
enum class RuleCategory {
    URGENCY_AND_COERCION,
    CREDENTIAL_REQUEST,
    FINANCIAL_IMPERSONATION,
    PAYMENT_DEMAND,
    ACCOUNT_SUSPENSION
}
