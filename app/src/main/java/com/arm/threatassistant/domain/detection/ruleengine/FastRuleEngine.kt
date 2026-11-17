package com.arm.threatassistant.domain.detection.ruleengine

import com.arm.threatassistant.domain.model.AnalysisInput
import java.text.Normalizer

/**
 * Deterministic, offline rule engine for detecting suspicious SMS patterns.
 *
 * FastRuleEngine applies independent, explainable rules across five categories
 * (urgency/coercion, credential requests, financial impersonation, payment
 * demands, account suspension threats) and returns every detected signal.
 *
 * It does NOT produce a security verdict. Verdict determination is the
 * responsibility of the RiskPolicyEngine (Phase 5).
 *
 * Design principles:
 * - Rules are defined as data (not hardcoded conditionals) for easy extension.
 * - Matching is case-insensitive and tolerant of punctuation/whitespace
 *   variations.
 * - Broad single-word terms (e.g. "bank", "account", "OTP", "payment") never
 *   fire alone; only multi-word phrases and contextual combinations match.
 * - All relevant matches are returned; the engine never stops at the first.
 * - Duplicate signals for the same rule and matched span are suppressed, and
 *   overlapping matches of the same rule collapse into the longest one.
 * - No network, no LLM, no ExecuTorch, no external APIs.
 */
object FastRuleEngine {

    internal const val DETECTOR_ID = "FastRuleEngine"
    internal const val DETECTOR_VERSION = "1.0.0"

    /**
     * Zero-width / invisible / directional formatting characters used to break
     * up phrases ("Act<ZWSP>within<ZWSP>24 hours") so that naive phrase
     * matching fails. They are replaced with a space before matching — not
     * deleted, so the words they separate stay separated.
     */
    private val INVISIBLE_CHARACTERS = Regex(
        "[\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\uFFF9-\\uFFFB]"
    )

    /** Punctuation and symbols are replaced with a space before matching. */
    private val PUNCTUATION_OR_SYMBOLS = Regex("[\\p{Punct}\\p{S}]")

    /** Runs of whitespace collapse to a single space. */
    private val WHITESPACE_RUNS = Regex("\\s+")

    /**
     * A single rule definition. Patterns are matched against a normalized,
     * lowercased, punctuation-stripped copy of the input.
     */
    private data class RuleDefinition(
        val ruleId: String,
        val category: RuleCategory,
        val severity: DetectionSeverity,
        val patterns: List<String>,
        val description: String
    )

    /** A matched span of normalized text, used to suppress overlapping matches. */
    private data class MatchSpan(val start: Int, val end: Int, val text: String) {
        val length: Int get() = end - start + 1

        fun overlaps(other: MatchSpan): Boolean = start <= other.end && other.start <= end
    }

    /** All rules, grouped by category for maintainability. */
    private val RULES = listOf(
        // ---- A. Urgency and coercion ----
        RuleDefinition("urg_001", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.HIGH,
            listOf("immediate action required"),
            "Message demands immediate action, a common coercion tactic."),
        RuleDefinition("urg_002", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.HIGH,
            listOf("account will be blocked today", "account will be blocked"),
            "Message threatens account blocking within a short timeframe."),
        RuleDefinition("urg_003", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.MEDIUM,
            listOf("urgent verification", "verification required immediately"),
            "Message pressures the recipient to verify urgently."),
        RuleDefinition("urg_004", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.HIGH,
            listOf("act within 24 hours", "act within twenty four hours"),
            "Message imposes a 24-hour deadline to act."),
        RuleDefinition("urg_005", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.HIGH,
            listOf("failure to respond will result in suspension",
                "failure to respond will result in deactivation"),
            "Message threatens suspension if the recipient does not respond."),
        RuleDefinition("urg_006", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.MEDIUM,
            listOf("time is running out", "limited time to act"),
            "Message creates artificial time pressure."),
        RuleDefinition("urg_007", RuleCategory.URGENCY_AND_COERCION, DetectionSeverity.MEDIUM,
            listOf("act now", "respond immediately"),
            "Message demands immediate response without explanation."),

        // ---- B. Credential requests ----
        RuleDefinition("cred_001", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("enter your password", "enter the password"),
            "Message asks the recipient to enter or reveal a password."),
        RuleDefinition("cred_002", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("verify your banking credentials", "verify your credentials"),
            "Message requests banking credential verification."),
        RuleDefinition("cred_003", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("share your otp", "share the otp", "send your otp", "send the otp"),
            "Message asks the recipient to share or send an OTP."),
        RuleDefinition("cred_004", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("confirm your pin", "confirm your pincode", "reveal your pin"),
            "Message asks the recipient to confirm or reveal a PIN."),
        RuleDefinition("cred_005", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("update login details", "update your login", "update login information"),
            "Message requests login detail updates."),
        RuleDefinition("cred_006", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("provide your password", "provide the password"),
            "Message asks the recipient to provide a password."),
        RuleDefinition("cred_007", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.HIGH,
            listOf("otp verification required", "otp verification needed"),
            "Message states OTP verification is required, often a prelude to OTP theft."),
        RuleDefinition("cred_008", RuleCategory.CREDENTIAL_REQUEST, DetectionSeverity.MEDIUM,
            listOf("your otp is", "your otp has been"),
            "Message references an OTP value; legitimate in some contexts but reviewed here."),

        // ---- C. Financial impersonation ----
        RuleDefinition("fin_001", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("this is your bank", "this is your bank speaking"),
            "Message claims to be from the recipient's bank without verification."),
        RuleDefinition("fin_002", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("we are from your bank", "we are calling from your bank"),
            "Message claims the sender is from the recipient's bank."),
        RuleDefinition("fin_003", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("bank department", "banking department"),
            "Message invokes a bank department to appear authoritative."),
        RuleDefinition("fin_004", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("payment service team", "payment services team"),
            "Message claims to be from a payment service team."),
        RuleDefinition("fin_005", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("government payment", "government department payment"),
            "Message claims to be a government payment communication."),
        RuleDefinition("fin_006", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("customer support team", "support team calling"),
            "Message claims to be customer support, a common impersonation pretext."),
        RuleDefinition("fin_007", RuleCategory.FINANCIAL_IMPERSONATION, DetectionSeverity.MEDIUM,
            listOf("financial institution", "your financial institution"),
            "Message references a financial institution in an unverified context."),

        // ---- D. Payment demands ----
        RuleDefinition("pay_001", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("pay immediately", "payment immediately"),
            "Message demands immediate payment."),
        RuleDefinition("pay_002", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("transfer money to avoid penalties", "transfer funds to avoid penalties"),
            "Message demands money transfers to avoid penalties."),
        RuleDefinition("pay_003", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("pay a processing fee", "pay the processing fee", "processing fee payment"),
            "Message demands a processing fee payment."),
        RuleDefinition("pay_004", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.MEDIUM,
            listOf("outstanding payment", "outstanding balance due"),
            "Message references an outstanding payment demand."),
        RuleDefinition("pay_005", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("unexpected refund processing fee", "refund processing fee"),
            "Message mentions an unexpected refund processing fee, a common scam lure."),
        RuleDefinition("pay_006", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("pay now to avoid", "pay today to avoid", "pay now"),
            "Message demands immediate payment, often to avoid consequences."),
        RuleDefinition("pay_007", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.MEDIUM,
            listOf("penalty of", "penalty will be"),
            "Message threatens a penalty."),
        RuleDefinition("pay_008", RuleCategory.PAYMENT_DEMAND, DetectionSeverity.HIGH,
            listOf("transfer funds immediately", "transfer money immediately",
                "send money immediately"),
            "Message demands immediate fund transfer."),

        // ---- E. Account suspension threats ----
        RuleDefinition("susp_001", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("bank account suspension", "account suspension"),
            "Message threatens bank account suspension."),
        RuleDefinition("susp_002", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("account deactivation", "your account will be deactivated"),
            "Message threatens account deactivation."),
        RuleDefinition("susp_003", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("kyc expiration", "kyc has expired", "kyc expiry"),
            "Message threatens KYC expiration."),
        RuleDefinition("susp_004", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("sim blocking", "sim will be blocked", "sim card blocking"),
            "Message threatens SIM blocking."),
        RuleDefinition("susp_005", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("service termination", "service will be terminated"),
            "Message threatens service termination."),
        RuleDefinition("susp_006", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("your account will be suspended", "account will be suspended"),
            "Message states the account will be suspended."),
        RuleDefinition("susp_007", RuleCategory.ACCOUNT_SUSPENSION, DetectionSeverity.HIGH,
            listOf("kyc verification required immediately", "kyc update required immediately"),
            "Message demands immediate KYC verification under threat of suspension.")
    )

    /**
     * Analyzes [input] and returns all detected rule signals.
     *
     * The original input is preserved; matching is performed on a normalized
     * copy (lowercased, punctuation stripped, whitespace collapsed). No
     * verdict is produced.
     */
    fun detect(input: AnalysisInput): RuleDetectionResult {
        val text = input.normalizedText ?: input.messageText
        val normalized = normalizeForMatching(text)
        // Invisible characters are used both between words ("act​within") and
        // inside words to break keywords ("sh​are your o‍TP"). Match both
        // readings: invisible as a space, and invisible removed.
        val variants = if (INVISIBLE_CHARACTERS.containsMatchIn(text)) {
            listOf(normalized, normalizeForMatching(text.replace(INVISIBLE_CHARACTERS, "")))
        } else {
            listOf(normalized)
        }

        val detectedSignals = mutableListOf<DetectionSignal>()

        var signalIndex = 0

        for (rule in RULES) {
            val spans = variants.flatMap { bestMatches(rule, it) }.distinctBy { it.text }
            for (span in spans) {
                signalIndex++
                detectedSignals.add(
                    DetectionSignal(
                        signalId = "${DETECTOR_ID}-$signalIndex",
                        category = rule.category,
                        ruleId = rule.ruleId,
                        description = rule.description,
                        matchedText = span.text,
                        severity = rule.severity,
                        detectorId = DETECTOR_ID,
                        detectorVersion = DETECTOR_VERSION
                    )
                )
            }
        }

        // Order signals by category then ruleId for stable, traceable output.
        detectedSignals.sortWith(compareBy<DetectionSignal> { it.category.toString() }.thenBy { it.ruleId })

        return RuleDetectionResult(
            signals = detectedSignals,
            detectorId = DETECTOR_ID,
            detectorVersion = DETECTOR_VERSION
        )
    }

    /**
     * Returns the matches of [rule] inside [normalized] that do not overlap
     * each other.
     *
     * When several patterns of the same rule match overlapping text (e.g.
     * "account will be blocked today" and "account will be blocked"), only the
     * longest match is kept so that a single rule never emits redundant
     * signals for the same piece of text. Non-overlapping matches of the same
     * rule are all returned.
     */
    private fun bestMatches(rule: RuleDefinition, normalized: String): List<MatchSpan> {
        val candidates = mutableListOf<MatchSpan>()
        for (pattern in rule.patterns) {
            val matcher = Regex(pattern, RegexOption.IGNORE_CASE).find(normalized) ?: continue
            if (matcher.value.isEmpty()) continue
            candidates.add(MatchSpan(matcher.range.first, matcher.range.last, matcher.value))
        }
        if (candidates.isEmpty()) return emptyList()

        candidates.sortWith(compareByDescending<MatchSpan> { it.length }.thenBy { it.start })

        val selected = mutableListOf<MatchSpan>()
        for (candidate in candidates) {
            if (selected.none { it.overlaps(candidate) }) {
                selected.add(candidate)
            }
        }
        return selected
    }

    /**
     * Produces a matching-friendly representation of [text]: NFC-normalized,
     * lowercased, zero-width/invisible characters replaced with spaces,
     * punctuation replaced with spaces, and whitespace collapsed.
     *
     * This makes matching tolerant of case, punctuation, whitespace and
     * invisible-character obfuscation while the original input remains
     * preserved in [AnalysisInput.messageText].
     */
    private fun normalizeForMatching(text: String): String {
        return Normalizer.normalize(text, Normalizer.Form.NFC)
            .lowercase()
            .replace(INVISIBLE_CHARACTERS, " ")
            .replace(PUNCTUATION_OR_SYMBOLS, " ")
            .replace(WHITESPACE_RUNS, " ")
            .trim()
    }
}
