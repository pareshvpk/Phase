package com.arm.threatassistant.llm

/**
 * Builds Llama 3 chat-formatted prompts for the plain-language explanation.
 *
 * Pure Kotlin with no Android dependencies so it can be unit-tested on the JVM.
 * The detection verdict is authoritative and is passed to the model as fixed
 * context; the model is only asked to explain it.
 *
 * The prompt is split into a reusable [prefix] (system prompt plus the user
 * header) and a per-message [tail] so the model's KV cache can keep the prefix
 * and only process the short tail for each new message.
 */
object ExplanationPromptBuilder {

    internal const val SYSTEM_PROMPT =
        "You are a friendly phone-safety helper who protects people from SMS fraud. " +
            "The user's security app has already checked the message and decided the " +
            "verdict; treat that verdict as correct and do not question it. Explain the " +
            "warning in plain, simple words. Do not repeat links, numbers or codes. Never " +
            "tell the user to click, call, reply, share a code, or type, open, visit or " +
            "copy a link."

    private const val BEGIN_OF_TEXT = "<|begin_of_text|>"
    private const val START_HEADER = "<|start_header_id|>"
    private const val END_HEADER = "<|end_header_id|>"
    private const val EOT_ID = "<|eot_id|>"

    internal const val USER_OPENING =
        "I received this SMS and my phone's security app warned me about it. " +
            "Please help me understand the warning.\n"

    private const val MAX_MESSAGE_LENGTH = 160
    private const val MAX_EVIDENCE_ITEMS = 5

    /** Everything up to and including the user header; cached across messages. */
    fun prefix(languageName: String): String {
        val safeLanguageName = languageName.sanitize()
        return buildString {
            append(BEGIN_OF_TEXT)
            append(START_HEADER).append("system").append(END_HEADER).append("\n\n")
            append(SYSTEM_PROMPT)
            append(" Write the explanation in ")
            append(safeLanguageName)
            append('.')
            append(EOT_ID)
            append(START_HEADER).append("user").append(END_HEADER).append("\n\n")
            // The fixed opening of the user turn is cached with the prefix too.
            append(USER_OPENING)
        }
    }

    /** The per-message user prompt, EOT, assistant header and answer start. */
    fun tail(
        verdictLabel: String,
        evidence: List<String>,
        messageText: String,
        languageName: String
    ): String {
        val safeMessage = messageText
            .take(MAX_MESSAGE_LENGTH)
            .sanitize()
        val safeEvidence = evidence
            .take(MAX_EVIDENCE_ITEMS)
            .map { it.sanitize() }
        val safeLanguageName = languageName.sanitize()

        val mappedVerdict = when (val raw = verdictLabel.replace("<|", "").replace("|>", "").trim()) {
            "HIGH_RISK" -> "Dangerous - likely a scam"
            "SUSPICIOUS" -> "Suspicious"
            "INSUFFICIENT_EVIDENCE" -> "Not sure"
            "SAFE" -> "Looks safe"
            else -> raw
        }

        val userPrompt = buildString {
            append("I received this SMS and my phone's security app warned me about it. ")
            append("Please help me understand the warning.\n")
            append("Verdict: ")
            append(mappedVerdict)
            append("\nReasons found: ")
            append(safeEvidence.joinToString("; "))
            append("\nMessage: \"")
            append(safeMessage)
            append("\"")
            // Asking "why it is or is not dangerous" made the 1B model write
            // "this message is not dangerous because it is a scam" for scam verdicts.
            val risky = verdictLabel.contains("HIGH_RISK") || verdictLabel.contains("SUSPICIOUS")
            append(
                if (risky) "\nIn 2 short sentences (at most 15 words each), explain why this message is likely a scam"
                else "\nIn 2 short sentences (at most 15 words each), tell me whether this message looks risky"
            )
            append(". Answer in plain sentences, no bullet points, no links.")
        }

        return buildString {
            append(userPrompt)
            append(EOT_ID)
            append(START_HEADER).append("assistant").append(END_HEADER).append("\n\n")
            // Start the reply ourselves: small instruction-tuned models otherwise
            // tend to refuse anything that mentions a scam message.
            append(answerStart(safeLanguageName))
        }
    }

    fun build(
        verdictLabel: String,
        evidence: List<String>,
        messageText: String,
        languageName: String
    ): String = prefix(languageName) + tail(verdictLabel, evidence, messageText, languageName)

    internal fun answerStart(languageName: String): String = when (languageName) {
        "Hindi" -> "ज़रूर। आसान शब्दों में:\n\n"
        "Tamil" -> "நிச்சயமாக. எளிய வார்த்தைகளில்:\n\n"
        else -> "Sure. Here is a simple explanation:\n\n"
    }

    private fun String.sanitize(): String = replace("<|", "").replace("|>", "")
}
