package com.arm.threatassistant.llm

/**
 * Builds Llama 3 chat-formatted prompts for the plain-language explanation.
 *
 * Pure Kotlin with no Android dependencies so it can be unit-tested on the JVM.
 * The detection verdict is authoritative and is passed to the model as fixed
 * context; the model is only asked to explain it.
 */
object ExplanationPromptBuilder {

    internal const val SYSTEM_PROMPT =
        "You are a friendly phone-safety helper who protects people from SMS fraud. " +
            "The user's security app has already checked a message they received and decided " +
            "the verdict; treat that verdict as correct and do not question it. Help the user " +
            "stay safe by explaining the warning in plain, simple words. Do not repeat links or " +
            "phone numbers from the message. Never tell the user to click links, call numbers, " +
            "reply, or share codes."

    private const val BEGIN_OF_TEXT = "<|begin_of_text|>"
    private const val START_HEADER = "<|start_header_id|>"
    private const val END_HEADER = "<|end_header_id|>"
    private const val EOT_ID = "<|eot_id|>"

    private const val MAX_MESSAGE_LENGTH = 500
    private const val MAX_EVIDENCE_ITEMS = 8

    fun build(
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

        val userPrompt = buildString {
            append("I received this SMS and my phone's security app warned me about it. ")
            append("Please help me understand the warning.\n")
            append("Verdict: ")
            append(verdictLabel.replace("<|", "").replace("|>", ""))
            append("\nReasons found: ")
            append(safeEvidence.joinToString("; "))
            append("\nMessage: \"")
            append(safeMessage)
            append("\"")
            append("\nIn 2-4 short, simple sentences, tell me why this message is or is not ")
            append("dangerous and what I should do to stay safe.")
        }

        return buildString {
            append(BEGIN_OF_TEXT)
            append(START_HEADER).append("system").append(END_HEADER).append("\n\n")
            append(SYSTEM_PROMPT)
            append(" Write the explanation in ")
            append(safeLanguageName)
            append('.')
            append(EOT_ID)
            append(START_HEADER).append("user").append(END_HEADER).append("\n\n")
            append(userPrompt)
            append(EOT_ID)
            append(START_HEADER).append("assistant").append(END_HEADER).append("\n\n")
            // Start the reply ourselves: small instruction-tuned models otherwise
            // tend to refuse anything that mentions a scam message.
            append(answerStart(safeLanguageName))
        }
    }

    internal fun answerStart(languageName: String): String = when (languageName) {
        "Hindi" -> "ज़रूर। आसान शब्दों में:\n\n"
        "Tamil" -> "நிச்சயமாக. எளிய வார்த்தைகளில்:\n\n"
        else -> "Sure. Here is a simple explanation:\n\n"
    }

    private fun String.sanitize(): String = replace("<|", "").replace("|>", "")
}
