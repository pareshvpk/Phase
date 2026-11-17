package com.arm.threatassistant.llm

import android.os.Debug
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.result.OfflineExplanation
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device check that the installed Llama model loads through ExecuTorch and
 * produces a guarded explanation. Needs the model installed by the app first.
 * Capture with: `adb logcat -s ARMLLM`
 */
@RunWith(AndroidJUnit4::class)
class LlmDeviceTest {

    private val messages = listOf(
        "Dear SBI customer, your KYC expires today and your account will be blocked. " +
            "Share the OTP sent to your mobile to update KYC now: http://sbi-kyc-update.in/verify",
        "Congratulations! You won Rs 25,00,000 in the KBC lucky draw. Pay Rs 4,999 " +
            "processing fee to claim. Call 9876543210 now."
    )

    private fun log(line: String) = Log.i("ARMLLM", line)

    @Test
    fun llamaExplainsScamMessages() = runBlocking {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        log("cpu_supported=${CpuSupport.isSupported(ctx)}")
        val explainer = LlmExplainerProvider.get(ctx)
        // 32-bit Android / Armv8.0 phones never run Llama: skip instead of failing.
        org.junit.Assume.assumeTrue("Llama unsupported on this CPU/ABI", CpuSupport.isSupported(ctx))
        assertNotNull("Model not installed - open the app once first", explainer)
        explainer!!

        messages.forEachIndexed { i, text ->
            val result = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS)
            val assessment = result.riskAssessment
            val prompt = ExplanationPromptBuilder.build(
                verdictLabel = assessment.verdict.name,
                evidence = assessment.evidenceSummary,
                messageText = text,
                languageName = "English"
            )
            val start = System.nanoTime()
            var firstTokenNs = 0L
            var tokens = 0
            val raw = explainer.explain(prompt) {
                if (tokens == 0) firstTokenNs = System.nanoTime()
                tokens++
            }
            val end = System.nanoTime()
            val genSec = (end - firstTokenNs) / 1e9
            log(
                "msg=$i|verdict=${assessment.verdict}|first_token_ms=${(firstTokenNs - start) / 1_000_000}" +
                    "|total_ms=${(end - start) / 1_000_000}|tokens=$tokens" +
                    "|tok_per_s=${"%.2f".format(if (genSec > 0) (tokens - 1) / genSec else 0.0)}" +
                    "|pss_mb=${Debug.getPss() / 1024}"
            )
            log("msg=$i|raw=${raw.replace('\n', ' ')}")
            val guarded = AdviceGuard.guard(
                text = raw,
                verdict = assessment.verdict,
                languageTag = "en",
                fallback = "FALLBACK_USED",
                safeSteps = OfflineExplanation.safeStepsFor(ctx, assessment.verdict)
            )
            log("msg=$i|guarded=${guarded.replace('\n', ' ')}")
            assertTrue(raw.isNotBlank())
        }
    }
}
