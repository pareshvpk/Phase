package com.arm.threatassistant.benchmark

import android.os.Debug
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.llm.AdviceGuard
import com.arm.threatassistant.llm.ExplanationPromptBuilder
import com.arm.threatassistant.llm.LlmExplainerProvider
import com.arm.threatassistant.presentation.result.OfflineExplanation
import com.arm.threatassistant.sms.SensitiveSmsFilter
import com.arm.threatassistant.sms.SmsAlertPolicy
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/**
 * End-to-end accuracy, soak, concurrency, hostile-input and Llama stress tests.
 *
 * Accuracy uses the held-out test split from tools/sms_classifier/build_dataset.py,
 * pushed beforehand with:
 *   adb push tools/sms_classifier/data/test.csv /data/local/tmp/arm_eval/test.csv
 * Results are logged with tag ARMSTRESS (`adb logcat -s ARMSTRESS`).
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class StressAndAccuracyDeviceTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    private data class Row(val text: String, val scam: Boolean, val language: String, val real: Boolean)

    private data class Outcome(val skipped: Boolean, val verdict: ThreatVerdictLevel?, val alert: Boolean) {
        /** What the user sees as a warning in the app (Check tab or SMS alert). */
        val flagged get() = verdict == ThreatVerdictLevel.HIGH_RISK || verdict == ThreatVerdictLevel.SUSPICIOUS
    }

    private fun log(line: String) = Log.i(TAG, line)

    /** The SMS receiver path: sensitive filter first, then the full analysis. */
    private fun runPipeline(text: String): Outcome {
        if (SensitiveSmsFilter.shouldSkip(text)) return Outcome(skipped = true, verdict = null, alert = false)
        val verdict = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS).riskAssessment.verdict
        return Outcome(skipped = false, verdict = verdict, alert = SmsAlertPolicy.shouldAlert(verdict))
    }

    private fun loadTestSet(): List<Row> {
        val file = File(EVAL_CSV)
        assumeTrue("Push the test split to $EVAL_CSV first", file.canRead())
        val records = parseCsv(file.readText(Charsets.UTF_8))
        val header = records.first()
        val text = header.indexOf("text")
        val label = header.indexOf("label")
        val lang = header.indexOf("language")
        val real = header.indexOf("real")
        return records.drop(1).filter { it.size == header.size }.map {
            Row(it[text], it[label] == "1", it[lang], it[real] == "True")
        }
    }

    // ---------------------------------------------------------------------
    // 1. End-to-end accuracy on the held-out test set
    // ---------------------------------------------------------------------

    @Test
    fun test1_endToEndAccuracy() {
        val rows = loadTestSet()
        val results = rows.map { it to runPipeline(it.text) }

        fun report(name: String, subset: List<Pair<Row, Outcome>>) {
            val scams = subset.filter { it.first.scam }
            val safe = subset.filter { !it.first.scam }
            if (scams.isEmpty() && safe.isEmpty()) return
            val alerted = scams.count { it.second.alert }
            val flagged = scams.count { it.second.flagged }
            val skipped = scams.count { it.second.skipped }
            val falseAlerts = safe.count { it.second.alert }
            val falseFlags = safe.count { it.second.flagged }
            log(
                "ACC|$name|scam_n=${scams.size}|scam_alerted=$alerted|alert_recall=${pct(alerted, scams.size)}" +
                    "|scam_flagged=$flagged|flag_recall=${pct(flagged, scams.size)}|scam_skipped_by_filter=$skipped" +
                    "|safe_n=${safe.size}|false_alerts=$falseAlerts|false_alert_rate=${pct(falseAlerts, safe.size)}" +
                    "|false_flags=$falseFlags|false_flag_rate=${pct(falseFlags, safe.size)}"
            )
        }

        report("all", results)
        report("real_only", results.filter { it.first.real })
        report("synthetic_only", results.filter { !it.first.real })
        for (lang in results.map { it.first.language }.distinct().sorted()) {
            report("lang_$lang", results.filter { it.first.language == lang })
        }

        val verdicts = results.groupingBy { (row, o) -> "${if (row.scam) "SCAM" else "SAFE"}->${o.verdict?.name ?: "SKIPPED"}" }
            .eachCount()
        verdicts.toSortedMap().forEach { (k, v) -> log("ACC_VERDICTS|$k|$v") }

        // A sample of errors on real messages, for error analysis (public dataset text only).
        results.filter { it.first.real && it.first.scam && !it.second.alert }.take(25).forEach {
            log("MISSED|${it.first.language}|${it.second.verdict?.name ?: "SKIPPED"}|${it.first.text.take(110).replace('\n', ' ')}")
        }
        results.filter { it.first.real && !it.first.scam && it.second.alert }.take(25).forEach {
            log("FALSE_ALERT|${it.first.language}|${it.second.verdict?.name}|${it.first.text.take(110).replace('\n', ' ')}")
        }
        assertTrue(results.isNotEmpty())
    }

    // ---------------------------------------------------------------------
    // 2. Soak: 10,000 analyses, throughput and memory growth
    // ---------------------------------------------------------------------

    @Test
    fun test2_soak10k() {
        val texts = loadTestSet().map { it.text }
        repeat(300) { runPipeline(texts[it % texts.size]) }
        val before = memorySnapshot()
        val n = 10_000
        val lat = LongArray(n)
        val start = System.nanoTime()
        for (i in 0 until n) {
            val t0 = System.nanoTime()
            runPipeline(texts[i % texts.size])
            lat[i] = System.nanoTime() - t0
        }
        val totalSec = (System.nanoTime() - start) / 1e9
        val after = memorySnapshot()
        stats("soak_pipeline", lat)
        log("SOAK|n=$n|seconds=${"%.2f".format(totalSec)}|msgs_per_sec=${"%.0f".format(n / totalSec)}")
        log("SOAK_MEM|before=$before|after=$after|java_growth_kb=${after.javaKb - before.javaKb}|pss_growth_kb=${after.pssKb - before.pssKb}")
        // Leak guard: Java heap must not grow by more than 20 MB over 10k analyses.
        assertTrue("Java heap grew ${after.javaKb - before.javaKb} KB", after.javaKb - before.javaKb < 20 * 1024)
    }

    // ---------------------------------------------------------------------
    // 3. Concurrency: 8 threads at once must give the same verdicts as 1 thread
    // ---------------------------------------------------------------------

    @Test
    fun test3_concurrentAnalysis() {
        val texts = loadTestSet().map { it.text }.take(400)
        val reference = texts.associateWith { runPipeline(it).verdict }
        val threads = 8
        val perThread = 500
        val pool = Executors.newFixedThreadPool(threads)
        val start = System.nanoTime()
        val futures = (0 until threads).map { t ->
            pool.submit(Callable {
                var mismatches = 0
                for (i in 0 until perThread) {
                    val text = texts[(t * 37 + i) % texts.size]
                    if (runPipeline(text).verdict != reference[text]) mismatches++
                }
                mismatches
            })
        }
        val mismatches = futures.sumOf { it.get(5, TimeUnit.MINUTES) }
        pool.shutdown()
        val sec = (System.nanoTime() - start) / 1e9
        val total = threads * perThread
        log("CONCURRENCY|threads=$threads|analyses=$total|seconds=${"%.2f".format(sec)}" +
            "|msgs_per_sec=${"%.0f".format(total / sec)}|verdict_mismatches=$mismatches")
        assertEquals("Verdicts differ under concurrency", 0, mismatches)
    }

    // ---------------------------------------------------------------------
    // 4. Hostile and edge-case inputs: no crash, bounded time
    // ---------------------------------------------------------------------

    @Test
    fun test4_hostileInputs() {
        val inputs = linkedMapOf(
            "empty" to "",
            "spaces" to "     \n\t  ",
            "50k_letters" to "A".repeat(50_000),
            "20k_single_token" to "x".repeat(20_000),
            "5k_emoji" to "😀🔥💰".repeat(1_700),
            "zero_width_only" to "​‌‍⁠".repeat(500),
            "zero_width_in_scam" to "Sh​are yo‌ur O‍TP to un⁠block your acc​ount",
            "rtl_arabic" to "حسابك المصرفي سيتم إغلاقه اضغط على الرابط",
            "mixed_scripts" to "Your खाता வங்கி account 账户 will be blocked, click http://x.co",
            "unpaired_surrogate" to "Win \uD800 prize \uDC00 now",
            "nul_chars" to "OTP\u0000share\u0000now",
            "500_urls" to (1..500).joinToString(" ") { "http://scam$it.xyz/a?b=$it" },
            "huge_url" to "http://" + "a".repeat(10_000) + ".com/" + "b".repeat(10_000),
            "html_script" to "<script>alert('x')</script><a href='http://evil.top'>Claim prize</a>",
            "sql_like" to "'; DROP TABLE sms; -- your KYC expires",
            "digits_only" to "9".repeat(5_000),
            "punctuation" to "!?.,;:".repeat(3_000),
            "combining_marks" to "á̂̃̄".repeat(2_000),
            "tamil_long" to "உங்கள் வங்கி கணக்கு முடக்கப்படும் ".repeat(400),
            "devanagari_long" to "आपका खाता बंद हो जाएगा ".repeat(400)
        )
        var failures = 0
        for ((name, text) in inputs) {
            val t0 = System.nanoTime()
            val outcome = runCatching { runPipeline(text) }
            val ms = (System.nanoTime() - t0) / 1e6
            val ok = outcome.isSuccess && ms < 3_000
            if (!ok) failures++
            log("HOSTILE|$name|chars=${text.length}|ms=${"%.1f".format(ms)}|ok=$ok|" +
                (outcome.getOrNull()?.let { "verdict=${it.verdict?.name ?: "SKIPPED"}" }
                    ?: "error=${outcome.exceptionOrNull()?.javaClass?.simpleName}: ${outcome.exceptionOrNull()?.message?.take(80)}"))
        }
        assertEquals("Hostile inputs crashed or took > 3 s", 0, failures)
    }

    // ---------------------------------------------------------------------
    // 5. Llama: 10 explanations in a row, then cancel mid-generation
    // ---------------------------------------------------------------------

    @Test
    fun test5_llamaRepeatedAndCancel() = runBlocking {
        val explainer = LlmExplainerProvider.get(ctx)
        assumeTrue("Llama model not on the device", explainer != null)
        explainer!!
        val scams = loadTestSet().filter { it.scam && it.language == "en" && it.real }.map { it.text }.take(10)
        var fallbacks = 0
        for ((i, text) in scams.withIndex()) {
            val assessment = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS).riskAssessment
            val prompt = ExplanationPromptBuilder.build(assessment.verdict.name, assessment.evidenceSummary, text, "English")
            val t0 = System.nanoTime()
            var first = 0L
            var tokens = 0
            val raw = explainer.explain(prompt) { if (tokens++ == 0) first = System.nanoTime() }
            val end = System.nanoTime()
            val guarded = AdviceGuard.guard(raw, assessment.verdict, "en", "FALLBACK", OfflineExplanation.safeStepsFor(ctx, assessment.verdict))
            if (guarded == "FALLBACK") {
                fallbacks++
                log("LLM_FALLBACK_RAW|i=$i|${raw.replace('\n', ' ').take(600)}")
            }
            val gen = (end - first) / 1e9
            log("LLM_RUN|i=$i|verdict=${assessment.verdict}|first_token_ms=${(first - t0) / 1_000_000}|total_ms=${(end - t0) / 1_000_000}" +
                "|tokens=$tokens|tok_per_s=${"%.2f".format(if (gen > 0) (tokens - 1) / gen else 0.0)}|pss_mb=${Debug.getPss() / 1024}" +
                "|guard_fallback=${guarded == "FALLBACK"}")
        }
        log("LLM_SUMMARY|runs=${scams.size}|guard_fallbacks=$fallbacks")

        // Cancel: stop() during generation must return quickly and leave the model usable.
        val text = scams.first()
        val assessment = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS).riskAssessment
        val prompt = ExplanationPromptBuilder.build(assessment.verdict.name, assessment.evidenceSummary, text, "English")
        var tokensBeforeStop = 0
        val job = async(Dispatchers.IO) { explainer.explain(prompt) { tokensBeforeStop++ } }
        while (tokensBeforeStop < 5) delay(50)
        val stopAt = System.nanoTime()
        explainer.stop()
        job.await()
        val stopMs = (System.nanoTime() - stopAt) / 1_000_000
        val again = withContext(Dispatchers.IO) { explainer.explain(prompt) { } }
        log("LLM_CANCEL|tokens_before_stop=$tokensBeforeStop|stop_to_return_ms=$stopMs|works_after_cancel=${again.isNotBlank()}")
        assertTrue("Explainer unusable after cancel", again.isNotBlank())
        assertTrue("stop() took $stopMs ms", stopMs < 3_000)
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private data class Mem(val javaKb: Long, val nativeKb: Long, val pssKb: Long) {
        override fun toString() = "java_kb=$javaKb,native_kb=$nativeKb,pss_kb=$pssKb"
    }

    private fun memorySnapshot(): Mem {
        repeat(3) { Runtime.getRuntime().gc(); Thread.sleep(100) }
        val rt = Runtime.getRuntime()
        return Mem((rt.totalMemory() - rt.freeMemory()) / 1024, Debug.getNativeHeapAllocatedSize() / 1024, Debug.getPss())
    }

    private fun stats(name: String, nanos: LongArray) {
        val sorted = nanos.sortedArray()
        fun p(q: Double) = sorted[((sorted.size - 1) * q).toInt()] / 1000.0
        log("STAT|$name|n=${sorted.size}|mean_us=${"%.1f".format(sorted.average() / 1000.0)}|median_us=${"%.1f".format(p(0.5))}" +
            "|p95_us=${"%.1f".format(p(0.95))}|p99_us=${"%.1f".format(p(0.99))}|max_us=${"%.1f".format(sorted.last() / 1000.0)}")
    }

    private fun pct(a: Int, b: Int) = if (b == 0) "n/a" else "%.1f%%".format(100.0 * a / b)

    /** RFC 4180 CSV: quoted fields may contain commas, quotes ("") and newlines. */
    private fun parseCsv(text: String): List<List<String>> {
        val records = mutableListOf<List<String>>()
        var field = StringBuilder()
        var record = mutableListOf<String>()
        var inQuotes = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                inQuotes && c == '"' && i + 1 < text.length && text[i + 1] == '"' -> { field.append('"'); i++ }
                c == '"' -> inQuotes = !inQuotes
                !inQuotes && c == ',' -> { record.add(field.toString()); field = StringBuilder() }
                !inQuotes && (c == '\n' || c == '\r') -> {
                    if (c == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    record.add(field.toString()); field = StringBuilder()
                    records.add(record); record = mutableListOf()
                }
                else -> field.append(c)
            }
            i++
        }
        if (field.isNotEmpty() || record.isNotEmpty()) { record.add(field.toString()); records.add(record) }
        return records
    }

    private companion object {
        const val TAG = "ARMSTRESS"
        const val EVAL_CSV = "/data/local/tmp/arm_eval/test.csv"
    }
}
