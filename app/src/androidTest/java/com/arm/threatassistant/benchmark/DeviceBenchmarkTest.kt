package com.arm.threatassistant.benchmark

import android.os.Debug
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.sms.SensitiveSmsFilter
import com.arm.threatassistant.sms.SensitiveSmsKind
import com.arm.threatassistant.sms.SmsAlertPolicy
import java.util.Locale
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import org.junit.runner.RunWith

private data class Sample(val label: String, val expectedKind: SensitiveSmsKind?, val text: String)

/**
 * On-device benchmark and correctness harness for the SMS threat pipeline.
 *
 * Every record is emitted through `android.util.Log.i("ARMBENCH", line)` so the
 * whole run can be captured with:
 * `adb logcat -s ARMBENCH`
 *
 * Records are single lines whose fields are separated by "|".
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class DeviceBenchmarkTest {

    private val corpus: List<Sample> = listOf(
        Sample(
            "SCAM",
            null,
            "Rs 5000 will be credited to your a/c. Click this link to receive the amount http://bit.ly/x9z"
        ),
        Sample(
            "SCAM",
            null,
            "Your a/c is credited with Rs 25,000 lottery prize. Claim now at www.prize-claim.top"
        ),
        Sample(
            "SCAM",
            null,
            "UPI cashback of Rs 2000 pending. Tap https://upi-reward.xyz/claim to collect payment of Rs 2000"
        ),
        Sample(
            "SCAM",
            null,
            "Dear customer share your OTP 445566 with our agent to complete KYC"
        ),
        Sample(
            "SCAM",
            null,
            "Congratulations you won Rs 50000 prize, click www.win.top"
        ),
        Sample(
            "SCAM",
            null,
            "Your SBI account will be suspended today. Update KYC immediately at http://sbi-kyc-verify.xyz/login"
        ),
        Sample(
            "SCAM",
            null,
            "Electricity power will be disconnected tonight 9.30pm. Call officer 9876543210 immediately"
        ),
        Sample(
            "SCAM",
            null,
            "Your parcel is on hold due to incomplete address. Pay Rs 25 fee at https://indiapost-track.top/pay"
        ),
        Sample(
            "SCAM",
            null,
            "URGENT: You have been selected for a work from home job. Earn Rs 8000 daily. WhatsApp wa.me/919876543210"
        ),
        Sample(
            "SCAM",
            null,
            "Your PAN card is blocked. Click http://pan-update.info to verify and avoid penalty"
        ),
        Sample("BENIGN", null, "Hey are we still meeting at 5 today?"),
        Sample("BENIGN", null, "Mom called, please ring her back when you are free"),
        Sample("BENIGN", null, "Your order has been shipped and will arrive tomorrow"),
        Sample("BENIGN", null, "Happy birthday! Have a great year ahead"),
        Sample("BENIGN", null, "Running 10 mins late, start without me"),
        Sample("BENIGN", null, "Reminder: dentist appointment on Monday at 10am"),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.OTP,
            "123456 is your OTP for txn of INR 2,499.00 at AMAZON on HDFC Bank card"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.OTP,
            "Use 4821 as your login OTP for Paytm. Never share it. Visit paytm.com/"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.OTP,
            "OTP for your SBI internet banking login is 55443322. Do not share with anyone"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.TRANSACTION,
            "Rs.1,250.00 debited from A/c XX4321 on 12-Nov-26 to VPA abc@okaxis (UPI Ref 431298765432)"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.TRANSACTION,
            "Dear Customer, Rs 499 spent on your SBI Credit Card ending 1234 at SWIGGY on 13/11/26. " +
                "If not done by you, click https://sbicard.com/dispute"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.TRANSACTION,
            "You have received Rs 500.00 from RAMESH K in your a/c XX1234. UPI Ref 431298765432. " +
                "Details: https://hdfc.bk/a1b2"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.TRANSACTION,
            "Dear Customer, your refund of Rs. 349.00 has been credited to your a/c XX9876"
        ),
        Sample(
            "SENSITIVE",
            SensitiveSmsKind.TRANSACTION,
            "Txn of USD 12.99 done on your Axis Bank card XX4455 at NETFLIX.COM. Avl limit Rs 85,000"
        )
    )

    private fun stats(name: String, nanos: LongArray) {
        val sorted = nanos.copyOf()
        sorted.sort()
        val n = sorted.size
        if (n == 0) {
            Log.i(TAG, "STAT|$name|n=0|mean_us=0.0|median_us=0.0|p95_us=0.0|p99_us=0.0|max_us=0.0|min_us=0.0")
            return
        }
        var sum = 0L
        for (v in sorted) sum += v
        val mean = sum.toDouble() / n.toDouble()
        val median = sorted[percentileIndex(n, 0.50)].toDouble()
        val p95 = sorted[percentileIndex(n, 0.95)].toDouble()
        val p99 = sorted[percentileIndex(n, 0.99)].toDouble()
        val max = sorted[n - 1].toDouble()
        val min = sorted[0].toDouble()
        Log.i(
            TAG,
            String.format(
                Locale.US,
                "STAT|%s|n=%d|mean_us=%.1f|median_us=%.1f|p95_us=%.1f|p99_us=%.1f|max_us=%.1f|min_us=%.1f",
                name,
                n,
                mean / 1000.0,
                median / 1000.0,
                p95 / 1000.0,
                p99 / 1000.0,
                max / 1000.0,
                min / 1000.0
            )
        )
    }

    private fun percentileIndex(n: Int, p: Double): Int {
        val idx = ((n - 1) * p).toInt()
        return if (idx < 0) 0 else if (idx > n - 1) n - 1 else idx
    }

    @Test
    fun test1_coldFirstAnalyze() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val text = corpus[0].text

        val t0 = System.nanoTime()
        val first = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS)
        val t1 = System.nanoTime()
        sink = sink xor first.hashCode()
        Log.i(
            TAG,
            String.format(Locale.US, "COLD|first_analyze_ms=%.2f", (t1 - t0) / 1_000_000.0)
        )

        val t2 = System.nanoTime()
        val second = ThreatAnalyzer.analyze(ctx, text, InputSource.SMS)
        val t3 = System.nanoTime()
        sink = sink xor second.hashCode()
        Log.i(
            TAG,
            String.format(Locale.US, "COLD|second_analyze_ms=%.2f", (t3 - t2) / 1_000_000.0)
        )

        assertNotNull(first)
        assertNotNull(second)
    }

    @Test
    fun test2_filterCorrectnessOnDevice() {
        var failCount = 0
        for (sample in corpus) {
            val actual = SensitiveSmsFilter.classify(sample.text)
            val pass = actual == sample.expectedKind
            if (!pass) failCount++
            sink = sink xor (actual?.ordinal ?: -1)
            Log.i(
                TAG,
                "FILTER|${if (pass) "PASS" else "FAIL"}|expected=${sample.expectedKind}" +
                    "|actual=${actual}|${sample.text.take(50)}"
            )
        }
        assertEquals(0, failCount)
    }

    @Test
    fun test3_verdictsOnDevice() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        var scamTotal = 0
        var scamAlerted = 0
        var benignTotal = 0
        var benignAlerted = 0
        var sensitiveTotal = 0
        var sensitiveSkipped = 0
        var sensitiveAlerted = 0

        for (sample in corpus) {
            val kind = SensitiveSmsFilter.classify(sample.text)
            val outcome: String
            var alert = false
            if (kind != null) {
                outcome = "SKIPPED"
            } else {
                val verdict: ThreatVerdictLevel =
                    ThreatAnalyzer.analyze(ctx, sample.text, InputSource.SMS).riskAssessment.verdict
                outcome = verdict.name
                alert = SmsAlertPolicy.shouldAlert(verdict)
                sink = sink xor verdict.ordinal
            }
            sink = sink xor (kind?.ordinal ?: -1)

            Log.i(
                TAG,
                "VERDICT|${sample.label}|$outcome|alert=$alert|${sample.text.take(50)}"
            )

            when (sample.label) {
                "SCAM" -> {
                    scamTotal++
                    if (alert) scamAlerted++
                }
                "BENIGN" -> {
                    benignTotal++
                    if (alert) benignAlerted++
                }
                "SENSITIVE" -> {
                    sensitiveTotal++
                    if (outcome == "SKIPPED") {
                        sensitiveSkipped++
                    } else if (alert) {
                        sensitiveAlerted++
                    }
                }
            }
        }

        Log.i(
            TAG,
            "SUMMARY|scam_total=$scamTotal|scam_alerted=$scamAlerted" +
                "|benign_total=$benignTotal|benign_alerted=$benignAlerted" +
                "|sensitive_total=$sensitiveTotal|sensitive_skipped=$sensitiveSkipped" +
                "|sensitive_alerted=$sensitiveAlerted"
        )

        assertEquals(sensitiveTotal, sensitiveSkipped)
    }

    @Test
    fun test4_benchmarkFilter() {
        for (i in 0 until 2000) {
            val warm = SensitiveSmsFilter.classify(corpus[i % corpus.size].text)
            sink = sink xor (warm?.ordinal ?: -1)
        }

        val samples = LongArray(20000)
        for (i in samples.indices) {
            val sample = corpus[i % corpus.size]
            val t0 = System.nanoTime()
            val result = SensitiveSmsFilter.classify(sample.text)
            val t1 = System.nanoTime()
            samples[i] = t1 - t0
            sink = sink xor (result?.ordinal ?: -1)
        }
        stats("filter_classify", samples)
    }

    @Test
    fun test5_benchmarkAnalyze() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext

        for (i in 0 until 200) {
            val warm = ThreatAnalyzer.analyze(ctx, corpus[i % corpus.size].text, InputSource.SMS)
            sink = sink xor warm.hashCode()
        }

        val samples = LongArray(2000)
        val scam = LongArray(2000)
        var scamCount = 0
        val benign = LongArray(2000)
        var benignCount = 0
        val sensitive = LongArray(2000)
        var sensitiveCount = 0

        for (i in samples.indices) {
            val sample = corpus[i % corpus.size]
            val t0 = System.nanoTime()
            val result = ThreatAnalyzer.analyze(ctx, sample.text, InputSource.SMS)
            val t1 = System.nanoTime()
            val elapsed = t1 - t0
            samples[i] = elapsed
            sink = sink xor result.hashCode()
            when (sample.label) {
                "SCAM" -> scam[scamCount++] = elapsed
                "BENIGN" -> benign[benignCount++] = elapsed
                "SENSITIVE" -> sensitive[sensitiveCount++] = elapsed
            }
        }

        stats("analyze_full", samples)
        stats("analyze_SCAM", scam.copyOf(scamCount))
        stats("analyze_BENIGN", benign.copyOf(benignCount))
        stats("analyze_SENSITIVE", sensitive.copyOf(sensitiveCount))
    }

    @Test
    fun test6_benchmarkReceiverPath() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext

        for (i in 0 until 200) {
            val sample = corpus[i % corpus.size]
            if (SensitiveSmsFilter.shouldSkip(sample.text)) continue
            val verdict = ThreatAnalyzer.analyze(ctx, sample.text, InputSource.SMS).riskAssessment.verdict
            sink = sink xor verdict.ordinal xor SmsAlertPolicy.shouldAlert(verdict).hashCode()
        }

        val samples = LongArray(2000)
        var totalNanos = 0L
        for (i in samples.indices) {
            val sample = corpus[i % corpus.size]
            val t0 = System.nanoTime()
            if (!SensitiveSmsFilter.shouldSkip(sample.text)) {
                val verdict = ThreatAnalyzer.analyze(ctx, sample.text, InputSource.SMS).riskAssessment.verdict
                val alert = SmsAlertPolicy.shouldAlert(verdict)
                sink = sink xor verdict.ordinal xor alert.hashCode()
            }
            val t1 = System.nanoTime()
            samples[i] = t1 - t0
            totalNanos += samples[i]
        }

        stats("receiver_path", samples)

        val elapsedSeconds = totalNanos / 1_000_000_000.0
        val perSecond = if (elapsedSeconds > 0.0) samples.size / elapsedSeconds else 0.0
        Log.i(
            TAG,
            String.format(Locale.US, "THROUGHPUT|receiver_path_msgs_per_sec=%.0f", perSecond)
        )
    }

    @Test
    fun test7_longMessage() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext

        val base = corpus[5].text
        val builder = StringBuilder()
        while (builder.length < 1600) {
            if (builder.isNotEmpty()) builder.append(' ')
            builder.append(base)
        }
        val longMessage = builder.toString().trim().take(1600)

        for (i in 0 until 20) {
            val warm = ThreatAnalyzer.analyze(ctx, longMessage, InputSource.SMS)
            sink = sink xor warm.hashCode()
        }

        val samples = LongArray(200)
        for (i in samples.indices) {
            val t0 = System.nanoTime()
            val result = ThreatAnalyzer.analyze(ctx, longMessage, InputSource.SMS)
            val t1 = System.nanoTime()
            samples[i] = t1 - t0
            sink = sink xor result.hashCode()
        }
        stats("analyze_1600_chars", samples)
    }

    @Test
    fun test8_memory() {
        Runtime.getRuntime().gc()
        val runtime = Runtime.getRuntime()
        val javaUsedKb = (runtime.totalMemory() - runtime.freeMemory()) / 1024
        val nativeHeapKb = Debug.getNativeHeapAllocatedSize() / 1024
        Log.i(TAG, "MEM|java_used_kb=$javaUsedKb|native_heap_kb=$nativeHeapKb")
    }

    companion object {
        private const val TAG = "ARMBENCH"

        @Volatile
        @JvmStatic
        var sink: Int = 0

        // A visible activity keeps the process in the foreground; without it
        // the OEM app freezer suspends the instrumented process mid-run.
        private var activity: android.app.Activity? = null

        @org.junit.BeforeClass
        @JvmStatic
        fun keepForeground() {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val intent = android.content.Intent(instrumentation.targetContext, com.arm.threatassistant.MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            activity = instrumentation.startActivitySync(intent)
        }

        @AfterClass
        @JvmStatic
        fun printSummary() {
            activity?.finish()
            Log.i(TAG, "DONE|bench=DeviceBenchmarkTest|status=completed|sink=$sink")
            Log.i(TAG, "DONE|logcat=ARMBENCH|records=COLD,FILTER,VERDICT,SUMMARY,STAT,THROUGHPUT,MEM")
        }
    }
}
