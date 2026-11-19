package com.arm.threatassistant.llm

import android.app.ActivityManager
import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmGenerationConfig
import org.pytorch.executorch.extension.llm.LlmModule
import org.pytorch.executorch.extension.llm.LlmModuleConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Streams a plain-language explanation from the on-device Llama model.
 *
 * Implementations must never influence the detection verdict; they only
 * explain the verdict produced by the detection engine.
 */
interface LlmExplainer {
    fun isAvailable(): Boolean
    suspend fun explain(prompt: String, onToken: (String) -> Unit): String

    /**
     * Generates from a cached [prefix] plus a per-message [tail]. The default
     * implementation simply concatenates them; [ExecuTorchLlmExplainer] reuses
     * the KV cache for the prefix so the first token is much faster.
     */
    suspend fun explain(prefix: String, tail: String, onToken: (String) -> Unit): String =
        explain(prefix + tail, onToken)

    /** Loads the model and prefills [prefix] so the next explanation is fast. */
    suspend fun warmUp(prefix: String) {}

    /** Releases native resources held by this explainer. */
    fun release() {}

    fun stop()
}

/**
 * [LlmExplainer] backed by ExecuTorch's [LlmModule].
 *
 * The native module is created and loaded lazily, exactly once. Loading or
 * generation failures mark the explainer permanently unavailable so the rest
 * of the app continues to work without the LLM feature.
 *
 * A single [genMutex] guards every native call. The system prompt is kept in
 * the KV cache ([prefixReady]); after each generation a background job
 * re-prefills it so the next message only has to process its own short tail.
 */
class ExecuTorchLlmExplainer(
    private val files: LlmModelFiles
) : LlmExplainer {

    private companion object {
        const val TAG = "ARMLLM"
        const val TEMPERATURE = 0f
        const val MAX_SEQ_LEN = 768
        const val MAX_NEW_TOKENS = 70
        const val MAX_SENTENCES = 2
        const val EOT_ID = "<|eot_id|>"
    }

    private val genMutex = Mutex()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var reprefillJob: Job? = null

    @Volatile
    private var module: LlmModule? = null

    @Volatile
    private var unavailable = false

    /** The prefix currently held in the KV cache, or null when it is unknown. */
    @Volatile
    var prefixReady: String? = null
        private set

    /** True once prefix prefill failed; all later calls use the full prompt. */
    @Volatile
    var prefixBroken = false
        private set

    /** Stats reported by the model for the most recent generation. */
    @Volatile
    var lastStats: String? = null
        private set

    override fun isAvailable(): Boolean =
        !unavailable && files.model.isFile && files.model.canRead() &&
            files.tokenizer.isFile && files.tokenizer.canRead()

    override suspend fun explain(prompt: String, onToken: (String) -> Unit): String =
        withContext(Dispatchers.Default) {
            genMutex.withLock {
                val llmModule = ensureLoaded()
                cancelReprefill()
                // The cache is unknown after a reset; the full prompt is processed now.
                prefixReady = null
                try {
                    llmModule.resetContext()
                    generateLocked(llmModule, prompt, onToken)
                } catch (t: Throwable) {
                    throw Exception("The on-device explanation model failed to generate a response.", t)
                }
            }
        }

    override suspend fun explain(
        prefix: String,
        tail: String,
        onToken: (String) -> Unit
    ): String = withContext(Dispatchers.Default) {
        genMutex.withLock {
            val llmModule = ensureLoaded()
            cancelReprefill()

            var fullPrompt = prefixBroken
            if (!prefixBroken && prefixReady != prefix) {
                try {
                    llmModule.resetContext()
                    llmModule.prefillPrompt(prefix)
                } catch (t: Throwable) {
                    // Prefill is an optimisation only; fall back to the full prompt.
                    prefixBroken = true
                    fullPrompt = true
                }
            }

            // Generation appends to the cache, so the cached prefix no longer
            // matches a clean state until the background re-prefill completes.
            prefixReady = null

            val result = try {
                if (fullPrompt) {
                    llmModule.resetContext()
                    generateLocked(llmModule, prefix + tail, onToken)
                } else {
                    generateLocked(llmModule, tail, onToken)
                }
            } catch (t: Throwable) {
                throw Exception("The on-device explanation model failed to generate a response.", t)
            }

            scheduleReprefill(prefix)
            result
        }
    }

    override suspend fun warmUp(prefix: String) = withContext(Dispatchers.Default) {
        genMutex.withLock {
            val llmModule = ensureLoaded()
            cancelReprefill()
            if (prefixReady == prefix) return@withLock
            try {
                llmModule.resetContext()
                llmModule.prefillPrompt(prefix)
                prefixReady = prefix
            } catch (t: Throwable) {
                prefixBroken = true
                prefixReady = null
            }
        }
    }

    override fun release() {
        scope.launch {
            genMutex.withLock {
                cancelReprefill()
                runCatching { module?.close() }
                module = null
                prefixReady = null
            }
        }
    }

    override fun stop() {
        module?.let { runCatching { it.stop() } }
    }

    /** Assumes [genMutex] is held (or called from a context that owns it). */
    private fun ensureLoaded(): LlmModule {
        if (unavailable) {
            throw Exception("The on-device explanation model is unavailable.")
        }
        module?.let { return it }

        try {
            val created = LlmModule(
                LlmModuleConfig.create()
                    .modulePath(files.model.absolutePath)
                    .tokenizerPath(files.tokenizer.absolutePath)
                    .temperature(TEMPERATURE)
                    .loadMode(LlmModuleConfig.LOAD_MODE_MMAP)
                    .build()
            )
            created.load()
            module = created
            return created
        } catch (t: Throwable) {
            unavailable = true
            throw Exception("The on-device explanation model could not be loaded.", t)
        }
    }

    /** Runs one generation; assumes [genMutex] is held. */
    private fun generateLocked(
        llmModule: LlmModule,
        prompt: String,
        onToken: (String) -> Unit
    ): String {
        val text = StringBuilder()
        val stopped = AtomicBoolean(false)
        var generatedTokens = 0
        val callback = object : LlmCallback {
            override fun onResult(token: String) {
                if (stopped.get()) return
                text.append(token)
                onToken(token)
                generatedTokens += 1
                if (text.contains(EOT_ID) ||
                    generatedTokens >= MAX_NEW_TOKENS ||
                    SentenceLimiter.reached(text.toString(), MAX_SENTENCES)
                ) {
                    stopped.set(true)
                    runCatching { llmModule.stop() }
                }
            }

            override fun onStats(stats: String) {
                runCatching {
                    lastStats = stats
                    Log.i(TAG, stats)
                }
            }
        }

        val config = LlmGenerationConfig.create()
            .maxNewTokens(MAX_NEW_TOKENS)
            .temperature(TEMPERATURE)
            .echo(false)
            .seqLen(MAX_SEQ_LEN)
            .build()
        llmModule.generate(prompt, config, callback)
        return text.toString().replace(EOT_ID, "").trim()
    }

    /**
     * Restores the clean prefix in the KV cache after generation so the next
     * message is fast. A new explanation cancels/ignores this job.
     */
    private fun scheduleReprefill(prefix: String) {
        reprefillJob?.cancel()
        reprefillJob = scope.launch {
            genMutex.withLock {
                val llmModule = module ?: return@withLock
                try {
                    llmModule.resetContext()
                    llmModule.prefillPrompt(prefix)
                    prefixReady = prefix
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (t: Throwable) {
                    prefixBroken = true
                    prefixReady = null
                }
            }
        }
    }

    private fun cancelReprefill() {
        reprefillJob?.cancel()
        reprefillJob = null
    }
}

/**
 * Process-wide access point for the optional LLM explainer. Returns null when
 * the model files have not been installed on the device.
 */
object LlmExplainerProvider {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile
    private var explainer: LlmExplainer? = null

    fun get(context: Context): LlmExplainer? {
        explainer?.let { return it }
        // Never touch ExecuTorch's native code on a CPU/process that cannot run it
        // (32-bit Android, Armv8.0): loading it would crash the app.
        if (!CpuSupport.isSupported(context)) return null
        return synchronized(this) {
            explainer ?: LlmModelLocator.locate(context.applicationContext)
                ?.let { files -> ExecuTorchLlmExplainer(files) }
                ?.also { explainer = it }
        }
    }

    /**
     * Loads the model and prefills the explanation prefix in the background so
     * the first explanation is fast. Skips low-memory devices and unsupported CPUs.
     */
    fun warmUp(context: Context, languageName: String) {
        if (!CpuSupport.isSupported(context)) return
        val app = context.applicationContext
        if (LlmModelLocator.locate(app) == null) return
        val activityManager = app.getSystemService(ActivityManager::class.java) ?: return
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)
        if (memoryInfo.totalMem < 6L * 1024 * 1024 * 1024) return

        scope.launch {
            delay(2_000)
            runCatching {
                get(app)?.warmUp(ExplanationPromptBuilder.prefix(languageName))
            }
        }
    }

    /** Drops the loaded model and its KV cache to free memory. */
    fun release() {
        explainer?.release()
    }

    /**
     * Drops the cached explainer (including a cached "unavailable") so the next
     * [get] re-locates the files. Called after the bundled model is installed.
     */
    fun refresh() {
        synchronized(this) {
            explainer?.stop()
            explainer = null
        }
    }
}
