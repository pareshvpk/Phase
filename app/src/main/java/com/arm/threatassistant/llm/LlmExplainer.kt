package com.arm.threatassistant.llm

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmModule
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
    fun stop()
}

/**
 * [LlmExplainer] backed by ExecuTorch's [LlmModule].
 *
 * The native module is created and loaded lazily, exactly once. Loading or
 * generation failures mark the explainer permanently unavailable so the rest
 * of the app continues to work without the LLM feature.
 */
class ExecuTorchLlmExplainer(
    private val files: LlmModelFiles
) : LlmExplainer {

    private companion object {
        const val TEMPERATURE = 0.2f
        const val MAX_SEQ_LEN = 768
        const val MAX_NEW_TOKENS = 150
        const val EOT_ID = "<|eot_id|>"
    }

    private val loadMutex = Mutex()

    @Volatile
    private var module: LlmModule? = null

    @Volatile
    private var unavailable = false

    override fun isAvailable(): Boolean =
        !unavailable && files.model.isFile && files.model.canRead() &&
            files.tokenizer.isFile && files.tokenizer.canRead()

    override suspend fun explain(prompt: String, onToken: (String) -> Unit): String =
        withContext(Dispatchers.Default) {
            val llmModule = ensureLoaded()

            val text = StringBuilder()
            val stopped = AtomicBoolean(false)
            var generatedTokens = 0
            val callback = object : LlmCallback {
                override fun onResult(token: String) {
                    if (stopped.get()) return
                    text.append(token)
                    onToken(token)
                    generatedTokens += 1
                    if (text.contains(EOT_ID) || generatedTokens >= MAX_NEW_TOKENS) {
                        stopped.set(true)
                        runCatching { llmModule.stop() }
                    }
                }
            }

            try {
                // Each explanation is independent: without this the KV cache keeps
                // previous prompts and the context fills up after a few messages.
                llmModule.resetContext()
                llmModule.generate(prompt, MAX_SEQ_LEN, callback, false)
            } catch (t: Throwable) {
                throw Exception("The on-device explanation model failed to generate a response.", t)
            }

            text.toString().replace(EOT_ID, "").trim()
        }

    override fun stop() {
        module?.let { runCatching { it.stop() } }
    }

    private suspend fun ensureLoaded(): LlmModule = loadMutex.withLock {
        if (unavailable) {
            throw Exception("The on-device explanation model is unavailable.")
        }
        module?.let { return@withLock it }

        try {
            val created = LlmModule(
                files.model.absolutePath,
                files.tokenizer.absolutePath,
                TEMPERATURE
            )
            created.load()
            module = created
            created
        } catch (t: Throwable) {
            unavailable = true
            throw Exception("The on-device explanation model could not be loaded.", t)
        }
    }
}

/**
 * Process-wide access point for the optional LLM explainer. Returns null when
 * the model files have not been installed on the device.
 */
object LlmExplainerProvider {

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
