package com.arm.threatassistant.llm

import android.content.Context
import java.io.File

/**
 * On-device Llama model files. The model and tokenizer are usually downloaded
 * once by [LlmModelInstaller]; copies placed on the phone by other means also work.
 */
data class LlmModelFiles(val model: File, val tokenizer: File)

/**
 * Locates the optional on-device Llama files. Both files must exist and be
 * readable for the LLM feature to be available.
 */
object LlmModelLocator {

    private const val MODEL_FILE_NAME = "llama3_2_1b.pte"
    private const val TOKENIZER_FILE_NAME = "tokenizer.model"
    private const val ADB_DIRECTORY = "/data/local/tmp/llama"

    fun locate(context: Context): LlmModelFiles? {
        val directories = buildList {
            // Preferred: files from a completed download (or an earlier bundled install).
            if (LlmModelInstaller.isInstalled(context)) {
                add(LlmModelInstaller.installDir(context))
            }
            // Side-loaded model files.
            context.getExternalFilesDir("llm")?.let { add(it) }
            add(File(ADB_DIRECTORY))
        }

        for (directory in directories) {
            val model = File(directory, MODEL_FILE_NAME)
            val tokenizer = File(directory, TOKENIZER_FILE_NAME)
            if (model.isReadableFile() && tokenizer.isReadableFile()) {
                return LlmModelFiles(model = model, tokenizer = tokenizer)
            }
        }
        return null
    }

    private fun File.isReadableFile(): Boolean = isFile && canRead()
}
