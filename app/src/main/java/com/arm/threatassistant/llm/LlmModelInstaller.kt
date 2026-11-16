package com.arm.threatassistant.llm

import android.content.Context
import android.os.StatFs
import com.arm.threatassistant.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.Properties

/** Thrown when the device does not have room for the bundled model files. */
class InsufficientStorageException(message: String) : IOException(message)

/**
 * Pure installation helpers. Kept free of Android APIs so the marker matching,
 * free-space requirement and progress maths can be unit-tested on the JVM.
 */
object LlmInstallLogic {

    const val RESERVE_BYTES = 50L * 1024L * 1024L

    data class Marker(
        val modelBytes: Long,
        val tokenizerBytes: Long,
        val versionCode: Long
    )

    /** Asset bytes plus the 50 MB safety reserve. */
    fun requiredFreeBytes(assetBytes: Long): Long = assetBytes + RESERVE_BYTES

    fun hasEnoughSpace(availableBytes: Long, assetBytes: Long): Boolean =
        availableBytes >= requiredFreeBytes(assetBytes)

    /** Overall install progress in 0..1 across both asset files. */
    fun progress(copiedBytes: Long, totalBytes: Long): Float {
        if (totalBytes <= 0L) return 0f
        return (copiedBytes.toDouble() / totalBytes.toDouble()).toFloat().coerceIn(0f, 1f)
    }

    fun markerMatches(installed: Marker?, expected: Marker): Boolean = installed == expected
}

/**
 * Installs the Llama model and tokenizer that are bundled as APK assets into
 * `noBackupFilesDir/llm`, where the explainer can open them as regular files.
 *
 * The install runs at most once per process (guarded by [installMutex]) and is
 * skipped when the marker file proves a previous completed install for the
 * current APK version.
 */
object LlmModelInstaller {

    private const val DIR_NAME = "llm"
    private const val MODEL_FILE_NAME = "llama3_2_1b.pte"
    private const val TOKENIZER_FILE_NAME = "tokenizer.model"
    private const val MARKER_FILE_NAME = "installed.properties"
    private const val TMP_SUFFIX = ".tmp"
    private const val BUFFER_SIZE = 1 shl 20

    private const val KEY_MODEL_BYTES = "model.bytes"
    private const val KEY_TOKENIZER_BYTES = "tokenizer.bytes"
    private const val KEY_VERSION_CODE = "versionCode"

    private val installMutex = Mutex()

    fun installDir(context: Context): File =
        File(context.noBackupFilesDir, DIR_NAME)

    fun modelFile(context: Context): File = File(installDir(context), MODEL_FILE_NAME)

    fun tokenizerFile(context: Context): File = File(installDir(context), TOKENIZER_FILE_NAME)

    /** True when both model assets are present inside the APK. */
    fun isBundled(context: Context): Boolean = runCatching {
        val entries = context.assets.list(DIR_NAME)?.toSet().orEmpty()
        MODEL_FILE_NAME in entries && TOKENIZER_FILE_NAME in entries
    }.getOrDefault(false)

    /** True when both files are installed and the marker matches this APK. */
    fun isInstalled(context: Context): Boolean {
        val expected = expectedMarker(context) ?: return false
        val model = modelFile(context)
        val tokenizer = tokenizerFile(context)
        if (!model.isReadableFile() || !tokenizer.isReadableFile()) return false
        if (model.length() != expected.modelBytes || tokenizer.length() != expected.tokenizerBytes) {
            return false
        }
        val installed = readMarker(installDir(context)) ?: return false
        return LlmInstallLogic.markerMatches(installed, expected)
    }

    /**
     * Stream-copies both bundled assets into the install directory. Reports
     * overall progress in 0..1. Throws [InsufficientStorageException] when the
     * destination lacks the model size plus the safety reserve.
     */
    suspend fun install(context: Context, onProgress: (Float) -> Unit) =
        withContext(Dispatchers.IO) {
            installMutex.withLock {
                val app = context.applicationContext
                onProgress(0f)

                if (isInstalled(app)) {
                    onProgress(1f)
                    return@withLock
                }

                val modelBytes = assetLength(app, assetName(MODEL_FILE_NAME))
                    ?: throw IOException("Bundled model asset is missing or compressed.")
                val tokenizerBytes = assetLength(app, assetName(TOKENIZER_FILE_NAME))
                    ?: throw IOException("Bundled tokenizer asset is missing or compressed.")
                val totalBytes = modelBytes + tokenizerBytes

                val dir = installDir(app)
                if (!dir.isDirectory && !dir.mkdirs()) {
                    throw IOException("Could not create the model directory.")
                }

                val available = StatFs(dir.absolutePath).availableBytes
                if (!LlmInstallLogic.hasEnoughSpace(available, totalBytes)) {
                    throw InsufficientStorageException(
                        "Not enough free storage for the explanation model."
                    )
                }

                val tempFiles = mutableListOf<File>()
                var completed = false
                try {
                    var copied = copyAsset(
                        context = app,
                        assetPath = assetName(MODEL_FILE_NAME),
                        destination = modelFile(app),
                        tempFiles = tempFiles,
                        totalBytes = totalBytes,
                        alreadyCopied = 0L,
                        onProgress = onProgress
                    )
                    copied = copyAsset(
                        context = app,
                        assetPath = assetName(TOKENIZER_FILE_NAME),
                        destination = tokenizerFile(app),
                        tempFiles = tempFiles,
                        totalBytes = totalBytes,
                        alreadyCopied = copied,
                        onProgress = onProgress
                    )
                    writeMarker(
                        dir = dir,
                        marker = LlmInstallLogic.Marker(
                            modelBytes = modelBytes,
                            tokenizerBytes = tokenizerBytes,
                            versionCode = BuildConfig.VERSION_CODE.toLong()
                        )
                    )
                    completed = true
                    onProgress(1f)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } finally {
                    if (!completed) {
                        tempFiles.forEach { runCatching { it.delete() } }
                    }
                }
            }
        }

    private fun copyAsset(
        context: Context,
        assetPath: String,
        destination: File,
        tempFiles: MutableList<File>,
        totalBytes: Long,
        alreadyCopied: Long,
        onProgress: (Float) -> Unit
    ): Long {
        val temp = File(destination.parentFile, destination.name + TMP_SUFFIX)
        tempFiles += temp
        var copied = alreadyCopied

        context.assets.open(assetPath).use { input ->
            FileOutputStream(temp).use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                    copied += read
                    onProgress(LlmInstallLogic.progress(copied, totalBytes))
                }
                output.flush()
                output.fd.sync()
            }
        }

        if (destination.exists() && !destination.delete()) {
            throw IOException("Could not replace ${destination.name}.")
        }
        if (!temp.renameTo(destination)) {
            throw IOException("Could not move ${destination.name} into place.")
        }
        return copied
    }

    private fun writeMarker(dir: File, marker: LlmInstallLogic.Marker) {
        val target = File(dir, MARKER_FILE_NAME)
        val temp = File(dir, MARKER_FILE_NAME + TMP_SUFFIX)
        val properties = Properties().apply {
            setProperty(KEY_MODEL_BYTES, marker.modelBytes.toString())
            setProperty(KEY_TOKENIZER_BYTES, marker.tokenizerBytes.toString())
            setProperty(KEY_VERSION_CODE, marker.versionCode.toString())
        }
        try {
            FileOutputStream(temp).use { output ->
                properties.store(output, null)
                output.flush()
                output.fd.sync()
            }
            if (!temp.renameTo(target)) {
                throw IOException("Could not write the install marker.")
            }
        } finally {
            runCatching { temp.delete() }
        }
    }

    private fun readMarker(dir: File): LlmInstallLogic.Marker? = runCatching {
        val file = File(dir, MARKER_FILE_NAME)
        if (!file.isReadableFile()) return null
        val properties = Properties()
        file.inputStream().use { properties.load(it) }
        LlmInstallLogic.Marker(
            modelBytes = properties.getProperty(KEY_MODEL_BYTES)?.toLongOrNull() ?: return null,
            tokenizerBytes = properties.getProperty(KEY_TOKENIZER_BYTES)?.toLongOrNull() ?: return null,
            versionCode = properties.getProperty(KEY_VERSION_CODE)?.toLongOrNull() ?: return null
        )
    }.getOrNull()

    private fun expectedMarker(context: Context): LlmInstallLogic.Marker? {
        if (!isBundled(context)) return null
        val modelBytes = assetLength(context, assetName(MODEL_FILE_NAME)) ?: return null
        val tokenizerBytes = assetLength(context, assetName(TOKENIZER_FILE_NAME)) ?: return null
        return LlmInstallLogic.Marker(
            modelBytes = modelBytes,
            tokenizerBytes = tokenizerBytes,
            versionCode = BuildConfig.VERSION_CODE.toLong()
        )
    }

    private fun assetLength(context: Context, assetPath: String): Long? =
        runCatching { context.assets.openFd(assetPath).use { it.length } }.getOrNull()

    private fun assetName(fileName: String): String = "$DIR_NAME/$fileName"

    private fun File.isReadableFile(): Boolean = isFile && canRead()
}
