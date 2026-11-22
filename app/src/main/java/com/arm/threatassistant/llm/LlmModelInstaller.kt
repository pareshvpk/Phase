package com.arm.threatassistant.llm

import android.content.Context
import android.os.StatFs
import com.arm.threatassistant.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Properties
import kotlin.coroutines.coroutineContext

/** Thrown when the device does not have room for the model files. */
class InsufficientStorageException(message: String) : IOException(message)

/** Thrown when a downloaded file does not match its expected size or checksum. */
class CorruptDownloadException(message: String) : IOException(message)

/**
 * Pure installation helpers. Kept free of Android APIs so the marker matching,
 * free-space requirement, resume offsets and progress maths can be unit-tested.
 */
object LlmInstallLogic {

    const val RESERVE_BYTES = 50L * 1024L * 1024L

    /** Sizes of the files a completed install wrote. */
    data class Marker(
        val modelBytes: Long,
        val tokenizerBytes: Long
    )

    /** Download bytes plus the 50 MB safety reserve. */
    fun requiredFreeBytes(assetBytes: Long): Long = assetBytes + RESERVE_BYTES

    fun hasEnoughSpace(availableBytes: Long, assetBytes: Long): Boolean =
        availableBytes >= requiredFreeBytes(assetBytes)

    /** Overall install progress in 0..1 across both files. */
    fun progress(copiedBytes: Long, totalBytes: Long): Float {
        if (totalBytes <= 0L) return 0f
        return (copiedBytes.toDouble() / totalBytes.toDouble()).toFloat().coerceIn(0f, 1f)
    }

    /**
     * True when the files on disk are exactly the ones a completed install wrote
     * and, when the build names an expected model size, the model has that size.
     * A different expected size (a new model) therefore forces a fresh download.
     */
    fun isCompleteInstall(
        marker: Marker?,
        actualModelBytes: Long,
        actualTokenizerBytes: Long,
        expectedModelBytes: Long
    ): Boolean {
        if (marker == null) return false
        if (marker.modelBytes <= 0L || marker.tokenizerBytes <= 0L) return false
        if (marker.modelBytes != actualModelBytes || marker.tokenizerBytes != actualTokenizerBytes) return false
        return expectedModelBytes <= 0L || expectedModelBytes == actualModelBytes
    }

    /**
     * Byte offset to resume a partial download from. Restarts from zero when the
     * partial file is already as large as (or larger than) the expected total.
     */
    fun resumeOffset(partialBytes: Long, expectedTotalBytes: Long): Long = when {
        partialBytes <= 0L -> 0L
        expectedTotalBytes > 0L && partialBytes >= expectedTotalBytes -> 0L
        else -> partialBytes
    }

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * Downloads the Llama model and tokenizer once into `noBackupFilesDir/llm`,
 * where the explainer opens them as regular files. The model is no longer
 * bundled inside the APK, so the phone keeps exactly one copy.
 *
 * The source URLs come from the build (`armLlmModelUrl`, `armLlmTokenizerUrl`
 * Gradle properties). When they are empty the download is not offered and the
 * app still uses a copy that was placed on the phone by other means.
 */
object LlmModelInstaller {

    private const val DIR_NAME = "llm"
    private const val MODEL_FILE_NAME = "llama3_2_1b.pte"
    private const val TOKENIZER_FILE_NAME = "tokenizer.model"
    private const val MARKER_FILE_NAME = "installed.properties"
    private const val PART_SUFFIX = ".part"
    private const val BUFFER_SIZE = 1 shl 16
    private const val TIMEOUT_MS = 30_000

    private const val KEY_MODEL_BYTES = "model.bytes"
    private const val KEY_TOKENIZER_BYTES = "tokenizer.bytes"

    /** Rough tokenizer size, used only before the server reports the real one. */
    private const val TOKENIZER_ESTIMATE_BYTES = 2L * 1024L * 1024L

    private val installMutex = Mutex()

    fun installDir(context: Context): File =
        File(context.noBackupFilesDir, DIR_NAME)

    fun modelFile(context: Context): File = File(installDir(context), MODEL_FILE_NAME)

    fun tokenizerFile(context: Context): File = File(installDir(context), TOKENIZER_FILE_NAME)

    /** True when this build knows where to download the model from. */
    fun isDownloadConfigured(): Boolean =
        BuildConfig.LLM_MODEL_URL.isNotBlank() && BuildConfig.LLM_TOKENIZER_URL.isNotBlank()

    /** Expected download size for display; 0 when the build does not state it. */
    fun expectedDownloadBytes(): Long =
        if (BuildConfig.LLM_MODEL_BYTES > 0L) BuildConfig.LLM_MODEL_BYTES + TOKENIZER_ESTIMATE_BYTES else 0L

    /** True when both files are installed completely. */
    fun isInstalled(context: Context): Boolean {
        val model = modelFile(context)
        val tokenizer = tokenizerFile(context)
        if (!model.isReadableFile() || !tokenizer.isReadableFile()) return false
        return LlmInstallLogic.isCompleteInstall(
            marker = readMarker(installDir(context)),
            actualModelBytes = model.length(),
            actualTokenizerBytes = tokenizer.length(),
            expectedModelBytes = BuildConfig.LLM_MODEL_BYTES
        )
    }

    /**
     * Downloads both files (resuming partial downloads), verifies them and
     * writes the install marker. Reports overall progress in 0..1.
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
                if (!isDownloadConfigured()) {
                    throw IOException("No download source configured.")
                }

                val dir = installDir(app)
                if (!dir.isDirectory && !dir.mkdirs()) {
                    throw IOException("Could not create the model directory.")
                }
                // Remove an outdated install before downloading a new one.
                File(dir, MARKER_FILE_NAME).delete()
                modelFile(app).delete()
                tokenizerFile(app).delete()

                val estimatedTotal = expectedDownloadBytes()
                val available = StatFs(dir.absolutePath).availableBytes
                if (estimatedTotal > 0L && !LlmInstallLogic.hasEnoughSpace(available, estimatedTotal)) {
                    throw InsufficientStorageException("Not enough free storage for the explanation model.")
                }

                val tokenizerBytes = download(
                    url = BuildConfig.LLM_TOKENIZER_URL,
                    destination = tokenizerFile(app),
                    expectedBytes = 0L,
                    expectedSha256 = BuildConfig.LLM_TOKENIZER_SHA256,
                    onBytes = { done, total ->
                        onProgress(LlmInstallLogic.progress(done, (estimatedTotal.takeIf { it > 0 } ?: total)) * 0.01f)
                    }
                )
                val modelBytes = download(
                    url = BuildConfig.LLM_MODEL_URL,
                    destination = modelFile(app),
                    expectedBytes = BuildConfig.LLM_MODEL_BYTES,
                    expectedSha256 = BuildConfig.LLM_MODEL_SHA256,
                    onBytes = { done, total ->
                        onProgress(0.01f + LlmInstallLogic.progress(done, total) * 0.99f)
                    }
                )
                writeMarker(dir, LlmInstallLogic.Marker(modelBytes, tokenizerBytes))
                onProgress(1f)
            }
        }

    /** Downloads `url` to `destination` via a resumable `.part` file. Returns the file size. */
    private suspend fun download(
        url: String,
        destination: File,
        expectedBytes: Long,
        expectedSha256: String,
        onBytes: (done: Long, total: Long) -> Unit
    ): Long {
        val part = File(destination.parentFile, destination.name + PART_SUFFIX)
        var offset = LlmInstallLogic.resumeOffset(part.length(), expectedBytes)
        if (offset == 0L) part.delete()

        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            instanceFollowRedirects = true
            if (offset > 0L) setRequestProperty("Range", "bytes=$offset-")
        }
        try {
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_OK && offset > 0L) {
                // Server ignored the range request: start over.
                part.delete()
                offset = 0L
            } else if (code != HttpURLConnection.HTTP_OK && code != HttpURLConnection.HTTP_PARTIAL) {
                throw IOException("Download failed (HTTP $code).")
            }
            val total = when {
                expectedBytes > 0L -> expectedBytes
                connection.contentLengthLong > 0L -> offset + connection.contentLengthLong
                else -> 0L
            }

            var done = offset
            connection.inputStream.use { input ->
                FileOutputStream(part, offset > 0L).use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    while (true) {
                        coroutineContext.ensureActive()
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        done += read
                        onBytes(done, total)
                    }
                    output.flush()
                    output.fd.sync()
                }
            }
        } finally {
            connection.disconnect()
        }

        val size = part.length()
        if (expectedBytes > 0L && size != expectedBytes) {
            part.delete()
            throw CorruptDownloadException("Downloaded file has the wrong size.")
        }
        if (expectedSha256.isNotBlank() && !sha256(part).equals(expectedSha256, ignoreCase = true)) {
            part.delete()
            throw CorruptDownloadException("Downloaded file is damaged.")
        }
        if (destination.exists() && !destination.delete()) {
            throw IOException("Could not replace ${destination.name}.")
        }
        if (!part.renameTo(destination)) {
            throw IOException("Could not move ${destination.name} into place.")
        }
        return size
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return LlmInstallLogic.toHex(digest.digest())
    }

    private fun writeMarker(dir: File, marker: LlmInstallLogic.Marker) {
        val target = File(dir, MARKER_FILE_NAME)
        val temp = File(dir, "$MARKER_FILE_NAME.tmp")
        val properties = Properties().apply {
            setProperty(KEY_MODEL_BYTES, marker.modelBytes.toString())
            setProperty(KEY_TOKENIZER_BYTES, marker.tokenizerBytes.toString())
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

    /** Reads the marker; markers from the old bundled installer are still accepted. */
    private fun readMarker(dir: File): LlmInstallLogic.Marker? = runCatching {
        val file = File(dir, MARKER_FILE_NAME)
        if (!file.isReadableFile()) return null
        val properties = Properties()
        file.inputStream().use { properties.load(it) }
        LlmInstallLogic.Marker(
            modelBytes = properties.getProperty(KEY_MODEL_BYTES)?.toLongOrNull() ?: return null,
            tokenizerBytes = properties.getProperty(KEY_TOKENIZER_BYTES)?.toLongOrNull() ?: return null
        )
    }.getOrNull()

    private fun File.isReadableFile(): Boolean = isFile && canRead()
}
