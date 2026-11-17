package com.arm.threatassistant.llm

import android.content.Context
import com.arm.threatassistant.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/** Lifecycle of the on-device model, shared app-wide. */
sealed interface LlmInstallStatus {
    /** No model on the phone and this build has no download source. */
    data object NotBundled : LlmInstallStatus
    /** No model on the phone yet; the user can start a one-time download. */
    data class DownloadAvailable(val totalBytes: Long) : LlmInstallStatus
    data class Installing(val progress: Float) : LlmInstallStatus
    data object Ready : LlmInstallStatus
    /** The device CPU cannot run the stock ExecuTorch AAR (no Armv8.1 atomics). */
    data object Unsupported : LlmInstallStatus
    data class Failed(val message: String) : LlmInstallStatus
}

/**
 * Process-wide install state. At app start it only checks what is on the
 * phone; the large download runs only after the user asks for it ([retry]),
 * and survives activity recreation, so rotation never restarts it.
 */
object LlmInstallState {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow<LlmInstallStatus>(LlmInstallStatus.NotBundled)
    val state: StateFlow<LlmInstallStatus> = _state.asStateFlow()

    private val started = AtomicBoolean(false)
    private var job: Job? = null

    /** Checks the model once per process; safe to call from any entry point. */
    @Synchronized
    fun ensureStarted(context: Context) {
        if (job?.isActive == true) return
        if (_state.value is LlmInstallStatus.Ready) return
        if (started.get() && _state.value !is LlmInstallStatus.Failed) return
        if (!CpuSupport.isSupported(context)) {
            started.set(true)
            _state.value = LlmInstallStatus.Unsupported
            return
        }
        started.set(true)
        val app = context.applicationContext
        job = scope.launch { _state.value = currentStatus(app) }
    }

    /** Starts (or resumes) the download, also after a failure. */
    @Synchronized
    fun retry(context: Context) {
        if (job?.isActive == true) return
        if (_state.value is LlmInstallStatus.Installing) return
        if (!CpuSupport.isSupported(context)) {
            started.set(true)
            _state.value = LlmInstallStatus.Unsupported
            return
        }
        started.set(true)
        launchInstall(context.applicationContext)
    }

    private fun launchInstall(context: Context) {
        job = scope.launch {
            if (LlmModelLocator.locate(context) != null) {
                markReady()
                return@launch
            }
            if (!LlmModelInstaller.isDownloadConfigured()) {
                _state.value = LlmInstallStatus.NotBundled
                return@launch
            }

            _state.value = LlmInstallStatus.Installing(0f)
            try {
                LlmModelInstaller.install(context) { progress ->
                    _state.value = LlmInstallStatus.Installing(progress)
                }
                markReady()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (t: Throwable) {
                val message = when (t) {
                    is InsufficientStorageException -> context.getString(R.string.llm_install_no_space)
                    is CorruptDownloadException -> context.getString(R.string.llm_install_failed_generic)
                    is java.io.IOException -> context.getString(R.string.llm_install_no_network)
                    else -> t.message?.takeIf { it.isNotBlank() }
                        ?: context.getString(R.string.llm_install_failed_generic)
                }
                _state.value = LlmInstallStatus.Failed(message)
            }
        }
    }

    private fun currentStatus(context: Context): LlmInstallStatus = when {
        LlmModelLocator.locate(context) != null -> {
            LlmExplainerProvider.refresh()
            LlmInstallStatus.Ready
        }
        LlmModelInstaller.isDownloadConfigured() ->
            LlmInstallStatus.DownloadAvailable(LlmModelInstaller.expectedDownloadBytes())
        else -> LlmInstallStatus.NotBundled
    }

    private fun markReady() {
        LlmExplainerProvider.refresh()
        _state.value = LlmInstallStatus.Ready
    }
}
