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

/** Lifecycle of the bundled-model installation, shared app-wide. */
sealed interface LlmInstallStatus {
    data object NotBundled : LlmInstallStatus
    data class Installing(val progress: Float) : LlmInstallStatus
    data object Ready : LlmInstallStatus
    data class Failed(val message: String) : LlmInstallStatus
}

/**
 * Process-wide install state. The install is started when the app process
 * starts and survives activity recreation, so rotation never restarts it.
 */
object LlmInstallState {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow<LlmInstallStatus>(LlmInstallStatus.NotBundled)
    val state: StateFlow<LlmInstallStatus> = _state.asStateFlow()

    private val started = AtomicBoolean(false)
    private var job: Job? = null

    /** Starts the install once per process; safe to call from any entry point. */
    @Synchronized
    fun ensureStarted(context: Context) {
        if (job?.isActive == true) return
        if (_state.value is LlmInstallStatus.Ready) return
        if (started.get() && _state.value !is LlmInstallStatus.Failed) return
        started.set(true)
        launchInstall(context.applicationContext)
    }

    /** Re-runs the install after a failure. */
    @Synchronized
    fun retry(context: Context) {
        if (job?.isActive == true) return
        if (_state.value is LlmInstallStatus.Installing) return
        started.set(true)
        launchInstall(context.applicationContext)
    }

    private fun launchInstall(context: Context) {
        job = scope.launch {
            if (!LlmModelInstaller.isBundled(context)) {
                _state.value = LlmInstallStatus.NotBundled
                return@launch
            }
            if (LlmModelInstaller.isInstalled(context)) {
                markReady()
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
                    else -> t.message?.takeIf { it.isNotBlank() }
                        ?: context.getString(R.string.llm_install_failed_generic)
                }
                _state.value = LlmInstallStatus.Failed(message)
            }
        }
    }

    private fun markReady() {
        LlmExplainerProvider.refresh()
        _state.value = LlmInstallStatus.Ready
    }
}
