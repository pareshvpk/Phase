package com.arm.threatassistant.presentation.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.arm.threatassistant.apps.InstalledAppsCollector
import com.arm.threatassistant.domain.apps.AppRiskScorer
import com.arm.threatassistant.domain.apps.AppScanResult
import com.arm.threatassistant.domain.apps.AppScanSummary
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** UI states of the Apps tab: nothing scanned yet, scanning, or a result list. */
sealed interface AppsScanState {
    data object Idle : AppsScanState
    data object Scanning : AppsScanState
    data class Results(val results: List<AppScanResult>) : AppsScanState
}

/**
 * Drives the on-device app scan. The collector and the scorer both run on a
 * background dispatcher and never touch the network; the view model only
 * forwards the sorted result list to the UI.
 */
class AppsViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow<AppsScanState>(AppsScanState.Idle)
    val uiState: StateFlow<AppsScanState> = _uiState.asStateFlow()

    /** Starts a scan unless one is already running. */
    fun scan() {
        if (_uiState.value is AppsScanState.Scanning) return
        _uiState.value = AppsScanState.Scanning

        viewModelScope.launch {
            try {
                val apps = InstalledAppsCollector.collect(getApplication<Application>())
                val nowMillis = System.currentTimeMillis()
                val results = apps.map { app -> AppRiskScorer.score(app, nowMillis) }
                _uiState.value = AppsScanState.Results(AppScanSummary.sort(results))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (ignored: Throwable) {
                _uiState.value = AppsScanState.Idle
            }
        }
    }
}
