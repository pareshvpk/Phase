package com.arm.threatassistant.presentation.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.arm.threatassistant.apps.AppReviewHistoryStore
import com.arm.threatassistant.apps.ReviewSnapshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface AppsState {
    data object Idle : AppsState
    data object Cleared : AppsState
    data object Loading : AppsState
    data object Unavailable : AppsState
    data class Ready(val snapshot: ReviewSnapshot) : AppsState
}

class AppsViewModel(application: Application) : AndroidViewModel(application) {
    private val history = AppReviewHistoryStore(application)
    private val mutableState = MutableStateFlow<AppsState>(AppsState.Idle)
    val state = mutableState.asStateFlow()
    private var job: kotlinx.coroutines.Job? = null

    fun refresh() = runOperation { AppsState.Ready(history.scan()) }

    fun clearHistory() = runOperation {
        history.reset()
        AppsState.Cleared
    }

    private fun runOperation(operation: () -> AppsState) {
        if (job?.isActive == true) return
        mutableState.value = AppsState.Loading
        job = viewModelScope.launch {
            mutableState.value = try {
                withContext(Dispatchers.IO) { operation() }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                AppsState.Unavailable
            }
        }
    }
}
