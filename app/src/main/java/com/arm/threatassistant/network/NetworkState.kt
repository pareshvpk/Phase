package com.arm.threatassistant.network

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

data class NetworkSnapshot(
    val running: Boolean = false, val starting: Boolean = false, val failed: Boolean = false,
    val sent: Long = 0, val received: Long = 0, val packets: Long = 0,
    val active: Int = 0, val completed: Long = 0,
    val findings: List<NetworkFinding> = emptyList(), val estimate: NetworkModel.Estimate? = null
)

/** Session-only metadata. No payloads or endpoint history are persisted. */
object NetworkState {
    private val mutable = MutableStateFlow(NetworkSnapshot())
    val state = mutable.asStateFlow()
    @Synchronized fun update(change: (NetworkSnapshot) -> NetworkSnapshot) { mutable.value = change(mutable.value) }
    fun clear() = update { it.copy(findings = emptyList(), estimate = null) }
}
