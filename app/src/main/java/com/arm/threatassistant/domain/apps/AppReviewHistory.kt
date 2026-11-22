package com.arm.threatassistant.domain.apps

data class LastAccess(
    val visible: Boolean,
    val readsScreen: Boolean,
    val performsGestures: Boolean,
    val smsGranted: Boolean?
)

enum class AccessChange { NEWLY_VISIBLE, SCREEN, GESTURES, SMS }

data class AppComparison(
    val baseline: Map<String, LastAccess>,
    val changes: Map<String, Set<AccessChange>>
)

fun compareAccess(previous: Map<String, LastAccess>?, current: Map<String, AppAccess>): AppComparison {
    // Android may filter a package out of a later snapshot. Keep its last known capabilities.
    val baseline = previous.orEmpty().mapValues { (_, access) -> access.copy(visible = false) }.toMutableMap()
    val changes = mutableMapOf<String, Set<AccessChange>>()
    for ((id, access) in current) {
        val old = previous?.get(id)
        val evidence = buildSet {
            if (previous != null && old?.visible != true) add(AccessChange.NEWLY_VISIBLE)
            if (old != null) {
                if (!old.readsScreen && access.readsScreen) add(AccessChange.SCREEN)
                if (!old.performsGestures && access.performsGestures) add(AccessChange.GESTURES)
                if (old.smsGranted == false && access.smsGranted == true) add(AccessChange.SMS)
            }
        }
        if (evidence.isNotEmpty()) changes[id] = evidence
        baseline[id] = LastAccess(true, access.readsScreen, access.performsGestures, access.smsGranted ?: old?.smsGranted)
    }
    return AppComparison(baseline, changes)
}
