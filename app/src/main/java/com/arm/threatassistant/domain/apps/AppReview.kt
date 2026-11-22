package com.arm.threatassistant.domain.apps

enum class ReviewPriority { INFORMATION, REVIEW }

data class AppAccess(
    val readsScreen: Boolean,
    val performsGestures: Boolean,
    val smsGranted: Boolean?,
    val systemApp: Boolean
) {
    // Screen readers commonly use both accessibility capabilities.
    fun priority(): ReviewPriority {
        return if (!systemApp && smsGranted == true && (readsScreen || performsGestures)) {
            ReviewPriority.REVIEW
        } else {
            ReviewPriority.INFORMATION
        }
    }
}
