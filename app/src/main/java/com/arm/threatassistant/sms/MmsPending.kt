package com.arm.threatassistant.sms

/** Only IDs and first-observed times are retained while the provider writes parts. */
internal object MmsPending {
    const val MAX_ENTRIES = 128
    const val RETRY_WINDOW_MS = 10 * 60 * 1000L

    fun bounded(entries: Map<Long, Long>): Map<Long, Long> = entries
        .filterKeys { it >= 0 }
        .entries.sortedByDescending { it.value }.take(MAX_ENTRIES)
        .associate { it.key to it.value }

    // Check expiry only after reading this row. A delayed job can still find
    // a completed message on its final attempt.
    fun defer(entries: Map<Long, Long>, id: Long, now: Long): Map<Long, Long> {
        val firstSeen = entries[id] ?: now
        if (now < firstSeen || now - firstSeen >= RETRY_WINDOW_MS) return entries - id
        return bounded(entries + (id to firstSeen))
    }
}
