package com.arm.threatassistant.sms

import org.junit.Assert.*
import org.junit.Test

class MmsPendingTest {
    @Test fun retryPreservesOriginalDeadline() {
        val first = MmsPending.defer(emptyMap(), 17, 1000)
        val retried = MmsPending.defer(first, 17, 2000)
        assertEquals(1000L, retried[17])
    }

    @Test fun imageOnlyOrMissingMessageExpires() {
        assertTrue(MmsPending.defer(mapOf(17L to 0L), 17, MmsPending.RETRY_WINDOW_MS).isEmpty())
    }

    @Test fun delayedSchedulerKeepsOverdueIdsUntilTheirFinalRead() {
        val overdue = MmsPending.bounded(mapOf(17L to 0L, 18L to 1L))
        val afterEmptyRow = MmsPending.defer(overdue, 17, MmsPending.RETRY_WINDOW_MS + 2)
        assertEquals(mapOf(18L to 1L), afterEmptyRow)
    }

    @Test fun incompleteOlderIdDoesNotPreventTrackingLaterIds() {
        val pending = MmsPending.defer(mapOf(17L to 1000L), 20, 2000)
        assertEquals(setOf(17L, 20L), pending.keys)
        assertEquals(setOf(20L), (pending - 17).keys)
    }

    @Test fun pendingStateIsBoundedWithoutMessageText() {
        var pending = emptyMap<Long, Long>()
        for (id in 1L..300) pending = MmsPending.defer(pending, id, id)
        assertEquals(MmsPending.MAX_ENTRIES, pending.size)
        assertTrue(pending.containsKey(300))
        assertFalse(pending.containsKey(1))
    }

    @Test fun clockRollbackDoesNotLeavePermanentPendingIds() {
        assertTrue(MmsPending.defer(mapOf(1L to 10000L), 1, 2000).isEmpty())
    }
}
