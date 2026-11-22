package com.arm.threatassistant.sms

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class MmsRowsTest {
    @Test fun failedRowIsFirstOnRetry() {
        val ids = listOf(17L, 18L, 19L)
        val attempts = mutableListOf<Long>()
        var checkpoint = 16L
        fun scan(failAt: Long?) {
            val rows = ids.filter { it > checkpoint }.iterator()
            consumeMmsRows(
                nextId = { if (rows.hasNext()) rows.next() else null },
                active = { true },
                process = {
                    attempts.add(it)
                    if (it == failAt) throw IOException()
                },
                checkpoint = { checkpoint = it }
            )
        }
        try {
            scan(18L)
            fail("provider failure must reach scheduler")
        } catch (_: IOException) {
            assertEquals(17L, checkpoint)
        }
        scan(null)
        assertEquals(listOf(17L, 18L, 18L, 19L), attempts)
        assertEquals(19L, checkpoint)
    }

    @Test fun cancellationDuringAnalysisLeavesCheckpointUntouched() {
        var active = true
        consumeMmsRows(
            nextId = { 17L },
            active = { active },
            process = { active = false },
            checkpoint = { fail("Stopped work advanced the cursor") }
        )
    }
}
