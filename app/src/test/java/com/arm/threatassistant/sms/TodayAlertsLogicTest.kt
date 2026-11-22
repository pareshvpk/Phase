package com.arm.threatassistant.sms

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import java.time.ZoneId
import java.time.ZonedDateTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TodayAlertsLogicTest {

    private val zone: ZoneId = ZoneId.of("Asia/Kolkata")

    private fun millisAt(
        year: Int,
        month: Int,
        day: Int,
        hour: Int,
        minute: Int
    ): Long = ZonedDateTime.of(year, month, day, hour, minute, 0, 0, zone)
        .toInstant()
        .toEpochMilli()

    private fun alert(id: String, receivedAtMillis: Long, body: String = "message $id") =
        TodayAlert(
            id = id,
            sender = "VM-BANK",
            body = body,
            verdict = ThreatVerdictLevel.SUSPICIOUS,
            receivedAtMillis = receivedAtMillis,
            reasonIds = listOf("FAKE_LINK")
        )

    @Test
    fun pruneKeepsTodayAndDropsYesterdayAcrossLocalMidnight() {
        val now = millisAt(2026, 1, 2, 0, 0)
        val yesterday2359 = millisAt(2026, 1, 1, 23, 59)
        val today0000 = millisAt(2026, 1, 2, 0, 0)
        val today0800 = millisAt(2026, 1, 2, 8, 0)

        val kept = TodayAlertsLogic.prune(
            list = listOf(
                alert("yesterday", yesterday2359),
                alert("midnight", today0000),
                alert("morning", today0800)
            ),
            nowMillis = now,
            zone = zone
        )

        assertEquals(listOf("midnight", "morning"), kept.map { it.id })
    }

    @Test
    fun pruneUsesTheSuppliedZoneNotUtc() {
        // 2026-01-01 18:45 UTC is 2026-01-02 00:15 in Asia/Kolkata.
        val justAfterLocalMidnight = ZonedDateTime.of(
            2026,
            1,
            1,
            18,
            45,
            0,
            0,
            ZoneId.of("UTC")
        ).toInstant().toEpochMilli()
        val now = millisAt(2026, 1, 2, 9, 0)

        val kept = TodayAlertsLogic.prune(
            list = listOf(alert("local-today", justAfterLocalMidnight)),
            nowMillis = now,
            zone = zone
        )

        assertEquals(1, kept.size)
    }

    @Test
    fun addPrunesOldEntriesAndPrependsNewestFirst() {
        val yesterday = millisAt(2026, 1, 1, 20, 0)
        val firstToday = millisAt(2026, 1, 2, 9, 0)
        val secondToday = millisAt(2026, 1, 2, 10, 0)

        val afterFirst = TodayAlertsLogic.add(
            list = listOf(alert("yesterday", yesterday)),
            alert = alert("first", firstToday),
            nowMillis = firstToday,
            zone = zone
        )
        val afterSecond = TodayAlertsLogic.add(
            list = afterFirst,
            alert = alert("second", secondToday),
            nowMillis = secondToday,
            zone = zone
        )

        assertEquals(listOf("second", "first"), afterSecond.map { it.id })
    }

    @Test
    fun addCapsTheListAtTwoHundredEntries() {
        val now = millisAt(2026, 1, 2, 12, 0)
        var list = emptyList<TodayAlert>()

        for (index in 0 until 205) {
            list = TodayAlertsLogic.add(
                list = list,
                alert = alert(index.toString(), now),
                nowMillis = now,
                zone = zone
            )
        }

        assertEquals(TodayAlertsLogic.MAX_ENTRIES, list.size)
        assertEquals("204", list.first().id)
        assertEquals("5", list.last().id)
    }

    @Test
    fun addTruncatesLongMessageBodies() {
        val now = millisAt(2026, 1, 2, 12, 0)
        val longBody = "a".repeat(TodayAlert.MAX_BODY_LENGTH + 250)

        val result = TodayAlertsLogic.add(
            list = emptyList(),
            alert = alert("long", now, body = longBody),
            nowMillis = now,
            zone = zone
        )

        assertEquals(TodayAlert.MAX_BODY_LENGTH, result.single().body.length)
    }

    @Test
    fun millisUntilNextMidnightUsesLocalMidnight() {
        val now = millisAt(2026, 1, 2, 23, 30)

        val remaining = TodayAlertsLogic.millisUntilNextMidnight(now, zone)

        assertEquals(30 * 60 * 1000L, remaining)
        assertTrue(remaining > 0)
    }

    @Test
    fun retryingAnMmsRecordKeepsOneAlert() {
        val now = millisAt(2026, 1, 2, 12, 30)
        val message = alert("mms-42", now)
        val once = TodayAlertsLogic.add(emptyList(), message, now, zone)
        assertEquals(once, TodayAlertsLogic.add(once, message, now, zone))
    }
}
