package com.arm.threatassistant.sms

import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import java.time.Instant
import java.time.ZoneId

/**
 * A flagged message kept for the "Today" list.
 *
 * [body] is truncated to [MAX_BODY_LENGTH] characters before it is stored.
 */
data class TodayAlert(
    val id: String,
    val sender: String,
    val body: String,
    val verdict: ThreatVerdictLevel,
    val receivedAtMillis: Long,
    val reasonIds: List<String>
) {
    companion object {
        const val MAX_BODY_LENGTH = 1000
    }
}

/**
 * Pure-Kotlin date logic for the same-day alert list.
 *
 * All decisions use the supplied local zone, so an entry expires at the
 * device's local midnight rather than at UTC midnight.
 */
object TodayAlertsLogic {

    const val MAX_ENTRIES = 200

    fun prune(list: List<TodayAlert>, nowMillis: Long, zone: ZoneId): List<TodayAlert> {
        val today = localDate(nowMillis, zone)
        return list.filter { localDate(it.receivedAtMillis, zone) == today }
    }

    fun add(
        list: List<TodayAlert>,
        alert: TodayAlert,
        nowMillis: Long,
        zone: ZoneId
    ): List<TodayAlert> {
        val bounded = if (alert.body.length > TodayAlert.MAX_BODY_LENGTH) {
            alert.copy(body = alert.body.take(TodayAlert.MAX_BODY_LENGTH))
        } else {
            alert
        }
        return (listOf(bounded) + prune(list, nowMillis, zone)).take(MAX_ENTRIES)
    }

    fun millisUntilNextMidnight(nowMillis: Long, zone: ZoneId): Long {
        val now = Instant.ofEpochMilli(nowMillis).atZone(zone)
        val nextMidnight = now.toLocalDate().plusDays(1).atStartOfDay(zone)
        return nextMidnight.toInstant().toEpochMilli() - nowMillis
    }

    private fun localDate(millis: Long, zone: ZoneId) =
        Instant.ofEpochMilli(millis).atZone(zone).toLocalDate()
}
