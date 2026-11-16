package com.arm.threatassistant.sms

import android.content.Context
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.time.ZoneId

/**
 * Same-day storage for flagged (scam/suspicious) incoming SMS.
 *
 * The list is a JSON array in the app-private file
 * `filesDir/today_alerts.json`. Entries are filtered by the device's local
 * date: anything received before local midnight is deleted the next time the
 * list is read or changed. Safe messages are never written here.
 *
 * Every file operation is serialized on a single lock because the SMS
 * receiver runs on a background executor while an open UI may read the list at
 * the same time. [alerts] is updated after every change so the UI can refresh
 * live.
 */
object TodayAlertsStore {

    private const val FILE_NAME = "today_alerts.json"

    private val lock = Any()

    private val _alerts = MutableStateFlow<List<TodayAlert>>(emptyList())
    val alerts: StateFlow<List<TodayAlert>> = _alerts.asStateFlow()

    fun add(context: Context, alert: TodayAlert) {
        synchronized(lock) {
            val folder = context.applicationContext
            val now = System.currentTimeMillis()
            val next = TodayAlertsLogic.add(
                list = readFile(folder),
                alert = alert,
                nowMillis = now,
                zone = ZoneId.systemDefault()
            )
            persist(folder, next)
            _alerts.value = next
        }
    }

    fun getToday(context: Context): List<TodayAlert> {
        synchronized(lock) {
            val folder = context.applicationContext
            val existing = readFile(folder)
            val pruned = TodayAlertsLogic.prune(
                list = existing,
                nowMillis = System.currentTimeMillis(),
                zone = ZoneId.systemDefault()
            )
            if (pruned != existing) {
                persist(folder, pruned)
            }
            _alerts.value = pruned
            return pruned
        }
    }

    fun remove(context: Context, id: String) {
        synchronized(lock) {
            val folder = context.applicationContext
            val current = TodayAlertsLogic.prune(
                list = readFile(folder),
                nowMillis = System.currentTimeMillis(),
                zone = ZoneId.systemDefault()
            )
            val next = current.filterNot { it.id == id }
            persist(folder, next)
            _alerts.value = next
        }
    }

    fun clear(context: Context) {
        synchronized(lock) {
            val folder = context.applicationContext
            runCatching { file(folder).delete() }
            runCatching { tempFile(folder).delete() }
            _alerts.value = emptyList()
        }
    }

    private fun readFile(context: Context): List<TodayAlert> {
        val target = file(context)
        if (!target.exists()) return emptyList()
        val text = runCatching { target.readText() }.getOrElse { return emptyList() }
        return decode(text)
    }

    private fun persist(context: Context, alerts: List<TodayAlert>) {
        val target = file(context)
        if (alerts.isEmpty()) {
            runCatching { target.delete() }
            runCatching { tempFile(context).delete() }
            return
        }

        val json = encode(alerts)
        runCatching {
            val temp = tempFile(context)
            temp.writeText(json)
            target.delete()
            if (!temp.renameTo(target)) {
                target.writeText(json)
                temp.delete()
            }
        }.onFailure {
            runCatching { target.writeText(json) }
        }
    }

    private fun encode(alerts: List<TodayAlert>): String {
        val array = JSONArray()
        alerts.forEach { alert ->
            val reasonIds = JSONArray()
            alert.reasonIds.forEach { reasonIds.put(it) }
            array.put(
                JSONObject().apply {
                    put("id", alert.id)
                    put("sender", alert.sender)
                    put("body", alert.body)
                    put("verdict", alert.verdict.name)
                    put("receivedAtMillis", alert.receivedAtMillis)
                    put("reasonIds", reasonIds)
                }
            )
        }
        return array.toString()
    }

    private fun decode(text: String): List<TodayAlert> = runCatching {
        val array = JSONArray(text)
        buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val verdict = ThreatVerdictLevel.entries
                    .firstOrNull { it.name == item.optString("verdict") }
                    ?: continue
                val reasonIds = buildList {
                    val stored = item.optJSONArray("reasonIds") ?: return@buildList
                    for (reasonIndex in 0 until stored.length()) {
                        stored.optString(reasonIndex)
                            .takeIf { it.isNotEmpty() }
                            ?.let { add(it) }
                    }
                }
                add(
                    TodayAlert(
                        id = item.optString("id"),
                        sender = item.optString("sender"),
                        body = item.optString("body").take(TodayAlert.MAX_BODY_LENGTH),
                        verdict = verdict,
                        receivedAtMillis = item.optLong("receivedAtMillis"),
                        reasonIds = reasonIds
                    )
                )
            }
        }
    }.getOrElse { emptyList() }

    private fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    private fun tempFile(context: Context): File = File(context.filesDir, "$FILE_NAME.tmp")
}
