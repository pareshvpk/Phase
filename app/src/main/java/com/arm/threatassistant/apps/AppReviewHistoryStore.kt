package com.arm.threatassistant.apps

import android.content.Context
import android.util.AtomicFile
import com.arm.threatassistant.domain.apps.AccessChange
import com.arm.threatassistant.domain.apps.LastAccess
import com.arm.threatassistant.domain.apps.compareAccess
import java.io.File
import java.io.IOException
import org.json.JSONObject

data class ReviewSnapshot(
    val entries: List<AppReviewEntry>,
    val firstScan: Boolean,
    val changes: Map<String, Set<AccessChange>>
)

class AppReviewHistoryStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "app-access-baseline-v1"))
    private val collector = AppReviewCollector(context)

    fun scan(): ReviewSnapshot = synchronized(lock) {
        val entries = collector.collect()
        val previous = try {
            read()
        } catch (missing: java.io.FileNotFoundException) {
            if (file.baseFile.exists()) throw missing
            null
        }
        val comparison = compareAccess(previous, entries.associate { it.id to it.access })
        val json = JSONObject()
        for ((id, access) in comparison.baseline) {
            var bits = 0
            if (access.visible) bits = bits or 1
            if (access.readsScreen) bits = bits or 2
            if (access.performsGestures) bits = bits or 4
            if (access.smsGranted != null) bits = bits or 8
            if (access.smsGranted == true) bits = bits or 16
            json.put(id, bits)
        }
        val output = file.startWrite()
        try {
            output.write(json.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(output)
        } catch (e: Exception) {
            file.failWrite(output)
            throw e
        }
        ReviewSnapshot(entries, previous == null, comparison.changes)
    }

    private fun read(): Map<String, LastAccess> {
        val json = JSONObject(file.readFully().toString(Charsets.UTF_8))
        return json.keys().asSequence().associateWith { id ->
            val bits = json.getInt(id)
            require(bits in 0..31 && (bits and 16 == 0 || bits and 8 != 0))
            LastAccess(bits and 1 != 0, bits and 2 != 0, bits and 4 != 0,
                if (bits and 8 == 0) null else bits and 16 != 0)
        }
    }

    fun reset() = synchronized(lock) {
        file.delete()
        if (file.baseFile.exists()) throw IOException("Baseline could not be deleted")
    }

    private companion object {
        val lock = Any()
    }
}
