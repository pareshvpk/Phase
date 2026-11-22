package com.arm.threatassistant.sms

import android.content.ContentProvider
import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 29)
class MmsActivationTest {
    @Test fun delayedRetryReadsCompletedTextBeforeExpiringId() = checkDelayedRetry(rowExists = true)

    @Test fun deletedPendingRowDoesNotRetryForever() = checkDelayedRetry(rowExists = false)

    private fun checkDelayedRetry(rowExists: Boolean) {
        val provider = PendingInbox(rowExists)
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val resolver = ContentResolver.wrap(provider)
        val context = object : ContextWrapper(target) {
            override fun getContentResolver(): ContentResolver = resolver
            override fun getSharedPreferences(name: String, mode: Int) =
                target.getSharedPreferences("instrumentation_pending_$name", mode)
            override fun checkPermission(permission: String, pid: Int, uid: Int): Int =
                PackageManager.PERMISSION_GRANTED
        }
        val prefs = context.getSharedPreferences("arm_mms_scanner", Context.MODE_PRIVATE)
        val signal = CancellationSignal()
        try {
            // Already checkpointed parent row, with text that became available
            // after Android delayed the job beyond the ten-minute retry window.
            prefs.edit().putLong("last_mms_id", 11L)
                .putStringSet("pending_mms_ids", setOf("11:1")).commit()
            SmsProtectionPreferences.setEnabled(context, true)
            assertTrue(MmsWatcher.begin(context, signal) != null)
            assertFalse(MmsScanner.scanNew(context, signal))
            assertEquals(if (rowExists) 1 else 0, provider.partReads)
            assertTrue(prefs.getStringSet("pending_mms_ids", emptySet()).orEmpty().isEmpty())
            assertEquals(11L, prefs.getLong("last_mms_id", -1))
        } finally {
            MmsWatcher.end(signal)
            MmsScanner.reset(context)
            SmsProtectionPreferences.setEnabled(context, false)
        }
    }

    @Test fun snapshotsAtRegistrationAndReactivationAndRejectsStaleWork() {
        val provider = Inbox()
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val resolver = ContentResolver.wrap(provider)
        val context = object : ContextWrapper(target) {
            override fun getContentResolver(): ContentResolver = resolver
            override fun getSharedPreferences(name: String, mode: Int) =
                target.getSharedPreferences("instrumentation_$name", mode)
        }
        MmsScanner.reset(context)
        try {
            provider.maximum = 10
            assertTrue(MmsScanner.initialize(context) { commit -> commit(); true })
            provider.maximum = 11
            assertTrue(MmsScanner.initialize(context) { commit -> commit(); true })
            assertEquals(listOf(10L), provider.snapshots)
            MmsScanner.reset(context)
            provider.maximum = 14
            assertFalse(MmsScanner.initialize(context) { false })
            provider.maximum = 15
            assertTrue(MmsScanner.initialize(context) { commit -> commit(); true })
            assertEquals(listOf(10L, 14L, 15L), provider.snapshots)
        } finally {
            MmsScanner.reset(context)
        }
    }

    private class PendingInbox(private val rowExists: Boolean) : ContentProvider() {
        var partReads = 0
        override fun query(
            uri: Uri, projection: Array<out String>?, selection: String?,
            selectionArgs: Array<out String>?, sortOrder: String?
        ): Cursor = when (uri.toString()) {
            "content://mms" -> {
                assertTrue(selection.orEmpty().contains("_id IN (?)"))
                assertEquals(listOf("11", "11"), selectionArgs?.toList())
                MatrixCursor(arrayOf("_id")).apply { if (rowExists) addRow(arrayOf<Any>(11L)) }
            }
            "content://mms/part" -> {
                partReads++
                MatrixCursor(arrayOf("_id", "_data", "text")).apply {
                    addRow(arrayOf<Any?>(22L, null, "Your OTP is 482913. Do not share it with anyone."))
                }
            }
            "content://mms/11/addr" -> MatrixCursor(arrayOf("address"))
            else -> error("Unexpected URI: $uri")
        }
        override fun onCreate() = true
        override fun getType(uri: Uri): String? = null
        override fun insert(uri: Uri, values: ContentValues?): Uri? = error("read only")
        override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = error("read only")
        override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = error("read only")
    }

    private class Inbox : ContentProvider() {
        var maximum = 0L
        val snapshots = mutableListOf<Long>()

        override fun query(
            uri: Uri, projection: Array<out String>?, selection: String?,
            selectionArgs: Array<out String>?, sortOrder: String?
        ): Cursor {
            assertEquals("content://mms", uri.toString())
            assertEquals("_id DESC", sortOrder)
            snapshots.add(maximum)
            return MatrixCursor(arrayOf("_id")).apply { addRow(arrayOf<Any>(maximum)) }
        }

        override fun onCreate() = true
        override fun getType(uri: Uri): String? = null
        override fun insert(uri: Uri, values: ContentValues?): Uri? = error("read only")
        override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = error("read only")
        override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = error("read only")
    }
}
