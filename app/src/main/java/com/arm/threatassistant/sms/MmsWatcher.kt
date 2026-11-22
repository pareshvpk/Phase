package com.arm.threatassistant.sms

import android.Manifest
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.CancellationSignal
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

object MmsWatcher {
    const val JOB_ID = 4711
    internal const val SCAN_JOB_ID = 4712
    private val registration = Executors.newSingleThreadExecutor()
    private var generation = 0L
    private var running: CancellationSignal? = null

    internal fun allowed(context: Context) = SmsProtectionPreferences.isEnabled(context) &&
        hasReadSmsPermission(context) &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) ==
        PackageManager.PERMISSION_GRANTED

    fun schedule(context: Context) {
        val app = context.applicationContext
        if (!allowed(app)) {
            cancel(app)
            return
        }
        val expected = synchronized(this) { generation }
        registration.execute {
            try {
                // Snapshot before arming. The immediate pass catches writes between these operations.
                if (!prepare(app, expected)) return@execute
                synchronized(this) {
                    if (expected != generation || !allowed(app)) return@execute
                    val scheduler = requireNotNull(app.getSystemService(JobScheduler::class.java))
                    if (scheduler.getPendingJob(JOB_ID) == null) {
                        arm(app)
                        requestScan(app)
                    }
                }
            } catch (_: Exception) {
                Log.w("ARMSMS", "mms_registration_failed")
                synchronized(this) {
                    if (expected == generation && allowed(app)) requestScan(app)
                }
            }
        }
    }

    private fun prepare(context: Context, expected: Long): Boolean {
        return MmsScanner.initialize(context) { commit ->
            synchronized(this) {
                if (expected == generation && allowed(context)) {
                    commit()
                    true
                } else false
            }
        }
    }

    @Synchronized
    internal fun begin(context: Context, signal: CancellationSignal): Long? {
        if (!allowed(context)) return null
        running = signal
        return generation
    }

    internal fun scan(context: Context, signal: CancellationSignal, expected: Long): Boolean {
        signal.throwIfCanceled()
        if (!prepare(context, expected)) return false
        signal.throwIfCanceled()
        return MmsScanner.scanNew(context, signal)
    }

    @Synchronized
    internal fun checkpoint(context: Context, signal: CancellationSignal, save: () -> Unit) {
        signal.throwIfCanceled()
        if (running === signal && allowed(context)) save()
    }

    @Synchronized
    internal fun end(signal: CancellationSignal) {
        if (running === signal) running = null
    }

    @Synchronized
    internal fun arm(context: Context) {
        if (!allowed(context)) return
        val job = JobInfo.Builder(JOB_ID, ComponentName(context, MmsWatchJobService::class.java))
            .addTriggerContentUri(JobInfo.TriggerContentUri(
                Uri.parse("content://mms"), JobInfo.TriggerContentUri.FLAG_NOTIFY_FOR_DESCENDANTS
            ))
            .addTriggerContentUri(JobInfo.TriggerContentUri(
                Uri.parse("content://mms-sms"), JobInfo.TriggerContentUri.FLAG_NOTIFY_FOR_DESCENDANTS
            ))
            .setTriggerContentUpdateDelay(1500)
            .setTriggerContentMaxDelay(5000)
            .build()
        check(requireNotNull(context.getSystemService(JobScheduler::class.java)).schedule(job) == JobScheduler.RESULT_SUCCESS)
    }

    internal fun requestScan(context: Context) {
        try {
            if (!allowed(context)) return
            val job = JobInfo.Builder(SCAN_JOB_ID, ComponentName(context, MmsWatchJobService::class.java))
                .setMinimumLatency(0)
                .build()
            check(requireNotNull(context.getSystemService(JobScheduler::class.java)).schedule(job) == JobScheduler.RESULT_SUCCESS)
        } catch (_: Exception) {
            Log.w("ARMSMS", "mms_scan_unscheduled")
        }
    }

    @Synchronized
    fun cancel(context: Context) {
        generation++
        running?.cancel()
        running = null
        MmsScanner.reset(context)
        try {
            val scheduler = context.getSystemService(JobScheduler::class.java)
            scheduler?.cancel(JOB_ID)
            scheduler?.cancel(SCAN_JOB_ID)
        } catch (_: Exception) {
            Log.w("ARMSMS", "mms_cancel_failed")
        }
    }
}
