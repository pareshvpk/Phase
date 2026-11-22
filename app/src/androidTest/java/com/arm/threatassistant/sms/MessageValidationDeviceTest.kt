package com.arm.threatassistant.sms

import android.Manifest
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the real message processor with synthetic text and isolated alert storage.
 * Does not access the SMS inbox, send messages, or post notifications.
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 33)
class MessageValidationDeviceTest {
    private lateinit var context: Context
    private lateinit var folder: File

    @Before fun isolateStorage() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        folder = File(target.cacheDir, "message-validation-${UUID.randomUUID()}")
        check(folder.mkdir())
        context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = folder
            override fun checkPermission(permission: String, pid: Int, uid: Int): Int =
                if (permission == Manifest.permission.POST_NOTIFICATIONS) PackageManager.PERMISSION_DENIED
                else super.checkPermission(permission, pid, uid)
        }
    }

    @After fun cleanUp() {
        TodayAlertsStore.clear(context)
        folder.delete()
    }

    @Test fun sensitiveAndOrdinaryMessagesAreNotStored() {
        listOf(
            "Your OTP is 482913. Do not share it with anyone.",
            "Your OTP is 482615. Don't ever enter your UPI PIN to receive a refund.",
            "INR 5000 credited to your account via UPI ref 123456789012",
            "Your temporary password is Xy7#kLm2. Username: test_user",
            "Hey are we still meeting at 5 today?",
            "Security reminder: Never share your OTP, password or PIN with anyone."
        ).forEachIndexed { index, text ->
            SmsThreatProcessor.process(context, "AX-HDFCBK", text, "safe-$index")
        }
        assertTrue(TodayAlertsStore.getToday(context).isEmpty())
        assertFalse(File(folder, "today_alerts.json").exists())
    }

    @Test fun credentialRequestsAlertEvenWithOtpOrBusinessHeader() {
        val cases = listOf(
            "Someone is using your card. Reply with your OTP and PIN immediately to block the transaction.",
            "Your OTP is 482615. Reply with the code to cancel this transaction.",
            "Never share your OTP with strangers. Share your OTP with our agent.",
            "Aapka OTP 482615 hai. Apna OTP abhi bhejo."
        )
        for ((index, text) in cases.withIndex()) {
            SmsThreatProcessor.process(context, "AX-HDFCBK", text, "credential-$index")
        }
        val alerts = TodayAlertsStore.getToday(context)
        assertEquals(cases.size, alerts.size)
        assertEquals(cases.toSet(), alerts.map { it.body }.toSet())
        assertTrue(alerts.all { it.reasonIds.isNotEmpty() })
    }

    @Test fun repeatedMmsIdProducesOneStoredAlert() {
        val body = "Approve the UPI request to receive your refund."
        repeat(2) { SmsThreatProcessor.process(context, "+919999999999", body, "mms-validation-1") }
        val alerts = TodayAlertsStore.getToday(context)
        assertEquals(1, alerts.size)
        assertEquals("mms-validation-1", alerts.single().id)
        assertEquals(body, alerts.single().body)
    }

    @Test fun cancelledMessageDoesNotPersistAnAlert() {
        SmsThreatProcessor.process(
            context, "+919999999999",
            "Reply with your OTP and PIN immediately to block the transaction.",
            "cancelled"
        ) { false }
        assertTrue(TodayAlertsStore.getToday(context).isEmpty())
        assertFalse(File(folder, "today_alerts.json").exists())
    }
}
