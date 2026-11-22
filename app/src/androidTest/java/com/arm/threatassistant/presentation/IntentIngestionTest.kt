package com.arm.threatassistant.presentation

import android.content.Intent
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arm.threatassistant.MainActivity
import com.arm.threatassistant.R
import com.arm.threatassistant.presentation.onboarding.OnboardingPrefs
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IntentIngestionTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var wasDone = false

    @Before fun firstRun() {
        wasDone = OnboardingPrefs.isDone(context)
        OnboardingPrefs.reset(context)
    }

    @After fun restore() {
        if (wasDone) OnboardingPrefs.markDone(context) else OnboardingPrefs.reset(context)
    }

    private fun intent(action: String, body: String? = null) =
        Intent(action).setClass(context, MainActivity::class.java).apply {
            if (action != Intent.ACTION_MAIN) type = "text/plain"
            if (body != null) putExtra(
                if (action == Intent.ACTION_PROCESS_TEXT) Intent.EXTRA_PROCESS_TEXT else Intent.EXTRA_TEXT,
                body
            )
        }

    private fun await(description: String, predicate: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (predicate()) return
            SystemClock.sleep(50)
        }
        throw AssertionError(description)
    }

    private fun node(id: Int): AccessibilityNodeInfo? {
        val text = context.getString(id)
        // Compose exposes virtual children, but provider text-search is not
        // implemented consistently across Android/OEM versions. Walk the same
        // tree used by UiAutomator instead of relying on that search shortcut.
        fun find(current: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
            if (current == null) return null
            if (current.text?.toString() == text || current.contentDescription?.toString() == text) {
                return current
            }
            for (index in 0 until current.childCount) {
                find(current.getChild(index))?.let { return it }
            }
            return null
        }
        return find(instrumentation.uiAutomation.rootInActiveWindow)
    }

    private fun expectVisible(id: Int) = await(context.getString(id)) { node(id) != null }

    private fun click(id: Int) {
        await("Clickable ${context.getString(id)}") {
            var target = node(id)
            while (target != null && !target.isClickable) target = target.parent
            target?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
        }
    }

    private fun expectInput(scenario: ActivityScenario<MainActivity>, body: String) {
        await("Activity view model received shared input") {
            var matches = false
            scenario.onActivity {
                matches = ViewModelProvider(it)[ThreatAnalysisViewModel::class.java].uiState.value.inputText == body
            }
            matches
        }
    }

    @Test fun processTextBypassesIntroductionAndSurvivesRecreation() {
        val body = "Selected text for inspection"
        ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_PROCESS_TEXT, body)).use {
            expectInput(it, body)
            val edit = "My edited draft"
            it.onActivity { activity ->
                ViewModelProvider(activity)[ThreatAnalysisViewModel::class.java].onMessageChanged(activity, edit)
            }
            click(R.string.nav_today)
            click(R.string.nav_check)
            expectInput(it, edit)
            it.recreate()
            expectInput(it, edit)
            it.onActivity { activity ->
                activity.startActivity(intent(Intent.ACTION_PROCESS_TEXT, body).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP))
            }
            expectInput(it, body)
            expectVisible(R.string.nav_check)
        }
        assertFalse(OnboardingPrefs.isDone(context))
    }

    @Test fun incomingShareInterruptsAnOpenIntroduction() {
        ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_MAIN)).use { scenario ->
            lateinit var originalIntent: Intent
            scenario.onActivity { originalIntent = Intent(it.intent) }
            try {
                expectVisible(R.string.onboarding_check_title)
                val body = "Shared while the introduction was open"
                scenario.onActivity {
                    it.startActivity(intent(Intent.ACTION_SEND, body).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP))
                }
                expectInput(scenario, body)
                expectVisible(R.string.nav_check)
                assertFalse(OnboardingPrefs.isDone(context))
            } finally {
                // ActivityScenario filters lifecycle callbacks by the launching
                // intent. MainActivity correctly stores the new SEND intent;
                // restore only the test's identity before scenario teardown.
                scenario.onActivity { it.intent = originalIntent }
            }
        }
    }

    @Test fun emptyShareBypassesIntroductionWithoutCompletingIt() {
        ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_SEND)).use {
            expectVisible(R.string.nav_check)
            assertFalse(OnboardingPrefs.isDone(context))
        }
    }

    @Test fun introductionKeepsPageOnRecreationAndRemembersSkip() {
        ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_MAIN)).use {
            expectVisible(R.string.onboarding_check_title)
            click(R.string.onboarding_next)
            expectVisible(R.string.onboarding_privacy_title)
            it.recreate()
            expectVisible(R.string.onboarding_privacy_title)
            click(R.string.onboarding_skip)
            expectVisible(R.string.nav_check)
            assertTrue(OnboardingPrefs.isDone(context))
        }
        ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_MAIN)).use {
            expectVisible(R.string.nav_check)
        }
    }
}
