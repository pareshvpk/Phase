package com.arm.threatassistant.presentation.onboarding

import android.content.Intent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OnboardingPolicyTest {
    @Test
    fun `first launcher start shows introduction`() {
        assertTrue(shouldShowOnboarding(false, Intent.ACTION_MAIN))
    }

    @Test
    fun `start without action shows introduction`() {
        assertTrue(shouldShowOnboarding(false, null))
    }

    @Test
    fun `completed introduction stays dismissed for every entry point`() {
        listOf(null, Intent.ACTION_MAIN, Intent.ACTION_SEND, Intent.ACTION_PROCESS_TEXT)
            .forEach { assertFalse(shouldShowOnboarding(true, it)) }
    }

    @Test
    fun `first share including empty share bypasses introduction`() {
        assertFalse(shouldShowOnboarding(false, Intent.ACTION_SEND))
    }

    @Test
    fun `first selected text bypasses introduction`() {
        assertFalse(shouldShowOnboarding(false, Intent.ACTION_PROCESS_TEXT))
    }

    @Test
    fun `bypassing share does not complete next launcher introduction`() {
        assertFalse(shouldShowOnboarding(false, Intent.ACTION_SEND))
        assertTrue(shouldShowOnboarding(false, Intent.ACTION_MAIN))
    }
}
