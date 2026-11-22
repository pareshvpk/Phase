package com.arm.threatassistant.domain.apps

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppReviewHistoryTest {
    private val reader = AppAccess(true, true, false, false)
    private val limited = AppAccess(false, false, false, false)
    private fun scan(access: AppAccess, old: AppComparison? = null) =
        compareAccess(old?.baseline, mapOf("reader" to access))

    @Test fun firstSnapshotIsOnlyABaseline() {
        assertTrue(scan(reader).changes.isEmpty())
    }

    @Test fun unchangedAssistiveToolProducesNoChangeEvidence() {
        assertTrue(scan(reader, scan(reader)).changes.isEmpty())
    }

    @Test fun firstObservationAfterEmptyBaselineOnlyReportsVisibility() {
        val old = compareAccess(null, emptyMap())
        assertEquals(setOf(AccessChange.NEWLY_VISIBLE), scan(reader, old).changes["reader"])
    }

    @Test fun separateCapabilitiesAreComparedForSamePackage() {
        val changes = scan(reader.copy(smsGranted = true), scan(limited)).changes["reader"]
        assertEquals(setOf(AccessChange.SCREEN, AccessChange.GESTURES, AccessChange.SMS), changes)
    }

    @Test fun reducedAndRestoredAccessIsReportedOnlyOnRestoration() {
        val reduced = scan(limited, scan(reader))
        assertTrue(reduced.changes.isEmpty())
        assertEquals(setOf(AccessChange.GESTURES),
            scan(limited.copy(performsGestures = true), reduced).changes["reader"])
    }

    @Test fun unknownSmsStateRetainsLastVerifiedValue() {
        val missing = scan(reader.copy(smsGranted = null), scan(reader))
        assertTrue(missing.changes.isEmpty())
        assertEquals(setOf(AccessChange.SMS), scan(reader.copy(smsGranted = true), missing).changes["reader"])
    }

    @Test fun previouslyUnknownSmsStateCannotEstablishANewGrant() {
        val missing = scan(reader.copy(smsGranted = null))
        assertTrue(scan(reader.copy(smsGranted = true), missing).changes.isEmpty())
    }

    @Test fun packageVisibilityLossDoesNotEraseLastKnownCapabilities() {
        val missing = compareAccess(scan(reader).baseline, emptyMap())
        assertTrue(missing.changes.isEmpty())
        val restored = scan(reader, missing)
        assertEquals(setOf(AccessChange.NEWLY_VISIBLE), restored.changes["reader"])
        assertTrue(scan(reader, restored).changes.isEmpty())
    }

    @Test fun resettingToNoBaselineDiscardsChangeHistory() {
        val full = reader.copy(smsGranted = true)
        assertTrue(scan(full, scan(limited)).changes.isNotEmpty())
        assertTrue(scan(full, null).changes.isEmpty())
    }
}
