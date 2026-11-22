package com.arm.threatassistant.domain.apps

import org.junit.Assert.assertEquals
import org.junit.Test

class AppAccessTest {
    @Test fun screenReaderCapabilitiesAloneAreInformational() {
        for (sms in listOf(false, null)) {
            assertEquals(ReviewPriority.INFORMATION, AppAccess(true, true, sms, false).priority())
        }
    }

    @Test fun grantedSmsNeedsAnEnabledScreenOrGestureCapability() {
        assertEquals(ReviewPriority.INFORMATION, AppAccess(false, false, true, false).priority())
        assertEquals(ReviewPriority.REVIEW, AppAccess(true, false, true, false).priority())
        assertEquals(ReviewPriority.REVIEW, AppAccess(false, true, true, false).priority())
    }

    @Test fun systemAppCombinationRemainsInformational() {
        assertEquals(ReviewPriority.INFORMATION, AppAccess(true, true, true, true).priority())
    }
}
