package com.arm.threatassistant.llm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LlmInstallLogicTest {

    private val megabyte = 1024L * 1024L

    @Test
    fun requiredFreeBytesAddsFiftyMegabyteReserve() {
        assertEquals(50L * megabyte, LlmInstallLogic.requiredFreeBytes(0L))
        assertEquals(1_700L * megabyte + 50L * megabyte, LlmInstallLogic.requiredFreeBytes(1_700L * megabyte))
    }

    @Test
    fun hasEnoughSpaceRequiresAssetPlusReserve() {
        val assetBytes = 100L * megabyte
        val required = LlmInstallLogic.requiredFreeBytes(assetBytes)

        assertTrue(LlmInstallLogic.hasEnoughSpace(required, assetBytes))
        assertTrue(LlmInstallLogic.hasEnoughSpace(required + 1L, assetBytes))
        assertFalse(LlmInstallLogic.hasEnoughSpace(required - 1L, assetBytes))
    }

    @Test
    fun exactAssetSizeWithoutReserveIsRejected() {
        val assetBytes = 100L * megabyte
        assertFalse(LlmInstallLogic.hasEnoughSpace(assetBytes, assetBytes))
    }

    @Test
    fun progressIsFractionOfTotal() {
        assertEquals(0f, LlmInstallLogic.progress(0L, 200L), 0.0001f)
        assertEquals(0.25f, LlmInstallLogic.progress(50L, 200L), 0.0001f)
        assertEquals(1f, LlmInstallLogic.progress(200L, 200L), 0.0001f)
    }

    @Test
    fun progressIsClampedAndSafeForEmptyTotal() {
        assertEquals(0f, LlmInstallLogic.progress(10L, 0L), 0.0001f)
        assertEquals(1f, LlmInstallLogic.progress(300L, 200L), 0.0001f)
    }

    @Test
    fun markerMatchesOnlyWhenEveryFieldMatches() {
        val expected = LlmInstallLogic.Marker(
            modelBytes = 1_700L * megabyte,
            tokenizerBytes = 2L * megabyte,
            versionCode = 7L
        )

        assertTrue(LlmInstallLogic.markerMatches(expected.copy(), expected))
        assertFalse(LlmInstallLogic.markerMatches(null, expected))
        assertFalse(LlmInstallLogic.markerMatches(expected.copy(modelBytes = 1L), expected))
        assertFalse(LlmInstallLogic.markerMatches(expected.copy(tokenizerBytes = 1L), expected))
        assertFalse(LlmInstallLogic.markerMatches(expected.copy(versionCode = 6L), expected))
    }
}
