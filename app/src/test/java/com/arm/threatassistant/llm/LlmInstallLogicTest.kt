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
    fun completeInstallNeedsMarkerMatchingFilesOnDisk() {
        val marker = LlmInstallLogic.Marker(modelBytes = 1_100L * megabyte, tokenizerBytes = 2L * megabyte)
        val model = marker.modelBytes
        val tok = marker.tokenizerBytes

        assertTrue(LlmInstallLogic.isCompleteInstall(marker, model, tok, expectedModelBytes = 0L))
        assertFalse(LlmInstallLogic.isCompleteInstall(null, model, tok, 0L))
        assertFalse(LlmInstallLogic.isCompleteInstall(marker, model - 1, tok, 0L))
        assertFalse(LlmInstallLogic.isCompleteInstall(marker, model, tok - 1, 0L))
        assertFalse(LlmInstallLogic.isCompleteInstall(marker.copy(modelBytes = 0L), 0L, tok, 0L))
    }

    @Test
    fun newExpectedModelSizeForcesFreshDownload() {
        val oldModel = 1_700L * megabyte
        val marker = LlmInstallLogic.Marker(modelBytes = oldModel, tokenizerBytes = 2L * megabyte)

        assertTrue(LlmInstallLogic.isCompleteInstall(marker, oldModel, 2L * megabyte, expectedModelBytes = oldModel))
        assertFalse(
            LlmInstallLogic.isCompleteInstall(marker, oldModel, 2L * megabyte, expectedModelBytes = 1_100L * megabyte)
        )
    }

    @Test
    fun resumeOffsetContinuesPartialDownloadsOnly() {
        assertEquals(0L, LlmInstallLogic.resumeOffset(partialBytes = 0L, expectedTotalBytes = 100L))
        assertEquals(40L, LlmInstallLogic.resumeOffset(partialBytes = 40L, expectedTotalBytes = 100L))
        assertEquals(40L, LlmInstallLogic.resumeOffset(partialBytes = 40L, expectedTotalBytes = 0L))
        assertEquals(0L, LlmInstallLogic.resumeOffset(partialBytes = 100L, expectedTotalBytes = 100L))
        assertEquals(0L, LlmInstallLogic.resumeOffset(partialBytes = 120L, expectedTotalBytes = 100L))
    }

    @Test
    fun hexEncodingIsLowercaseAndPadded() {
        assertEquals("00ff0a", LlmInstallLogic.toHex(byteArrayOf(0, -1, 10)))
    }
}
