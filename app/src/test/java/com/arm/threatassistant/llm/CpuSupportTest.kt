package com.arm.threatassistant.llm

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CpuSupportTest {
    private val armv82 = """
        processor : 0
        BogoMIPS : 384.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd07
        CPU revision : 3

        processor : 1
        BogoMIPS : 384.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd07
        CPU revision : 3
    """.trimIndent()

    private val armv80 = """
        processor : 0
        BogoMIPS : 250.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x0
        CPU part : 0xd03
        CPU revision : 4

        processor : 1
        BogoMIPS : 250.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x0
        CPU part : 0xd03
        CPU revision : 4
    """.trimIndent()

    private val armv82WithTrailingBlock = """
        processor : 0
        BogoMIPS : 384.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd07
        CPU revision : 3

        processor : 1
        BogoMIPS : 384.00
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd07
        CPU revision : 3

        Hardware : Qualcomm
        Revision : 0000
        Serial : 0123456789
    """.trimIndent()

    private val armv82OneCoreMissingAtomics = """
        processor : 0
        Features : fp asimd atomics

        processor : 1
        Features : fp asimd
    """.trimIndent()

    private val noFeaturesLine = """
        processor : 0
        BogoMIPS : 250.00
        CPU implementer : 0x41
    """.trimIndent()

    @Test
    fun armv82CoreWithAtomicsIsSupported() {
        assertTrue(CpuSupport.isSupported(armv82))
    }

    @Test
    fun armv80CoreWithoutAtomicsIsNotSupported() {
        assertFalse(CpuSupport.isSupported(armv80))
    }

    @Test
    fun oneCoreMissingAtomicsMeansNotSupported() {
        assertFalse(CpuSupport.isSupported(armv82OneCoreMissingAtomics))
    }

    @Test
    fun coreWithoutFeaturesLineIsNotSupported() {
        assertFalse(CpuSupport.isSupported(noFeaturesLine))
    }

    @Test
    fun emptyCpuinfoIsNotSupported() {
        assertFalse(CpuSupport.isSupported(""))
        assertFalse(CpuSupport.isSupported("processor : 0\n"))
    }

    @Test
    fun armv82WithTrailingBlockIsSupported() {
        assertTrue(CpuSupport.isSupported(armv82WithTrailingBlock))
    }

    @Test
    fun armv82WithTrailingBlockOneCoreMissingAtomicsIsNotSupported() {
        val mixed = """
        processor : 0
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd07
        CPU revision : 3

        processor : 1
        Features : fp asimd evtstrm aes pmull sha1 sha2 crc32
        CPU implementer : 0x41
        CPU architecture : 8
        CPU variant : 0x1
        CPU part : 0xd03
        CPU revision : 4

        Hardware : Qualcomm
        Revision : 0000
        Serial : 0123456789
    """.trimIndent()
        assertFalse(CpuSupport.isSupported(mixed))
    }

    @Test
    fun textWithNoFeaturesLineIsNotSupported() {
        assertFalse(CpuSupport.isSupported(noFeaturesLine))
    }

    @Test
    fun crlfVersionOfArmv82IsSupported() {
        val crlf = """processor : 0
BogoMIPS : 384.00
Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
CPU implementer : 0x41
CPU architecture : 8
CPU variant : 0x1
CPU part : 0xd07
CPU revision : 3

processor : 1
BogoMIPS : 384.00
Features : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp
CPU implementer : 0x41
CPU architecture : 8
CPU variant : 0x1
CPU part : 0xd07
CPU revision : 3""".trimIndent().replace("\n", "\r\n")
        assertTrue(CpuSupport.isSupported(crlf))
    }
}
