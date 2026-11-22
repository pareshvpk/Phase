package com.arm.threatassistant.sms

import org.junit.Assert.assertEquals
import org.junit.Test

class MmsTextTest {

    @Test
    fun `joins text plain parts in order`() {
        val parts = listOf<Pair<String?, String?>>(
            "text/plain" to "Hello ",
            "image/jpeg" to null,
            "text/plain" to "world",
            "text/plain" to null
        )
        assertEquals("Hello world", MmsText.join(parts))
    }

    @Test
    fun `ignores non text parts and null bodies`() {
        assertEquals(
            "",
            MmsText.join(
                listOf(
                    "image/png" to "abc",
                    "text/plain" to null
                )
            )
        )
    }

    @Test
    fun `empty list joins to empty string`() {
        assertEquals("", MmsText.join(emptyList()))
    }

    @Test
    fun `mixed inline and streamed parts share the same budget`() {
        val result = StringBuilder("a".repeat(MmsText.MAX_CHARS - 2))
        val reader = "bcdef".reader()
        MmsText.append(result, reader) {}
        MmsText.append(result, "unused")
        assertEquals(MmsText.MAX_CHARS, result.length)
        assertEquals("abc", result.takeLast(3).toString())
        assertEquals('d'.code, reader.read())
    }

    @Test(expected = InterruptedException::class)
    fun `cancellation stops a stream before the next read`() {
        val result = StringBuilder()
        MmsText.append(result, "a".repeat(10_000).reader()) {
            if (result.isNotEmpty()) throw InterruptedException()
        }
    }
}
