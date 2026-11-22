package com.arm.threatassistant.sms

import java.io.Reader

object MmsText {
    const val MAX_CHARS = 100_000

    fun append(target: StringBuilder, text: String) {
        target.append(text, 0, minOf(text.length, MAX_CHARS - target.length))
    }

    fun append(target: StringBuilder, reader: Reader, checkActive: () -> Unit) {
        val buffer = CharArray(4096)
        while (target.length < MAX_CHARS) {
            checkActive()
            val count = reader.read(buffer, 0, minOf(buffer.size, MAX_CHARS - target.length))
            if (count <= 0) break
            target.append(buffer, 0, count)
        }
    }

    fun join(parts: List<Pair<String?, String?>>): String = buildString {
        for ((type, text) in parts) {
            if (type == "text/plain" && text != null) MmsText.append(this, text)
            if (length == MAX_CHARS) break
        }
    }
}

