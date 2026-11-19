package com.arm.threatassistant.llm

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SentenceLimiterTest {

    @Test
    fun twoCompleteSentencesReachTheDefaultLimit() {
        assertTrue(SentenceLimiter.reached("This looks risky. Do not reply."))
    }

    @Test
    fun oneCompleteSentenceDoesNotReachTheDefaultLimit() {
        assertFalse(SentenceLimiter.reached("This looks risky."))
    }

    @Test
    fun sentenceEndNeedsWhitespaceOrEndOfText() {
        assertFalse(SentenceLimiter.reached("This looks risky.And this too."))
        assertTrue(SentenceLimiter.reached("This looks risky!\nAnd this too?"))
    }

    @Test
    fun questionAndExclamationMarksCount() {
        assertTrue(SentenceLimiter.reached("Really? Yes!"))
    }

    @Test
    fun hindiDandaCounts() {
        assertTrue(SentenceLimiter.reached("यह संदिग्ध है। उत्तर न दें।"))
    }

    @Test
    fun dotsInsideNumbersAreNotSentenceEnds() {
        assertFalse(SentenceLimiter.reached("The fee is 2.5 percent."))
        assertFalse(SentenceLimiter.reached("You won Rs.500 today."))
    }

    @Test
    fun numberDotsDoNotHideRealSentenceEnds() {
        assertTrue(SentenceLimiter.reached("You won Rs.500 today. Do not pay any fee."))
        assertTrue(SentenceLimiter.reached("It grew 2.5 times. That is suspicious."))
    }

    @Test
    fun customLimitIsRespected() {
        assertTrue(SentenceLimiter.reached("One. Two. Three.", maxSentences = 3))
        assertFalse(SentenceLimiter.reached("One. Two.", maxSentences = 3))
        assertTrue(SentenceLimiter.reached("Anything", maxSentences = 0))
    }
}
