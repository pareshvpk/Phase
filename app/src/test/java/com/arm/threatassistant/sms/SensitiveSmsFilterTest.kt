package com.arm.threatassistant.sms

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SensitiveSmsFilterTest {

    @Test
    fun `otp with do not share warning is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "Your OTP is 482913. Do not share it with anyone. -HDFC Bank"
            )
        )
    }

    @Test
    fun `verification code with leading digits is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "483920 is your verification code for Google."
            )
        )
    }

    @Test
    fun `bank debit alert is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Rs.1,250.00 debited from A/c XX4321 on 12-Nov-26. Avl Bal Rs.8,430.55"
            )
        )
    }

    @Test
    fun `upi credit alert is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "INR 5000 credited to your account via UPI ref 123456789012"
            )
        )
    }

    @Test
    fun `temporary password message is credentials`() {
        assertEquals(
            SensitiveSmsKind.CREDENTIALS,
            SensitiveSmsFilter.classify(
                "Your temporary password is Xy7#kLm2. Username: john_d"
            )
        )
    }

    @Test
    fun `otp with link is still otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "Your OTP is 123456. Verify at http://bit-secure.xyz/login"
            )
        )
    }

    @Test
    fun `otp share request with kyc is not skippable`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "Dear customer share your OTP 445566 with our agent to complete KYC"
            )
        )
    }

    @Test
    fun `transaction with callback number is still transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Your a/c will be blocked. Rs 10 debited. Call 9876543210 now"
            )
        )
    }

    @Test
    fun `prize with link is not skippable`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "Congratulations you won Rs 50000 prize, click www.win.top"
            )
        )
    }

    @Test
    fun `ordinary conversation is not skippable`() {
        assertNull(SensitiveSmsFilter.classify("Hey are we still meeting at 5 today?"))
    }

    @Test
    fun `blank input is not skippable`() {
        assertNull(SensitiveSmsFilter.classify(""))
    }

    @Test
    fun `should skip otp`() {
        assertTrue(SensitiveSmsFilter.shouldSkip("Your OTP is 482913. Do not share it with anyone."))
    }

    @Test
    fun `should skip transaction`() {
        assertTrue(
            SensitiveSmsFilter.shouldSkip(
                "Rs.1,250.00 debited from A/c XX4321 on 12-Nov-26. Avl Bal Rs.8,430.55"
            )
        )
    }

    @Test
    fun `should skip credentials`() {
        assertTrue(
            SensitiveSmsFilter.shouldSkip(
                "Your temporary password is Xy7#kLm2. Username: john_d"
            )
        )
    }

    @Test
    fun `should not skip scam message`() {
        assertFalse(
            SensitiveSmsFilter.shouldSkip(
                "Dear customer share your OTP 445566 with our agent to complete KYC"
            )
        )
    }

    @Test
    fun `should not skip ordinary message`() {
        assertFalse(SensitiveSmsFilter.shouldSkip("Hey are we still meeting at 5 today?"))
    }

    @Test
    fun `bank otp with transaction details is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "123456 is your OTP for txn of INR 2,499.00 at AMAZON on HDFC Bank card ending 1234. Valid for 10 mins. Do not share OTP with anyone."
            )
        )
    }

    @Test
    fun `debit alert with block helpline is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Rs.1,250.00 debited from A/c XX4321 on 12-Nov-26 to VPA abc@okaxis (UPI Ref 431234567890). Not you? Call 18002586161 or SMS BLOCK UPI to 9223008333 -HDFC Bank"
            )
        )
    }

    @Test
    fun `credit card spend with dispute link is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Dear Customer, Rs 499 spent on your SBI Credit Card ending 1234 at SWIGGY on 13/11/26. If not done by you, click https://sbicard.com/dispute"
            )
        )
    }

    @Test
    fun `paytm login otp with link is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "Use 4821 as your login OTP for Paytm. Never share it. Visit paytm.com/care if not requested"
            )
        )
    }

    @Test
    fun `whatsapp split code is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "<#> Your WhatsApp code: 123-456 Don't share this code with others"
            )
        )
    }

    @Test
    fun `banking otp with blocked warning and helpline is otp`() {
        assertEquals(
            SensitiveSmsKind.OTP,
            SensitiveSmsFilter.classify(
                "OTP for your SBI internet banking login is 55443322. Do not share with anyone. If not requested, your account may be blocked - call 1800112211"
            )
        )
    }

    @Test
    fun `refund credited message is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Dear Customer, your refund of Rs. 349.00 has been credited to your a/c XX9911. -Flipkart"
            )
        )
    }

    @Test
    fun `cashback reward message is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Your Amazon Pay balance: Rs.250 added as cashback reward for your recent payment of Rs.999."
            )
        )
    }

    @Test
    fun `netflix txn with block sms is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "Txn of USD 12.99 done on your Axis Bank card XX4455 at NETFLIX.COM. Avl limit INR 85,000. Not you? SMS BLOCK 4455 to 919951860002"
            )
        )
    }

    @Test
    fun `rbi digital arrest advisory is not sensitive`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "Threatened with Digital Arrest? There is nothing like Digital Arrest in law. Don't share personal/financial information or pay money. Call 1930 for help. -RBI"
            )
        )
    }

    @Test
    fun `spin promo is not sensitive`() {
        assertNull(SensitiveSmsFilter.classify("Spin is live now, play today and enjoy"))
    }

    @Test
    fun `credited amount with link is not skippable`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "Rs 5000 will be credited to your a/c. Click this link to receive the amount http://bit.ly/x9z"
            )
        )
    }

    @Test
    fun `lottery prize with link is not skippable`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "Your a/c is credited with Rs 25,000 lottery prize. Claim now at www.prize-claim.top"
            )
        )
    }

    @Test
    fun `upi cashback reward with link is not skippable`() {
        assertNull(
            SensitiveSmsFilter.classify(
                "UPI cashback of Rs 2000 pending. Tap https://upi-reward.xyz/claim to collect payment of Rs 2000"
            )
        )
    }

    @Test
    fun `upi credit with details link is transaction`() {
        assertEquals(
            SensitiveSmsKind.TRANSACTION,
            SensitiveSmsFilter.classify(
                "You have received Rs 500.00 from RAMESH K in your a/c XX1234. UPI Ref 431298765432. Details: https://hdfc.bk/a1b2"
            )
        )
    }
}
