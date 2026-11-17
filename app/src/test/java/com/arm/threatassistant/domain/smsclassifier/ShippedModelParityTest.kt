package com.arm.threatassistant.domain.smsclassifier

import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModelLoader
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.domain.normalization.InputNormalizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The shipped SMS model must score text in Kotlin exactly as the Python
 * trainer did (tools/sms_classifier/train.py). Expected probabilities were
 * computed with that script for the model in src/main/assets; regenerate
 * them whenever the model is retrained.
 */
class ShippedModelParityTest {

    private val classifier: SmsSpecialistClassifier by lazy {
        val json = File("src/main/assets/sms_classifier_model.json").readText(Charsets.UTF_8)
        SmsSpecialistClassifier.fromModel(SmsClassifierModelLoader.parse(json))
    }

    private val expected = listOf(
        "Dear customer, your SBI KYC will expire today. Update now at http://sbi-kyc-update.in or your account will be blocked." to 0.9769909397785226,
        "Hi, are we still meeting for lunch tomorrow at 1?" to 0.001667506555953521,
        "Rs.2,500 debited from A/c XX1234 on 17-11-26 by UPI. Not you? Call 1800-111-109 -HDFC Bank" to 0.17912958898842415,
        "Congratulations! You have won Rs 25 lakh in KBC lottery. Pay Rs 5000 processing fee to claim." to 0.9988863263359484,
        "आपका बिजली कनेक्शन आज रात 9 बजे काट दिया जाएगा। तुरंत इस नंबर पर कॉल करें।" to 0.8974098264530934,
        "Bhai kal party hai, time pe aa jana" to 0.010867680945953964,
        "உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே OTP பகிரவும்." to 0.5191198153450743,
        "Your order has been delivered. Thank you for shopping with us." to 0.013425533204673856
    )

    @Test
    fun kotlinScoresMatchPythonTrainer() {
        for ((text, pythonScore) in expected) {
            val input = InputNormalizer.normalize(AnalysisInput(messageText = text, source = InputSource.SMS))
            val score = classifier.classify(input).threatScore
            assertNotNull("No score for: $text", score)
            assertEquals("Score mismatch for: $text", pythonScore, score!!, 1e-6)
        }
    }

    @Test
    fun shippedModelIsTheTrainedOneNotTheFixture() {
        val json = File("src/main/assets/sms_classifier_model.json").readText(Charsets.UTF_8)
        val model = SmsClassifierModelLoader.parse(json)
        assertTrue("vocabulary too small: ${model.vocabulary.size}", model.vocabulary.size >= 5_000)
    }
}
