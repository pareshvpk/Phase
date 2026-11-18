package com.arm.threatassistant.domain.detection.urldetection

/**
 * Severity of a single URL detection signal.
 */
enum class UrlDetectionSeverity {
    LOW,
    MEDIUM,
    HIGH
}

/**
 * Category of URL detection signal.
 */
enum class UrlDetectionCategory {
    IP_BASED_URL,
    SUSPICIOUS_DOMAIN,
    HOMOGRAPH_ATTACK,
    URL_SHORTENER,
    SUSPICIOUS_SUBDOMAIN,
    MISLEADING_STRUCTURE,
    UNUSUAL_PORT,
    ENCODED_CHARACTERS,
    SUSPICIOUS_TLD,
    EXCESSIVE_LENGTH,
    ML_PHISHING_HOST
}

/**
 * A single structured URL detection signal.
 */
data class UrlDetectionSignal(
    val signalId: String,
    val category: UrlDetectionCategory,
    val severity: UrlDetectionSeverity,
    val description: String,
    val matchedUrl: String,
    val matchedComponent: String?,
    val detectorId: String,
    val detectorVersion: String
)

/**
 * Aggregated output of [UrlSpecialistDetector].
 *
 * Contains every detected URL signal for an input. No verdict is produced;
 * verdict determination is the responsibility of the RiskPolicyEngine.
 */
data class UrlDetectionResult(
    val urls: List<UrlAnalysis>,
    val signals: List<UrlDetectionSignal>,
    val detectorId: String,
    val detectorVersion: String
) {
    val signalCount: Int get() = signals.size
    val categoriesDetected: Set<UrlDetectionCategory> get() = signals.map { it.category }.toSet()
    val hasSignals: Boolean get() = signals.isNotEmpty()
    val hasUrls: Boolean get() = urls.isNotEmpty()
}

/**
 * Analysis of a single URL found in the input.
 */
data class UrlAnalysis(
    val originalUrl: String,
    val scheme: String?,
    val host: String?,
    val port: Int?,
    val path: String?,
    val isIpBased: Boolean,
    val isUrlShortener: Boolean,
    val suspiciousIndicators: List<String>
)

/**
 * Known URL shortener domains (offline list, no network lookup).
 */
internal object UrlShortenerList {
    val domains = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "adf.ly",
        "bit.do", "cutt.ly", "rebrand.ly", "short.url", "is.gd", "cli.re",
        "po.st", "bc.vc", "tiny.cc", "tr.im", "su.pr", "chilp.it", "x.co"
    )

    fun isShortener(host: String?): Boolean {
        host ?: return false
        val normalized = host.lowercase()
        return domains.any { normalized == it || normalized.endsWith(".$it") }
    }
}

/**
 * Suspicious TLDs commonly abused in phishing (offline heuristic list).
 */
internal object SuspiciousTldList {
    val tlds = setOf(
        "xyz", "top", "club", "loan", "buzz", "work", "date", "download",
        "review", "country", "stream", "science", "win", "men", "racing",
        "cf", "ga", "gq", "ml", "tk", "cm", "biz"
    )

    fun isSuspicious(host: String?): Boolean {
        host ?: return false
        val parts = host.split(".")
        if (parts.size < 2) return false
        val tld = parts.last().lowercase()
        return tlds.contains(tld)
    }
}

/**
 * Common legitimate brand names used for homograph/impersonation detection.
 */
internal object BrandNameList {
    val brands = listOf(
        "paypal", "amazon", "apple", "microsoft", "google", "facebook",
        "instagram", "whatsapp", "netflix", "bank", "hdfc", "sbi", "icici",
        "axis", "upi", "phonepe", "paytm", "flipkart", "myntra", "snapdeal"
    )

    fun containsBrand(host: String?): Boolean {
        host ?: return false
        val lower = host.lowercase()
        return brands.any { lower.contains(it) }
    }
}
