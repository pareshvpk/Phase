package com.arm.threatassistant.domain.detection.urldetection

import java.net.URI
import java.util.regex.Pattern

/**
 * Offline URL threat-analysis component.
 *
 * Inspects URLs extracted from input text and produces structured detection
 * signals. Operates entirely offline — no DNS lookups, no HTTP requests,
 * no URL visits, no network access of any kind.
 *
 * Detected signal categories:
 *   - IP_BASED_URL — URL uses an IP address instead of a domain name
 *   - SUSPICIOUS_DOMAIN — domain matches known suspicious patterns
 *   - HOMOGRAPH_ATTACK — domain uses mixed scripts or look-alike characters
 *   - URL_SHORTENER — domain is a known URL shortener
 *   - SUSPICIOUS_SUBDOMAIN — excessive or misleading subdomain depth
 *   - MISLEADING_STRUCTURE — URL structure designed to confuse (e.g. @ in userinfo)
 *   - UNUSUAL_PORT — non-standard port for the scheme
 *   - ENCODED_CHARACTERS — URL-encoded characters that may obfuscate the destination
 *   - SUSPICIOUS_TLD — top-level domain commonly abused in phishing
 *   - EXCESSIVE_LENGTH — unusually long URL
 */
object UrlSpecialistDetector {

    internal const val DETECTOR_ID = "UrlSpecialistDetector"
    internal const val DETECTOR_VERSION = "1.0.0"

    private const val MAX_URL_LENGTH = 200
    private const val MAX_SUBDOMAIN_DEPTH = 3
    private const val MAX_PATH_SEGMENTS = 10

    // Matches IP address literals (IPv4 dotted-decimal) as a URL host.
    private val IPV4_PATTERN = Pattern.compile(
        "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
    )

    // Detects mixed-script (Cyrillic + Latin, etc.) in domain labels for homograph detection.
    private val HAS_CYRILLIC = Pattern.compile("[\\u0400-\\u04FF]")
    private val HAS_GREEK = Pattern.compile("[\\u0370-\\u03FF]")
    private val HAS_LATIN = Pattern.compile("[a-zA-Z]")

    // Suspicious keywords in domain names that suggest impersonation.
    private val SUSPICIOUS_DOMAIN_KEYWORDS = listOf(
        "secure", "verify", "account", "banking", "payment", "update",
        "confirm", "suspend", "limited", "urgent", "bonus", "winner",
        "prize", "reward", "login", "signin", "auth", "validate"
    )

    // Suspicious path/structure indicators.
    private val MISLEADING_PATH_KEYWORDS = listOf(
        "verify", "suspend", "urgent", "login", "signin", "account"
    )

    /**
     * Analyzes all URLs in [input] and returns a [UrlDetectionResult].
     *
     * URLs are taken from [input.extractedUrls] if available, otherwise
     * extracted from [input.messageText] using the same pattern as
     * [com.arm.threatassistant.domain.normalization.InputNormalizer].
     */
    fun detect(input: com.arm.threatassistant.domain.model.AnalysisInput): UrlDetectionResult {
        val urls = input.extractedUrls
        val analyses = mutableListOf<UrlAnalysis>()
        val signals = mutableListOf<UrlDetectionSignal>()
        var signalIndex = 0

        for (url in urls) {
            val analysis = analyzeUrl(url)
            analyses.add(analysis)

            // IP-based URL.
            if (analysis.isIpBased) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.IP_BASED_URL,
                    severity = UrlDetectionSeverity.HIGH,
                    description = "URL uses an IP address literal instead of a domain name.",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // URL shortener.
            if (analysis.isUrlShortener) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.URL_SHORTENER,
                    severity = UrlDetectionSeverity.MEDIUM,
                    description = "URL shortener obscures the final destination.",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Suspicious TLD.
            if (analysis.host != null && SuspiciousTldList.isSuspicious(analysis.host)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.SUSPICIOUS_TLD,
                    severity = UrlDetectionSeverity.MEDIUM,
                    description = "Domain uses a top-level domain commonly abused in phishing.",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Homograph / mixed-script domain.
            if (analysis.host != null && isHomographAttack(analysis.host)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.HOMOGRAPH_ATTACK,
                    severity = UrlDetectionSeverity.HIGH,
                    description = "Domain mixes scripts or uses look-alike characters (homograph attack).",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Suspicious subdomain depth.
            if (analysis.host != null && isSuspiciousSubdomain(analysis.host)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.SUSPICIOUS_SUBDOMAIN,
                    severity = UrlDetectionSeverity.MEDIUM,
                    description = "Domain has excessive subdomain depth, often used to mimic legitimate brands.",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Misleading structure (e.g. @ in userinfo, brand name after path).
            if (isMisleadingStructure(url)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.MISLEADING_STRUCTURE,
                    severity = UrlDetectionSeverity.HIGH,
                    description = "URL structure is designed to mislead about the true destination.",
                    matchedUrl = url,
                    matchedComponent = null,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Unusual port.
            if (analysis.port != null && isUnusualPort(analysis.port!!, analysis.scheme)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.UNUSUAL_PORT,
                    severity = UrlDetectionSeverity.MEDIUM,
                    description = "URL uses a non-standard port for its scheme.",
                    matchedUrl = url,
                    matchedComponent = "${analysis.host}:${analysis.port}",
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Encoded characters.
            if (hasEncodedCharacters(url)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.ENCODED_CHARACTERS,
                    severity = UrlDetectionSeverity.LOW,
                    description = "URL contains percent-encoded characters that may obfuscate the destination.",
                    matchedUrl = url,
                    matchedComponent = null,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Excessive URL length.
            if (url.length > MAX_URL_LENGTH) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.EXCESSIVE_LENGTH,
                    severity = UrlDetectionSeverity.LOW,
                    description = "URL is unusually long, which may be used to hide suspicious components.",
                    matchedUrl = url,
                    matchedComponent = null,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }

            // Suspicious domain keywords.
            if (analysis.host != null && hasSuspiciousDomainKeywords(analysis.host)) {
                signalIndex++
                signals.add(UrlDetectionSignal(
                    signalId = "$DETECTOR_ID-$signalIndex",
                    category = UrlDetectionCategory.SUSPICIOUS_DOMAIN,
                    severity = UrlDetectionSeverity.MEDIUM,
                    description = "Domain name contains suspicious keywords associated with phishing.",
                    matchedUrl = url,
                    matchedComponent = analysis.host,
                    detectorId = DETECTOR_ID,
                    detectorVersion = DETECTOR_VERSION
                ))
            }
        }

        return UrlDetectionResult(
            urls = analyses,
            signals = signals,
            detectorId = DETECTOR_ID,
            detectorVersion = DETECTOR_VERSION
        )
    }

    // -----------------------------------------------------------------------
    // Per-URL analysis
    // -----------------------------------------------------------------------

    private fun analyzeUrl(url: String): UrlAnalysis {
        var scheme: String? = null
        var host: String? = null
        var port: Int? = null
        var path: String? = null
        val indicators = mutableListOf<String>()

        var isIpBased = false
        var isShortener = false

        try {
            val uri = URI(url)
            scheme = uri.scheme
            host = uri.host
            port = uri.port
            path = uri.path

            host?.let { h ->
                isIpBased = IPV4_PATTERN.matcher(h).matches()
                isShortener = UrlShortenerList.isShortener(h)
                if (isIpBased) {
                    indicators.add("IP-address-based host: $h")
                }
                if (isShortener) {
                    indicators.add("URL shortener: $h")
                }
                if (SuspiciousTldList.isSuspicious(h)) {
                    indicators.add("Suspicious TLD")
                }
                if (hasSuspiciousDomainKeywords(h)) {
                    indicators.add("Suspicious domain keywords")
                }
            }
        } catch (_: Exception) {
            // Malformed URL: still record it with what we can parse.
            indicators.add("Malformed or unparseable URL")
        }

        return UrlAnalysis(
            originalUrl = url,
            scheme = scheme,
            host = host,
            port = port,
            path = path,
            isIpBased = isIpBased,
            isUrlShortener = isShortener,
            suspiciousIndicators = indicators
        )
    }

    // -----------------------------------------------------------------------
    // Detection heuristics
    // -----------------------------------------------------------------------

    private fun isHomographAttack(host: String?): Boolean {
        host ?: return false
        val lower = host.lowercase()
        val hasLatin = HAS_LATIN.matcher(lower).find()
        val hasCyrillic = HAS_CYRILLIC.matcher(lower).find()
        val hasGreek = HAS_GREEK.matcher(lower).find()
        val mixedScript = hasLatin && (hasCyrillic || hasGreek)
        // Also check for common look-alike substitutions mixed with ASCII.
        val lookAlikes = listOf("\u0430", "\u0435", "\u043e", "\u0440", "\u0441", "\u0445") // а е о р с х
        val hasLookAlike = lookAlikes.any { lower.contains(it) }
        return mixedScript || (hasLookAlike && hasLatin)
    }

    private fun isSuspiciousSubdomain(host: String?): Boolean {
        host ?: return false
        val parts = host.split(".")
        if (parts.size <= 2) return false
        // Subdomain count = total parts - 2 (domain + TLD), but handle co.uk etc.
        val subdomainCount = parts.size - 2
        return subdomainCount > MAX_SUBDOMAIN_DEPTH
    }

    private fun isMisleadingStructure(url: String): Boolean {
        // @ in userinfo: user:pass@host — the real host comes after @.
        if (url.contains("@")) return true
        // Brand name appearing after a path separator that mimics a domain.
        val lower = url.lowercase()
        val brands = BrandNameList.brands
        return brands.any { brand ->
            lower.contains("/$brand") || lower.contains("%2F$brand")
        }
    }

    private fun isUnusualPort(port: Int, scheme: String?): Boolean {
        val defaultPorts = when (scheme?.lowercase()) {
            "https" -> 443
            "http" -> 80
            "ftp" -> 21
            else -> -1
        }
        return defaultPorts == -1 || port != defaultPorts
    }

    private fun hasEncodedCharacters(url: String): Boolean {
        return url.contains("%")
    }

    private fun hasSuspiciousDomainKeywords(host: String?): Boolean {
        host ?: return false
        val lower = host.lowercase()
        return SUSPICIOUS_DOMAIN_KEYWORDS.any { lower.contains(it) }
    }
}
