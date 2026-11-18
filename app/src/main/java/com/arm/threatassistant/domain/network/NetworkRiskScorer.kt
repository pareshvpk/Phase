package com.arm.threatassistant.domain.network

/** How secure the access point reports the Wi-Fi to be. */
enum class WifiSecurity { NONE_OPEN, WEP, WPA_WPA2, WPA3, UNKNOWN }

/** Everything the on-phone network check reads about the network we are on. */
data class NetworkSnapshot(
    val onWifi: Boolean,
    val wifiSecurity: WifiSecurity,
    val isMetered: Boolean,
    val vpnActive: Boolean,
    val privateDnsActive: Boolean,
    val captivePortal: Boolean,
    val validated: Boolean,
    val dnsServers: List<String>,
    val gatewayIsPrivate: Boolean?,
    val usbDebuggingOn: Boolean,
    val developerOptionsOn: Boolean,
    val unknownSourcesAllowedForSomeApp: Boolean
)

enum class NetworkFinding {
    OPEN_WIFI,
    WEP_WIFI,
    CAPTIVE_PORTAL,
    NOT_VALIDATED,
    PUBLIC_DNS_HIJACK_RISK,
    NO_PRIVATE_DNS_ON_OPEN_WIFI,
    USB_DEBUGGING_ON,
    DEVELOPER_OPTIONS_ON,
    VPN_ACTIVE_UNKNOWN
}

enum class NetworkRiskLevel { OK, CAUTION, RISKY }

/**
 * Offline risk policy for the current network. Fixed rules over data the
 * collector already read from ConnectivityManager, WifiManager and Settings;
 * nothing here touches the network or leaves the phone.
 */
object NetworkRiskScorer {

    fun score(s: NetworkSnapshot): Pair<NetworkRiskLevel, List<NetworkFinding>> {
        val findings = mutableListOf<NetworkFinding>()

        val openWifi = s.onWifi && s.wifiSecurity == WifiSecurity.NONE_OPEN
        if (openWifi) {
            findings += NetworkFinding.OPEN_WIFI
        }
        if (s.onWifi && s.wifiSecurity == WifiSecurity.WEP) {
            findings += NetworkFinding.WEP_WIFI
        }
        if (s.captivePortal) {
            findings += NetworkFinding.CAPTIVE_PORTAL
        }
        if (s.onWifi && !s.validated && !s.captivePortal) {
            findings += NetworkFinding.NOT_VALIDATED
        }
        if (openWifi && !s.privateDnsActive && !s.vpnActive) {
            findings += NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI
        }
        if (!s.privateDnsActive && !s.vpnActive &&
            s.dnsServers.any { !isPrivateAddress(it) && !isWellKnownPublicDns(it) }
        ) {
            findings += NetworkFinding.PUBLIC_DNS_HIJACK_RISK
        }
        if (s.usbDebuggingOn) {
            findings += NetworkFinding.USB_DEBUGGING_ON
        }
        if (!s.usbDebuggingOn && s.developerOptionsOn) {
            findings += NetworkFinding.DEVELOPER_OPTIONS_ON
        }
        if (s.vpnActive) {
            findings += NetworkFinding.VPN_ACTIVE_UNKNOWN
        }

        val level = when {
            findings.any { it == NetworkFinding.OPEN_WIFI || it == NetworkFinding.WEP_WIFI } ->
                NetworkRiskLevel.RISKY

            findings.isNotEmpty() -> NetworkRiskLevel.CAUTION
            else -> NetworkRiskLevel.OK
        }
        return level to findings
    }
}

/** DNS servers a user is expected to pick themselves, IPv4 and IPv6. */
private val WELL_KNOWN_DNS: List<String> = listOf(
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "2001:4860:4860::8888",
    "2606:4700:4700::1111"
)

private val WELL_KNOWN_DNS_BYTES: List<ByteArray> =
    WELL_KNOWN_DNS.mapNotNull { address -> parseIpv4(address) ?: parseIpv6(address) }

/** True for RFC 1918, CGNAT, loopback and the IPv6 ULA / link-local ranges. */
internal fun isPrivateAddress(address: String): Boolean {
    val text = address.trim()
    parseIpv4(text)?.let { return isPrivateIpv4(it) }
    parseIpv6(text)?.let { return isPrivateIpv6(it) }
    // Unreadable entries are not private, so they also count as unknown DNS.
    return false
}

internal fun isWellKnownPublicDns(address: String): Boolean {
    val text = address.trim().lowercase().substringBefore('%')
    if (text in WELL_KNOWN_DNS) return true
    val bytes = parseIpv4(text) ?: parseIpv6(text) ?: return false
    return WELL_KNOWN_DNS_BYTES.any { known -> known.contentEquals(bytes) }
}

private fun isPrivateIpv4(bytes: ByteArray): Boolean {
    val b0 = bytes[0].toInt() and 0xFF
    val b1 = bytes[1].toInt() and 0xFF
    return b0 == 10 ||
        (b0 == 172 && b1 and 0xF0 == 16) ||
        (b0 == 192 && b1 == 168) ||
        (b0 == 100 && b1 and 0xC0 == 64) ||
        b0 == 127
}

private fun isPrivateIpv6(bytes: ByteArray): Boolean {
    val b0 = bytes[0].toInt() and 0xFF
    val b1 = bytes[1].toInt() and 0xFF
    return b0 and 0xFE == 0xFC || (b0 == 0xFE && b1 and 0xC0 == 0x80)
}

private fun parseIpv4(text: String): ByteArray? {
    val parts = text.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' }) return null
        val value = part.toInt()
        if (value > 255) return null
        out[index] = value.toByte()
    }
    return out
}

private fun parseIpv6(text: String): ByteArray? {
    var body = text.trim().lowercase()
    val zone = body.indexOf('%')
    if (zone >= 0) {
        body = body.substring(0, zone)
    }
    if (body.isEmpty()) return null

    // "::ffff:192.168.1.1" — fold the IPv4 tail into two hexadecimal groups.
    val lastColon = body.lastIndexOf(':')
    if (lastColon >= 0 && body.substring(lastColon + 1).contains('.')) {
        val tail = parseIpv4(body.substring(lastColon + 1)) ?: return null
        val hi = ((tail[0].toInt() and 0xFF) shl 8) or (tail[1].toInt() and 0xFF)
        val lo = ((tail[2].toInt() and 0xFF) shl 8) or (tail[3].toInt() and 0xFF)
        body = body.substring(0, lastColon + 1) +
            hi.toString(16) + ":" + lo.toString(16)
    }

    val groups: List<String> = if (body.contains("::")) {
        val split = body.split("::", limit = 2)
        if (split.size != 2 || split[1].contains("::")) return null
        val left = split[0].split(':').filter { it.isNotEmpty() }
        val right = split[1].split(':').filter { it.isNotEmpty() }
        if (left.size + right.size > 7) return null
        left + List(8 - left.size - right.size) { "0" } + right
    } else {
        body.split(':')
    }

    if (groups.size != 8) return null
    val out = ByteArray(16)
    groups.forEachIndexed { index, group ->
        if (group.isEmpty() || group.length > 4 || group.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            return null
        }
        val value = group.toInt(16)
        out[index * 2] = (value shr 8).toByte()
        out[index * 2 + 1] = value.toByte()
    }
    return out
}
