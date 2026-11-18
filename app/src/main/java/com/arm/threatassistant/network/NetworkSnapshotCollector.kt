package com.arm.threatassistant.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import com.arm.threatassistant.domain.network.NetworkSnapshot
import com.arm.threatassistant.domain.network.WifiSecurity
import com.arm.threatassistant.domain.network.isPrivateAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Reads the facts the network check scores. Everything comes from
 * ConnectivityManager, WifiManager and Settings on this phone: no root, no
 * requests, nothing leaves the device.
 *
 * Every section has its own guard, so a missing service, a denied permission or
 * an unexpected platform value can never crash the app — the snapshot simply
 * falls back to UNKNOWN/false.
 */
object NetworkSnapshotCollector {

    suspend fun collect(context: Context): NetworkSnapshot = withContext(Dispatchers.Default) {
        val appContext = context.applicationContext
        val connectivity = appContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager
        val activeNetwork = runCatching { connectivity?.activeNetwork }.getOrNull()
        val capabilities = runCatching {
            activeNetwork?.let { network -> connectivity?.getNetworkCapabilities(network) }
        }.getOrNull()
        val linkProperties = runCatching {
            activeNetwork?.let { network -> connectivity?.getLinkProperties(network) }
        }.getOrNull()

        val dnsServers = runCatching {
            linkProperties?.dnsServers
                ?.mapNotNull { server -> server.hostAddress }
                ?: emptyList<String>()
        }.getOrDefault(emptyList())

        val gatewayIsPrivate = runCatching {
            val gateway = linkProperties?.routes
                ?.firstOrNull { route ->
                    route.isDefaultRoute &&
                        (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || route.hasGateway())
                }
                ?.gateway
                ?: return@runCatching null
            gateway.hostAddress?.let { address -> isPrivateAddress(address) }
        }.getOrNull()

        NetworkSnapshot(
            onWifi = hasTransport(capabilities, NetworkCapabilities.TRANSPORT_WIFI),
            wifiSecurity = wifiSecurity(appContext),
            isMetered = capabilities != null &&
                !hasCapability(capabilities, NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            vpnActive = hasTransport(capabilities, NetworkCapabilities.TRANSPORT_VPN),
            privateDnsActive = runCatching {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                    linkProperties?.isPrivateDnsActive == true
            }.getOrDefault(false),
            captivePortal = hasCapability(
                capabilities,
                NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL
            ),
            validated = hasCapability(capabilities, NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            dnsServers = dnsServers,
            gatewayIsPrivate = gatewayIsPrivate,
            usbDebuggingOn = globalSetting(
                appContext,
                Settings.Global.ADB_ENABLED
            ),
            developerOptionsOn = globalSetting(
                appContext,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
            ),
            unknownSourcesAllowedForSomeApp = false
        )
    }

    private fun hasTransport(caps: NetworkCapabilities?, transport: Int): Boolean =
        runCatching { caps?.hasTransport(transport) == true }.getOrDefault(false)

    private fun hasCapability(caps: NetworkCapabilities?, capability: Int): Boolean =
        runCatching { caps?.hasCapability(capability) == true }.getOrDefault(false)

    private fun globalSetting(context: Context, key: String): Boolean = try {
        Settings.Global.getInt(context.contentResolver, key, 0) != 0
    } catch (ignored: Throwable) {
        false
    }

    /**
     * API 31+ reports the exact security type through WifiInfo. Older platforms
     * (and any failure) fall back to UNKNOWN rather than guessing.
     */
    @Suppress("DEPRECATION")
    private fun wifiSecurity(context: Context): WifiSecurity {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return WifiSecurity.UNKNOWN
        }
        return try {
            val wifiManager =
                context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                    ?: return WifiSecurity.UNKNOWN
            val connectionInfo = wifiManager.connectionInfo ?: return WifiSecurity.UNKNOWN
            when (connectionInfo.currentSecurityType) {
                WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurity.NONE_OPEN
                // Opportunistic Wireless Encryption encrypts, so it is not open.
                WifiInfo.SECURITY_TYPE_OWE -> WifiSecurity.WPA3
                WifiInfo.SECURITY_TYPE_WEP -> WifiSecurity.WEP
                WifiInfo.SECURITY_TYPE_PSK,
                WifiInfo.SECURITY_TYPE_EAP -> WifiSecurity.WPA_WPA2

                WifiInfo.SECURITY_TYPE_SAE,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> WifiSecurity.WPA3

                else -> WifiSecurity.UNKNOWN
            }
        } catch (ignored: Throwable) {
            WifiSecurity.UNKNOWN
        }
    }
}
