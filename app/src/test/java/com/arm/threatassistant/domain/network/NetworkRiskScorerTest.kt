package com.arm.threatassistant.domain.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkRiskScorerTest {

    private fun snapshot(
        onWifi: Boolean = false,
        wifiSecurity: WifiSecurity = WifiSecurity.WPA_WPA2,
        isMetered: Boolean = false,
        vpnActive: Boolean = false,
        privateDnsActive: Boolean = false,
        captivePortal: Boolean = false,
        validated: Boolean = true,
        dnsServers: List<String> = listOf("192.168.1.1"),
        gatewayIsPrivate: Boolean? = true,
        usbDebuggingOn: Boolean = false,
        developerOptionsOn: Boolean = false,
        unknownSourcesAllowedForSomeApp: Boolean = false
    ) = NetworkSnapshot(
        onWifi = onWifi,
        wifiSecurity = wifiSecurity,
        isMetered = isMetered,
        vpnActive = vpnActive,
        privateDnsActive = privateDnsActive,
        captivePortal = captivePortal,
        validated = validated,
        dnsServers = dnsServers,
        gatewayIsPrivate = gatewayIsPrivate,
        usbDebuggingOn = usbDebuggingOn,
        developerOptionsOn = developerOptionsOn,
        unknownSourcesAllowedForSomeApp = unknownSourcesAllowedForSomeApp
    )

    @Test
    fun cleanSnapshotIsOk() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.WPA3, validated = true)
        )

        assertEquals(NetworkRiskLevel.OK, result.first)
        assertTrue(result.second.isEmpty())
    }

    @Test
    fun openWifiIsRisky() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.NONE_OPEN)
        )

        assertEquals(NetworkRiskLevel.RISKY, result.first)
        assertTrue(NetworkFinding.OPEN_WIFI in result.second)
    }

    @Test
    fun openWifiWithoutPrivateDnsAlsoFlagsMissingPrivateDns() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.NONE_OPEN)
        )

        assertTrue(NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI in result.second)
    }

    @Test
    fun openWifiWithPrivateDnsHasNoPrivateDnsFinding() {
        val result = NetworkRiskScorer.score(
            snapshot(
                onWifi = true,
                wifiSecurity = WifiSecurity.NONE_OPEN,
                privateDnsActive = true
            )
        )

        assertTrue(NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI !in result.second)
    }

    @Test
    fun openWifiWithVpnHasNoPrivateDnsFinding() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.NONE_OPEN, vpnActive = true)
        )

        assertTrue(NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI !in result.second)
    }

    @Test
    fun secureWifiIsNotFlaggedAsOpen() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.WPA_WPA2)
        )

        assertTrue(NetworkFinding.OPEN_WIFI !in result.second)
        assertTrue(NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI !in result.second)
    }

    @Test
    fun wepWifiIsRisky() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.WEP)
        )

        assertEquals(NetworkRiskLevel.RISKY, result.first)
        assertTrue(NetworkFinding.WEP_WIFI in result.second)
        assertTrue(NetworkFinding.OPEN_WIFI !in result.second)
    }

    @Test
    fun unknownSecurityIsNotTreatedAsOpen() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, wifiSecurity = WifiSecurity.UNKNOWN)
        )

        assertTrue(NetworkFinding.OPEN_WIFI !in result.second)
        assertTrue(NetworkFinding.WEP_WIFI !in result.second)
    }

    @Test
    fun openWifiOffIsNeverAnOpenWifiFinding() {
        val result = NetworkRiskScorer.score(snapshot(onWifi = false))

        assertTrue(NetworkFinding.OPEN_WIFI !in result.second)
        assertTrue(NetworkFinding.WEP_WIFI !in result.second)
        assertTrue(NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI !in result.second)
    }

    @Test
    fun captivePortalIsCaution() {
        val result = NetworkRiskScorer.score(snapshot(captivePortal = true))

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.CAPTIVE_PORTAL in result.second)
    }

    @Test
    fun unvalidatedWifiIsCaution() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, validated = false, captivePortal = false)
        )

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.NOT_VALIDATED in result.second)
    }

    @Test
    fun captivePortalSuppressesNotValidated() {
        val result = NetworkRiskScorer.score(
            snapshot(onWifi = true, validated = false, captivePortal = true)
        )

        assertTrue(NetworkFinding.NOT_VALIDATED !in result.second)
        assertTrue(NetworkFinding.CAPTIVE_PORTAL in result.second)
    }

    @Test
    fun unvalidatedCellularDoesNotFlagNotValidated() {
        val result = NetworkRiskScorer.score(snapshot(onWifi = false, validated = false))

        assertTrue(NetworkFinding.NOT_VALIDATED !in result.second)
        assertEquals(NetworkRiskLevel.OK, result.first)
    }

    @Test
    fun unknownPublicDnsIsCaution() {
        val result = NetworkRiskScorer.score(snapshot(dnsServers = listOf("93.184.216.34")))

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.PUBLIC_DNS_HIJACK_RISK in result.second)
    }

    @Test
    fun wellKnownPublicDnsIsAccepted() {
        val known = listOf(
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "149.112.112.112",
            "208.67.222.222",
            "208.67.220.220"
        )
        known.forEach { server ->
            val result = NetworkRiskScorer.score(snapshot(dnsServers = listOf(server)))
            assertTrue(
                "unexpected finding for $server",
                NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second
            )
        }
    }

    @Test
    fun wellKnownPublicDnsIpv6IsAccepted() {
        val known = listOf("2001:4860:4860::8888", "2606:4700:4700::1111")
        known.forEach { server ->
            val result = NetworkRiskScorer.score(snapshot(dnsServers = listOf(server)))
            assertTrue(
                "unexpected finding for $server",
                NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second
            )
        }
    }

    @Test
    fun privateDnsServersAreAccepted() {
        val privateRanges = listOf(
            "10.1.2.3",
            "172.16.9.9",
            "172.31.1.1",
            "192.168.0.1",
            "100.64.0.7",
            "127.0.0.1",
            "fd12:3456::1",
            "fe80::1"
        )
        privateRanges.forEach { server ->
            val result = NetworkRiskScorer.score(snapshot(dnsServers = listOf(server)))
            assertTrue(
                "unexpected finding for $server",
                NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second
            )
        }
    }

    @Test
    fun boundaryAddressesOutsidePrivateRangesAreFlagged() {
        val publicish = listOf("9.255.255.255", "172.15.255.255", "172.32.0.1", "192.169.0.1", "100.128.0.1")
        publicish.forEach { server ->
            val result = NetworkRiskScorer.score(snapshot(dnsServers = listOf(server)))
            assertTrue(
                "expected a finding for $server",
                NetworkFinding.PUBLIC_DNS_HIJACK_RISK in result.second
            )
        }
    }

    @Test
    fun privateDnsActiveSuppressesPublicDnsFinding() {
        val result = NetworkRiskScorer.score(
            snapshot(dnsServers = listOf("93.184.216.34"), privateDnsActive = true)
        )

        assertTrue(NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second)
        assertEquals(NetworkRiskLevel.OK, result.first)
    }

    @Test
    fun vpnActiveSuppressesPublicDnsFinding() {
        val result = NetworkRiskScorer.score(
            snapshot(dnsServers = listOf("93.184.216.34"), vpnActive = true)
        )

        assertTrue(NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second)
    }

    @Test
    fun noDnsServersMeansNoPublicDnsFinding() {
        val result = NetworkRiskScorer.score(snapshot(dnsServers = emptyList()))

        assertTrue(NetworkFinding.PUBLIC_DNS_HIJACK_RISK !in result.second)
    }

    @Test
    fun usbDebuggingIsCaution() {
        val result = NetworkRiskScorer.score(snapshot(usbDebuggingOn = true))

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.USB_DEBUGGING_ON in result.second)
    }

    @Test
    fun developerOptionsAloneIsCaution() {
        val result = NetworkRiskScorer.score(snapshot(developerOptionsOn = true))

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.DEVELOPER_OPTIONS_ON in result.second)
        assertTrue(NetworkFinding.USB_DEBUGGING_ON !in result.second)
    }

    @Test
    fun developerOptionsWithUsbDebuggingIsOnlyUsbDebugging() {
        val result = NetworkRiskScorer.score(
            snapshot(usbDebuggingOn = true, developerOptionsOn = true)
        )

        assertTrue(NetworkFinding.USB_DEBUGGING_ON in result.second)
        assertTrue(NetworkFinding.DEVELOPER_OPTIONS_ON !in result.second)
    }

    @Test
    fun vpnActiveIsCaution() {
        val result = NetworkRiskScorer.score(snapshot(vpnActive = true))

        assertEquals(NetworkRiskLevel.CAUTION, result.first)
        assertTrue(NetworkFinding.VPN_ACTIVE_UNKNOWN in result.second)
    }

    @Test
    fun levelIsWorstOfAllFindings() {
        val result = NetworkRiskScorer.score(
            snapshot(
                onWifi = true,
                wifiSecurity = WifiSecurity.NONE_OPEN,
                usbDebuggingOn = true
            )
        )

        assertEquals(NetworkRiskLevel.RISKY, result.first)
        assertTrue(NetworkFinding.USB_DEBUGGING_ON in result.second)
    }

    @Test
    fun worstLevelWinsOverCautionFindings() {
        val result = NetworkRiskScorer.score(
            snapshot(
                onWifi = true,
                wifiSecurity = WifiSecurity.WEP,
                captivePortal = true,
                validated = false
            )
        )

        assertEquals(NetworkRiskLevel.RISKY, result.first)
        assertTrue(NetworkFinding.CAPTIVE_PORTAL in result.second)
        assertTrue(NetworkFinding.NOT_VALIDATED !in result.second)
    }

    @Test
    fun findingsFollowEnumOrder() {
        val result = NetworkRiskScorer.score(
            snapshot(
                onWifi = true,
                wifiSecurity = WifiSecurity.NONE_OPEN,
                captivePortal = true,
                validated = false,
                usbDebuggingOn = true,
                developerOptionsOn = true
            )
        )

        val expected = listOf(
            NetworkFinding.OPEN_WIFI,
            NetworkFinding.CAPTIVE_PORTAL,
            NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI,
            NetworkFinding.USB_DEBUGGING_ON
        )
        assertEquals(expected, result.second)
    }

    @Test
    fun unknownSourcesFlagDoesNotRaiseAnyFinding() {
        val result = NetworkRiskScorer.score(
            snapshot(unknownSourcesAllowedForSomeApp = true)
        )

        assertTrue(result.second.isEmpty())
        assertEquals(NetworkRiskLevel.OK, result.first)
    }

    @Test
    fun meteredNetworkIsNotAfindingByItself() {
        val result = NetworkRiskScorer.score(snapshot(onWifi = true, isMetered = true))

        assertTrue(result.second.isEmpty())
        assertEquals(NetworkRiskLevel.OK, result.first)
    }

    @Test
    fun gatewayPrivacyDoesNotRaiseAfindingByItself() {
        val result = NetworkRiskScorer.score(snapshot(gatewayIsPrivate = false))

        assertTrue(result.second.isEmpty())
        assertEquals(NetworkRiskLevel.OK, result.first)
    }

    @Test
    fun isPrivateAddressCoversEveryPrivateRange() {
        assertTrue(isPrivateAddress("10.0.0.1"))
        assertTrue(isPrivateAddress("172.20.1.1"))
        assertTrue(isPrivateAddress("192.168.1.100"))
        assertTrue(isPrivateAddress("100.64.10.10"))
        assertTrue(isPrivateAddress("127.0.0.53"))
        assertTrue(isPrivateAddress("fc00::1"))
        assertTrue(isPrivateAddress("fd00::1"))
        assertTrue(isPrivateAddress("fe80::abcd"))
    }

    @Test
    fun isPrivateAddressRejectsPublicAddresses() {
        assertTrue(!isPrivateAddress("8.8.8.8"))
        assertTrue(!isPrivateAddress("172.32.0.1"))
        assertTrue(!isPrivateAddress("2001:4860:4860::8888"))
        assertTrue(!isPrivateAddress("2606:4700:4700::1111"))
        assertTrue(!isPrivateAddress("not-an-address"))
    }

    @Test
    fun wellKnownDnsMatchingIgnoresCaseAndZone() {
        assertTrue(isWellKnownPublicDns("8.8.8.8"))
        assertTrue(isWellKnownPublicDns("2001:4860:4860:0:0:0:0:8888"))
        assertTrue(!isWellKnownPublicDns("8.8.8.9"))
        assertTrue(!isWellKnownPublicDns("192.168.1.1"))
    }
}
