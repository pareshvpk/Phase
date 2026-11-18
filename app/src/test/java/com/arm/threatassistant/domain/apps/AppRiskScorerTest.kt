package com.arm.threatassistant.domain.apps

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRiskScorerTest {

    private val now = 1_700_000_000_000L

    private fun app(
        packageName: String = "com.example.app",
        label: String = "Example",
        isSystemApp: Boolean = false,
        installerPackage: String? = "com.android.vending",
        requestedPermissions: Set<String> = emptySet(),
        hasLauncherIcon: Boolean = true,
        isDeviceAdminActive: Boolean = false,
        isAccessibilityServiceEnabled: Boolean = false,
        isNotificationListenerEnabled: Boolean = false,
        firstInstallTimeMillis: Long = 1_600_000_000_000L
    ) = InstalledAppInfo(
        packageName = packageName,
        label = label,
        isSystemApp = isSystemApp,
        installerPackage = installerPackage,
        requestedPermissions = requestedPermissions,
        hasLauncherIcon = hasLauncherIcon,
        isDeviceAdminActive = isDeviceAdminActive,
        isAccessibilityServiceEnabled = isAccessibilityServiceEnabled,
        isNotificationListenerEnabled = isNotificationListenerEnabled,
        firstInstallTimeMillis = firstInstallTimeMillis
    )

    @Test
    fun bankingTrojanProfileIsDangerous() {
        // Sideloaded + SMS + accessibility + overlay is the classic dropper.
        val trojan = app(
            packageName = "com.fake.bank.update",
            label = "Bank Update",
            installerPackage = null,
            requestedPermissions = setOf(
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            isAccessibilityServiceEnabled = true
        )

        val result = AppRiskScorer.score(trojan, now)

        assertEquals(AppRiskLevel.DANGEROUS, result.level)
        assertTrue(AppRiskFinding.SIDELOADED in result.findings)
        assertTrue(AppRiskFinding.READS_SMS in result.findings)
        assertTrue(AppRiskFinding.ACCESSIBILITY_CONTROL in result.findings)
        assertTrue(AppRiskFinding.SCREEN_OVERLAY in result.findings)
        assertTrue(AppRiskFinding.SMS_PLUS_ACCESSIBILITY in result.findings)
        assertTrue(AppRiskFinding.REMOTE_CONTROL_COMBO in result.findings)
    }

    @Test
    fun playStoreAppWithSmsIsReview() {
        val whatsappLike = app(
            packageName = "com.example.chat",
            label = "Chat",
            installerPackage = "com.android.vending",
            requestedPermissions = setOf("android.permission.READ_SMS")
        )

        val result = AppRiskScorer.score(whatsappLike, now)

        assertEquals(AppRiskLevel.REVIEW, result.level)
        assertEquals(listOf(AppRiskFinding.READS_SMS), result.findings)
    }

    @Test
    fun systemAppWithEverythingIsSafe() {
        val systemApp = app(
            packageName = "com.android.systemui",
            label = "System UI",
            isSystemApp = true,
            installerPackage = null,
            requestedPermissions = setOf(
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ),
            hasLauncherIcon = false,
            isDeviceAdminActive = true,
            isAccessibilityServiceEnabled = true,
            isNotificationListenerEnabled = true
        )

        val result = AppRiskScorer.score(systemApp, now)

        assertEquals(AppRiskLevel.SAFE, result.level)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun ourOwnPackageIsAlwaysSafe() {
        val ours = app(
            packageName = "com.arm.threatassistant",
            label = "ARM",
            installerPackage = null,
            requestedPermissions = setOf(
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            hasLauncherIcon = false,
            isDeviceAdminActive = true,
            isAccessibilityServiceEnabled = true,
            isNotificationListenerEnabled = true
        )

        val result = AppRiskScorer.score(ours, now)

        assertEquals(AppRiskLevel.SAFE, result.level)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun hiddenSideloadedAppIsDangerous() {
        val hidden = app(
            packageName = "com.hidden.loader",
            label = "Loader",
            installerPackage = "com.android.packageinstaller",
            hasLauncherIcon = false
        )

        val result = AppRiskScorer.score(hidden, now)

        assertEquals(AppRiskLevel.DANGEROUS, result.level)
        assertTrue(AppRiskFinding.SIDELOADED in result.findings)
        assertTrue(AppRiskFinding.HIDDEN_ICON in result.findings)
    }

    @Test
    fun packageInstallerIsTreatedAsSideload() {
        val viaPackageInstaller = app(
            installerPackage = "com.google.android.packageinstaller"
        )

        val result = AppRiskScorer.score(viaPackageInstaller, now)

        assertTrue(AppRiskFinding.SIDELOADED in result.findings)
        assertEquals(AppRiskLevel.REVIEW, result.level)
    }

    @Test
    fun knownTrustedInstallersAreNotSideloaded() {
        val stores = listOf(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.bbk.appstore",
            "com.vivo.appstore",
            "com.xiaomi.market",
            "com.heytap.market",
            "com.oppo.market",
            "com.huawei.appmarket",
            "com.amazon.venezia"
        )

        stores.forEach { store ->
            val result = AppRiskScorer.score(app(installerPackage = store), now)
            assertTrue("$store must not be flagged", AppRiskFinding.SIDELOADED !in result.findings)
            assertEquals("$store", AppRiskLevel.SAFE, result.level)
        }
    }

    @Test
    fun deviceAdminFromPlayStoreIsDangerous() {
        val admin = app(
            installerPackage = "com.android.vending",
            isDeviceAdminActive = true
        )

        val result = AppRiskScorer.score(admin, now)

        assertEquals(AppRiskLevel.DANGEROUS, result.level)
        assertEquals(listOf(AppRiskFinding.DEVICE_ADMIN), result.findings)
    }

    @Test
    fun sideloadedWithOverlayOnlyIsReview() {
        val overlayOnly = app(
            installerPackage = null,
            requestedPermissions = setOf("android.permission.SYSTEM_ALERT_WINDOW")
        )

        val result = AppRiskScorer.score(overlayOnly, now)

        assertEquals(AppRiskLevel.REVIEW, result.level)
        assertEquals(
            listOf(AppRiskFinding.SIDELOADED, AppRiskFinding.SCREEN_OVERLAY),
            result.findings
        )
    }

    @Test
    fun receiveSmsCountsAsReadsSms() {
        val receiver = app(requestedPermissions = setOf("android.permission.RECEIVE_SMS"))

        val result = AppRiskScorer.score(receiver, now)

        assertEquals(listOf(AppRiskFinding.READS_SMS), result.findings)
        assertEquals(AppRiskLevel.REVIEW, result.level)
    }

    @Test
    fun smsAndAccessibilityAloneIsDangerousWithoutSideload() {
        val combo = app(
            installerPackage = "com.android.vending",
            requestedPermissions = setOf("android.permission.READ_SMS"),
            isAccessibilityServiceEnabled = true
        )

        val result = AppRiskScorer.score(combo, now)

        assertEquals(AppRiskLevel.DANGEROUS, result.level)
        assertTrue(AppRiskFinding.SMS_PLUS_ACCESSIBILITY in result.findings)
        assertTrue(AppRiskFinding.SIDELOADED !in result.findings)
    }

    @Test
    fun notificationListenerAloneIsReview() {
        val listener = app(isNotificationListenerEnabled = true)

        val result = AppRiskScorer.score(listener, now)

        assertEquals(AppRiskLevel.REVIEW, result.level)
        assertEquals(listOf(AppRiskFinding.READS_NOTIFICATIONS), result.findings)
    }

    @Test
    fun installPackagesPermissionAloneIsReview() {
        val installer = app(
            installerPackage = "com.android.vending",
            requestedPermissions = setOf("android.permission.REQUEST_INSTALL_PACKAGES")
        )

        val result = AppRiskScorer.score(installer, now)

        assertEquals(AppRiskLevel.REVIEW, result.level)
        assertEquals(listOf(AppRiskFinding.INSTALLS_APPS), result.findings)
    }

    @Test
    fun plainInstalledAppIsSafeWithNoFindings() {
        val plain = app()

        val result = AppRiskScorer.score(plain, now)

        assertEquals(AppRiskLevel.SAFE, result.level)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun findingsAreReportedInEnumOrder() {
        val everything = app(
            installerPackage = null,
            requestedPermissions = setOf(
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ),
            hasLauncherIcon = false,
            isDeviceAdminActive = true,
            isAccessibilityServiceEnabled = true,
            isNotificationListenerEnabled = true
        )

        val result = AppRiskScorer.score(everything, now)

        assertEquals(AppRiskFinding.entries.toList(), result.findings)
    }

    @Test
    fun sortPutsDangerousFirstThenReviewThenSafeAndLabelsWithinLevel() {
        val dangerous = AppScanResult(
            app = app(packageName = "com.a", label = "Zeta Malware"),
            findings = listOf(AppRiskFinding.DEVICE_ADMIN),
            level = AppRiskLevel.DANGEROUS
        )
        val dangerousEarlier = AppScanResult(
            app = app(packageName = "com.b", label = "Alpha Dropper"),
            findings = listOf(AppRiskFinding.SIDELOADED, AppRiskFinding.HIDDEN_ICON),
            level = AppRiskLevel.DANGEROUS
        )
        val review = AppScanResult(
            app = app(packageName = "com.c", label = "Beta Chat"),
            findings = listOf(AppRiskFinding.READS_SMS),
            level = AppRiskLevel.REVIEW
        )
        val reviewLater = AppScanResult(
            app = app(packageName = "com.d", label = "Omega Tool"),
            findings = listOf(AppRiskFinding.READS_NOTIFICATIONS),
            level = AppRiskLevel.REVIEW
        )
        val safe = AppScanResult(
            app = app(packageName = "com.e", label = "Aardvark Clock"),
            findings = emptyList(),
            level = AppRiskLevel.SAFE
        )
        val safeLater = AppScanResult(
            app = app(packageName = "com.f", label = "Zinc Notes"),
            findings = emptyList(),
            level = AppRiskLevel.SAFE
        )

        val sorted = AppScanSummary.sort(
            listOf(safeLater, reviewLater, dangerous, safe, review, dangerousEarlier)
        )

        assertEquals(
            listOf(
                "Alpha Dropper",
                "Zeta Malware",
                "Beta Chat",
                "Omega Tool",
                "Aardvark Clock",
                "Zinc Notes"
            ),
            sorted.map { it.app.label }
        )
    }

    @Test
    fun sortIsStableForEqualLabelsAndKeepsAllResults() {
        val first = AppScanResult(
            app = app(packageName = "com.one", label = "Same"),
            findings = listOf(AppRiskFinding.READS_SMS),
            level = AppRiskLevel.REVIEW
        )
        val second = AppScanResult(
            app = app(packageName = "com.two", label = "Same"),
            findings = listOf(AppRiskFinding.DEVICE_ADMIN),
            level = AppRiskLevel.DANGEROUS
        )

        val sorted = AppScanSummary.sort(listOf(first, second))

        assertEquals(2, sorted.size)
        assertEquals(second, sorted[0])
        assertEquals(first, sorted[1])
    }

    @Test
    fun emptyInputSortsToEmptyList() {
        assertTrue(AppScanSummary.sort(emptyList()).isEmpty())
    }
}
