package com.arm.threatassistant.domain.apps

/** Everything the scorer needs to know about one installed app. */
data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
    val installerPackage: String?,
    val requestedPermissions: Set<String>,
    val hasLauncherIcon: Boolean,
    val isDeviceAdminActive: Boolean,
    val isAccessibilityServiceEnabled: Boolean,
    val isNotificationListenerEnabled: Boolean,
    val firstInstallTimeMillis: Long
)

enum class AppRiskFinding {
    SIDELOADED,
    READS_SMS,
    ACCESSIBILITY_CONTROL,
    SCREEN_OVERLAY,
    DEVICE_ADMIN,
    HIDDEN_ICON,
    INSTALLS_APPS,
    READS_NOTIFICATIONS,
    SMS_PLUS_ACCESSIBILITY,
    REMOTE_CONTROL_COMBO
}

enum class AppRiskLevel { SAFE, REVIEW, DANGEROUS }

data class AppScanResult(
    val app: InstalledAppInfo,
    val findings: List<AppRiskFinding>,
    val level: AppRiskLevel
)

/**
 * Offline risk policy for installed apps. Nothing here touches the network or
 * leaves the phone: it is a fixed set of rules over data the collector already
 * read from PackageManager and Settings.Secure.
 */
object AppRiskScorer {

    private const val OUR_PACKAGE = "com.arm.threatassistant"

    /** Install sources a normal, non-sideloaded install comes from. */
    private val trustedInstallers: Set<String> = setOf(
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

    private val smsPermissions: Set<String> = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS"
    )

    fun score(app: InstalledAppInfo, nowMillis: Long): AppScanResult {
        // Our own package and pre-installed system apps can never be flagged.
        if (app.isSystemApp || app.packageName == OUR_PACKAGE) {
            return AppScanResult(app, emptyList(), AppRiskLevel.SAFE)
        }

        val findings = linkedSetOf<AppRiskFinding>()

        val installer = app.installerPackage
        if (installer == null || installer !in trustedInstallers) {
            findings += AppRiskFinding.SIDELOADED
        }
        if (app.requestedPermissions.any { it in smsPermissions }) {
            findings += AppRiskFinding.READS_SMS
        }
        if (app.isAccessibilityServiceEnabled) {
            findings += AppRiskFinding.ACCESSIBILITY_CONTROL
        }
        if ("android.permission.SYSTEM_ALERT_WINDOW" in app.requestedPermissions) {
            findings += AppRiskFinding.SCREEN_OVERLAY
        }
        if (app.isDeviceAdminActive) {
            findings += AppRiskFinding.DEVICE_ADMIN
        }
        if (!app.hasLauncherIcon) {
            findings += AppRiskFinding.HIDDEN_ICON
        }
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in app.requestedPermissions) {
            findings += AppRiskFinding.INSTALLS_APPS
        }
        if (app.isNotificationListenerEnabled) {
            findings += AppRiskFinding.READS_NOTIFICATIONS
        }

        val readsSms = AppRiskFinding.READS_SMS in findings
        val accessibility = AppRiskFinding.ACCESSIBILITY_CONTROL in findings
        val overlay = AppRiskFinding.SCREEN_OVERLAY in findings
        if (readsSms && accessibility) {
            findings += AppRiskFinding.SMS_PLUS_ACCESSIBILITY
        }
        if (accessibility && overlay) {
            findings += AppRiskFinding.REMOTE_CONTROL_COMBO
        }

        val ordered = AppRiskFinding.entries.filter { it in findings }

        val level = when {
            AppRiskFinding.SMS_PLUS_ACCESSIBILITY in ordered ||
                AppRiskFinding.REMOTE_CONTROL_COMBO in ordered ||
                AppRiskFinding.DEVICE_ADMIN in ordered -> AppRiskLevel.DANGEROUS

            AppRiskFinding.SIDELOADED in ordered && (
                readsSms ||
                    accessibility ||
                    AppRiskFinding.HIDDEN_ICON in ordered ||
                    AppRiskFinding.INSTALLS_APPS in ordered
                ) -> AppRiskLevel.DANGEROUS

            ordered.isNotEmpty() -> AppRiskLevel.REVIEW
            else -> AppRiskLevel.SAFE
        }

        return AppScanResult(app, ordered, level)
    }
}

/** Grouping for the Apps tab: the scariest first, then alphabetical by label. */
object AppScanSummary {

    private fun rank(level: AppRiskLevel): Int = when (level) {
        AppRiskLevel.DANGEROUS -> 0
        AppRiskLevel.REVIEW -> 1
        AppRiskLevel.SAFE -> 2
    }

    fun sort(results: List<AppScanResult>): List<AppScanResult> =
        results.sortedWith(
            compareBy<AppScanResult> { rank(it.level) }
                .thenBy { it.app.label }
        )
}
