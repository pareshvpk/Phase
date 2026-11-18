package com.arm.threatassistant.apps

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.arm.threatassistant.domain.apps.InstalledAppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Reads the installed-app facts the risk scorer needs. Everything is collected
 * on this device only: PackageManager plus three Settings.Secure strings, no
 * network, no root.
 *
 * Per-package work is isolated in a try/catch so a single misbehaving package
 * (or a permission denial) can never abort the whole scan.
 */
object InstalledAppsCollector {

    /** Notification listeners are stored under this Settings.Secure key. */
    private const val ENABLED_NOTIFICATION_LISTENERS = "enabled_notification_listeners"

    suspend fun collect(context: Context): List<InstalledAppInfo> =
        withContext(Dispatchers.Default) {
            val packageManager = context.packageManager
            val deviceAdminPackages = deviceAdminPackages(context)
            val accessibilityPackages = componentPackages(
                context,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            val notificationListenerPackages = componentPackages(
                context,
                ENABLED_NOTIFICATION_LISTENERS
            )

            installedPackages(packageManager).mapNotNull { packageInfo ->
                try {
                    val packageName = packageInfo.packageName ?: return@mapNotNull null
                    val applicationInfo = packageInfo.applicationInfo
                        ?: return@mapNotNull null

                    InstalledAppInfo(
                        packageName = packageName,
                        label = labelOf(packageManager, packageName, applicationInfo),
                        isSystemApp = applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                        installerPackage = installerPackage(packageManager, packageName),
                        requestedPermissions = packageInfo.requestedPermissions
                            ?.filterNotNull()
                            ?.toSet()
                            ?: emptySet(),
                        hasLauncherIcon = hasLauncherIcon(packageManager, packageName),
                        isDeviceAdminActive = packageName in deviceAdminPackages,
                        isAccessibilityServiceEnabled = packageName in accessibilityPackages,
                        isNotificationListenerEnabled = packageName in notificationListenerPackages,
                        firstInstallTimeMillis = packageInfo.firstInstallTime
                    )
                } catch (ignored: Throwable) {
                    null
                }
            }
        }

    @Suppress("DEPRECATION")
    private fun installedPackages(packageManager: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
        } else {
            packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

    private fun installerPackage(packageManager: PackageManager, packageName: String): String? =
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
        } catch (ignored: Throwable) {
            null
        }

    private fun labelOf(
        packageManager: PackageManager,
        packageName: String,
        applicationInfo: ApplicationInfo
    ): String = try {
        packageManager.getApplicationLabel(applicationInfo).toString()
    } catch (ignored: Throwable) {
        packageName
    }

    private fun hasLauncherIcon(packageManager: PackageManager, packageName: String): Boolean =
        try {
            packageManager.getLaunchIntentForPackage(packageName) != null
        } catch (ignored: Throwable) {
            false
        }

    private fun deviceAdminPackages(context: Context): Set<String> = try {
        val devicePolicyManager =
            context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        devicePolicyManager?.activeAdmins
            ?.mapNotNull { admin -> admin.packageName }
            ?.toSet()
            ?: emptySet()
    } catch (ignored: Throwable) {
        emptySet()
    }

    /**
     * Both accessibility services and notification listeners are stored as a
     * colon-separated list of `package/class` component names.
     */
    private fun componentPackages(context: Context, settingKey: String): Set<String> = try {
        val raw = Settings.Secure.getString(context.contentResolver, settingKey)
        if (raw.isNullOrBlank()) {
            emptySet()
        } else {
            raw.split(':')
                .map { entry -> entry.trim().substringBefore('/') }
                .filter { entry -> entry.isNotEmpty() }
                .toSet()
        }
    } catch (ignored: Throwable) {
        emptySet()
    }
}
