package com.arm.threatassistant.apps

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager
import com.arm.threatassistant.domain.apps.AppAccess

data class AppReviewEntry(val id: String, val label: String, val access: AppAccess)

class AppReviewCollector(private val context: Context) {
    @Suppress("DEPRECATION")
    fun collect(): List<AppReviewEntry> {
        val pm = context.packageManager
        val manager = requireNotNull(context.getSystemService(AccessibilityManager::class.java))
        val services = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        return services.groupBy { it.resolveInfo.serviceInfo.packageName }.map { (id, enabled) ->
            val info = enabled.first().resolveInfo.serviceInfo.applicationInfo
            val capabilities = enabled.fold(0) { bits, service -> bits or service.capabilities }
            val sms = try {
                val pkg = pm.getPackageInfo(id, PackageManager.GET_PERMISSIONS)
                val requested = pkg.requestedPermissions.orEmpty()
                val flags = pkg.requestedPermissionsFlags
                val index = requested.indexOf(Manifest.permission.READ_SMS)
                when {
                    index < 0 -> false
                    flags == null || index >= flags.size -> null
                    else -> flags[index] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
                }
            } catch (_: PackageManager.NameNotFoundException) {
                null
            } catch (_: SecurityException) {
                null
            }
            AppReviewEntry(id, info.loadLabel(pm).toString(), AppAccess(
                capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0,
                capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0,
                sms,
                info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            ))
        }.sortedWith(compareByDescending<AppReviewEntry> { it.access.priority() }.thenBy { it.label })
    }
}
