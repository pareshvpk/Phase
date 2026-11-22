package com.arm.threatassistant.network

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.arm.threatassistant.MainActivity
import com.arm.threatassistant.R
import hev.htproxy.TProxyService
import java.io.File
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class NetworkVpnService : VpnService() {
    companion object {
        const val STOP = "com.arm.threatassistant.STOP_NETWORK"
        const val OPEN = "com.arm.threatassistant.OPEN_NETWORK"
        private const val CHANNEL = "network_monitor"
        private const val ALERTS = "network_findings"
        // Native library has process-global state; serialize across service recreation.
        private val worker = Executors.newSingleThreadScheduledExecutor()
    }
    private var tun: ParcelFileDescriptor? = null
    private var relay: LocalForwarder? = null
    private var monitor: FlowMonitor? = null
    private var timer: ScheduledFuture<*>? = null
    private var config: File? = null
    private var nativeStarted = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var requested = false
    @Volatile private var destroyed = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { requestStop(); return START_NOT_STICKY }
        if (requested) return START_NOT_STICKY
        if (Build.VERSION.SDK_INT < 29 || prepare(this) != null) { stopSelf(); return START_NOT_STICKY }
        requested = true
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.network_title), NotificationManager.IMPORTANCE_LOW))
        manager.createNotificationChannel(NotificationChannel(ALERTS, getString(R.string.network_alert_title), NotificationManager.IMPORTANCE_DEFAULT))
        val stop = PendingIntent.getService(this, 501, Intent(this, javaClass).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_shield_lock).setContentTitle(getString(R.string.network_title))
            .setContentText(getString(R.string.network_notification)).setContentIntent(openIntent())
            .setOngoing(true).addAction(0, getString(R.string.network_stop), stop).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(501, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(501, notification)
        NetworkState.update { NetworkSnapshot(starting = true) }
        worker.execute {
            if (destroyed || !requested) return@execute
            try { startTunnel() }
            catch (e: Exception) { android.util.Log.e("ARMNetwork", "Start failed: ${e.javaClass.simpleName}"); fail() }
            catch (e: LinkageError) { android.util.Log.e("ARMNetwork", "Native load failed: ${e.javaClass.simpleName}"); fail() }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel() {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val network = connectivity.activeNetwork ?: error("No underlying network")
        val capabilities = connectivity.getNetworkCapabilities(network) ?: error("No network capabilities")
        require(!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        val dns = connectivity.getLinkProperties(network)?.dnsServers.orEmpty()
        require(dns.isNotEmpty()) { "No network DNS available" }
        val model = assets.open("nids_model.json").bufferedReader().use { NetworkModel(it.readText()) }
        val analysis = FlowMonitor(model, onFinding = { finding ->
            NetworkState.update { it.copy(findings = (listOf(finding) + it.findings.filterNot { old -> old == finding }).take(10)) }
            notifyFinding()
        }, onSummary = { summary -> NetworkState.update { it.copy(estimate = summary.estimate) } })
        monitor = analysis
        val username = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val forwarder = LocalForwarder(username, password, { protect(it) }, { protect(it) }, analysis,
            onFailure = { worker.execute { if (!destroyed) fail() } },
            onFlowError = { android.util.Log.w("ARMNetwork", "Flow failed: $it") })
        relay = forwarder
        val file = File(cacheDir, "network-tunnel.yml")
        config = file
        file.writeText("""
            tunnel:
              name: arm
              mtu: 1500
              ipv4: 198.18.0.1
              ipv6: 'fd00:6172:6d::1'
            socks5:
              address: 127.0.0.1
              port: ${forwarder.port}
              udp: 'udp'
              username: '$username'
              password: '$password'
            misc:
              max-session-count: 64
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: error
              log-file: /dev/null
        """.trimIndent())
        val builder = Builder().setSession(getString(R.string.network_title)).setMtu(1500)
            .addAddress("198.18.0.1", 32).addAddress("fd00:6172:6d::1", 128)
            .addRoute("0.0.0.0", 0).addRoute("::", 0)
            .setConfigureIntent(openIntent()).setBlocking(false)
        // Use the current network's resolver; never silently send DNS to a new provider.
        dns.forEach { builder.addDnsServer(it) }
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED).not())
        val descriptor = builder.establish() ?: error("VPN permission revoked")
        tun = descriptor
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(lost: Network) {
                if (lost == network) worker.execute { if (!destroyed && requested) fail() }
            }
        }
        connectivity.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
        networkCallback = callback
        check(TProxyService.TProxyStartService(file.absolutePath, descriptor.fd))
        nativeStarted = true
        android.util.Log.i("ARMNetwork", "Tunnel started")
        timer = worker.scheduleAtFixedRate({
            if (!destroyed && requested) {
                try {
                    if (!TProxyService.TProxyIsRunning()) { fail(); return@scheduleAtFixedRate }
                    val stats = TProxyService.TProxyGetStats()
                    NetworkState.update { it.copy(running = true, starting = false,
                        sent = stats[1], received = stats[3], packets = stats[0] + stats[2],
                        active = analysis.activeCount(), completed = analysis.completed) }
                } catch (_: Exception) { fail() }
            }
        }, 500, 1_000, TimeUnit.MILLISECONDS)
    }

    private fun openIntent() = PendingIntent.getActivity(this, 501,
        Intent(this, MainActivity::class.java).setAction(OPEN).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun notifyFinding() {
        val manager = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, ALERTS).setSmallIcon(R.drawable.ic_warning_sms)
            .setContentTitle(getString(R.string.network_alert_title)).setContentText(getString(R.string.network_alert_body))
            .setContentIntent(openIntent()).setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build()
        try { manager.notify(502, notification) } catch (_: SecurityException) { /* Still visible inside ARM. */ }
    }

    private fun fail() {
        requested = false
        cleanup()
        NetworkState.update { it.copy(running = false, starting = false, failed = true) }
        stopSelf()
    }

    private fun cleanup() {
        timer?.cancel(false); timer = null
        networkCallback?.let { callback ->
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
        }
        networkCallback = null
        if (nativeStarted) { TProxyService.TProxyStopService(); nativeStarted = false }
        tun?.close(); tun = null
        relay?.close(); relay = null
        monitor?.close(); monitor = null
        config?.delete(); config = null
        NetworkState.update { it.copy(running = false, starting = false, active = 0) }
        android.util.Log.i("ARMNetwork", "Tunnel stopped")
    }

    private fun requestStop() {
        requested = false
        // Android holds a binding to an established VPN. Release the TUN before
        // stopSelf; waiting for onDestroy alone can leave the VPN bound forever.
        worker.execute { cleanup(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }
    }
    override fun onRevoke() { requestStop() }
    override fun onDestroy() {
        destroyed = true; requested = false
        worker.execute { cleanup() }
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
