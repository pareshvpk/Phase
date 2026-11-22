package com.arm.threatassistant.network

import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.net.*

/** Requires prior system VPN consent and an explicitly supplied controlled fixture host. */
@RunWith(AndroidJUnit4::class)
class NetworkVpnDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun waitFor(condition: () -> Boolean) {
        val until = System.nanoTime() + 15_000_000_000L
        while (!condition() && System.nanoTime() < until) Thread.sleep(100)
        assertTrue("Condition did not become true: ${NetworkState.state.value}", condition())
    }
    @Test fun forwardsTcpUdpDetectsFanoutAndRestarts() {
        val host = InstrumentationRegistry.getArguments().getString("fixtureHost")
        assumeTrue("Supply a controlled LAN echo fixture", !host.isNullOrBlank())
        assertNull("Grant ARM VPN consent before this test", VpnService.prepare(context))
        val address = InetAddress.getByName(host)
        val intent = Intent(context, NetworkVpnService::class.java)
        fun start() {
            ContextCompat.startForegroundService(context, intent)
            waitFor { NetworkState.state.value.running }
        }
        fun tcp() {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, 39080), 5000)
                socket.soTimeout = 5000
                val data = ByteArray(64_000) { (it % 251).toByte() }
                socket.getOutputStream().write(data)
                val reply = ByteArray(data.size)
                DataInputStream(socket.getInputStream()).readFully(reply)
                assertArrayEquals(data, reply)
                socket.shutdownOutput()
                assertEquals(-1, socket.getInputStream().read())
            }
        }
        try {
            tcp() // Establish that the controlled fixture is reachable before VPN capture.
            start()
            tcp()
            DatagramSocket().use { socket ->
                socket.soTimeout = 5000
                repeat(12) { index ->
                    val data = "ARM-controlled-fixture-$index".toByteArray()
                    socket.send(DatagramPacket(data, data.size, address, 39090 + index))
                    val response = DatagramPacket(ByteArray(256), 256)
                    socket.receive(response)
                    assertArrayEquals(data, response.data.copyOfRange(0, response.length))
                }
            }
            waitFor { NetworkFinding.PORT_FANOUT in NetworkState.state.value.findings }
            waitFor { NetworkState.state.value.packets > 0 && NetworkState.state.value.estimate != null }
            context.startService(Intent(intent).setAction(NetworkVpnService.STOP))
            waitFor { !NetworkState.state.value.running }
            tcp() // Ordinary connectivity survives stopping the VPN.
            start()
            tcp()
        } finally {
            context.startService(Intent(intent).setAction(NetworkVpnService.STOP))
            waitFor { !NetworkState.state.value.running && !NetworkState.state.value.starting }
        }
    }
}
