package com.arm.threatassistant.network

import org.junit.Assert.*
import org.junit.Assume.assumeNotNull
import org.junit.Test
import java.io.DataInputStream
import java.net.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class LocalForwarderTest {
    private fun host(): InetAddress {
        val address = NetworkInterface.getNetworkInterfaces().toList().filter { it.isUp }
            .flatMap { it.inetAddresses.toList() }.firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
        assumeNotNull(address)
        return address!!
    }
    private fun connect(relay: LocalForwarder, password: String = "secret"): Socket {
        val s = Socket("127.0.0.1", relay.port).apply { soTimeout = 3000 }
        val input = DataInputStream(s.getInputStream())
        val out = s.getOutputStream()
        out.write(byteArrayOf(5, 1, 2))
        assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
        out.write(byteArrayOf(1, 3) + "arm".toByteArray() + byteArrayOf(password.length.toByte()) + password.toByteArray())
        assertEquals(1, input.readUnsignedByte())
        assertEquals(if (password == "secret") 0 else 1, input.readUnsignedByte())
        return s
    }
    private fun request(s: Socket, command: Int, host: InetAddress, port: Int): ByteArray {
        s.getOutputStream().write(byteArrayOf(5, command.toByte(), 0, if (host.address.size == 4) 1 else 4) +
            host.address + byteArrayOf((port ushr 8).toByte(), port.toByte()))
        return ByteArray(10).also { DataInputStream(s.getInputStream()).readFully(it) }
    }
    @Test fun tcpForwardsLargeStreamAndHalfCloseWithoutModification() {
        val executor = Executors.newSingleThreadExecutor()
        val protected = AtomicInteger()
        val monitor = FlowMonitor(null)
        try {
            ServerSocket(0, 1, host()).use { echo ->
                val result = executor.submit { echo.accept().use { socket ->
                    socket.soTimeout = 5000
                    val bytes = socket.getInputStream().readBytes()
                    socket.getOutputStream().write(bytes)
                } }
                LocalForwarder("arm", "secret", {
                    assertTrue("Socket must have a descriptor before VPN protection", it.isBound)
                    assertFalse("Protection must precede connect", it.isConnected)
                    protected.incrementAndGet(); true
                }, { true }, monitor).use { relay ->
                    connect(relay).use { client ->
                        assertEquals(0, request(client, 1, echo.inetAddress, echo.localPort)[1].toInt())
                        val data = ByteArray(256_000) { (it % 251).toByte() }
                        client.getOutputStream().write(data); client.shutdownOutput()
                        assertArrayEquals(data, client.getInputStream().readBytes())
                    }
                }
                result.get(5, TimeUnit.SECONDS)
                assertEquals(1, protected.get())
                assertEquals(256_000L, monitor.sentBytes)
                assertEquals(256_000L, monitor.receivedBytes)
            }
        } finally { executor.shutdownNow() }
    }
    @Test fun udpForwardsPayloadAndReplyThroughProtectedSocket() {
        val executor = Executors.newSingleThreadExecutor()
        val protected = AtomicInteger()
        try {
            DatagramSocket(InetSocketAddress(host(), 0)).use { echo ->
                echo.soTimeout = 5000
                val result = executor.submit {
                    val packet = DatagramPacket(ByteArray(2048), 2048)
                    echo.receive(packet); echo.send(packet)
                }
                LocalForwarder("arm", "secret", { true }, { protected.incrementAndGet(); true }, FlowMonitor(null)).use { relay ->
                    connect(relay).use { control ->
                        val response = request(control, 3, InetAddress.getByName("0.0.0.0"), 0)
                        val port = ((response[8].toInt() and 255) shl 8) or (response[9].toInt() and 255)
                        DatagramSocket(InetSocketAddress("127.0.0.1", 0)).use { udp ->
                            udp.soTimeout = 3000
                            val body = "unchanged DNS-like data".toByteArray()
                            val frame = byteArrayOf(0, 0, 0, 1) + echo.localAddress.address +
                                byteArrayOf((echo.localPort ushr 8).toByte(), echo.localPort.toByte()) + body
                            udp.send(DatagramPacket(frame, frame.size, InetAddress.getByName("127.0.0.1"), port))
                            val reply = DatagramPacket(ByteArray(2048), 2048); udp.receive(reply)
                            assertArrayEquals(body, reply.data.copyOfRange(10, reply.length))
                        }
                    }
                }
                result.get(5, TimeUnit.SECONDS)
                assertEquals(1, protected.get())
            }
        } finally { executor.shutdownNow() }
    }
    @Test fun badCredentialsCannotRelay() {
        LocalForwarder("arm", "secret", { error("must not connect") }, { false }, FlowMonitor(null)).use { relay ->
            connect(relay, "wrong").use { assertEquals(-1, it.getInputStream().read()) }
        }
    }
    @Test fun protectionFailureClosesConnection() {
        LocalForwarder("arm", "secret", { false }, { false }, FlowMonitor(null)).use { relay ->
            connect(relay).use { client ->
                client.getOutputStream().write(byteArrayOf(5, 1, 0, 1, -64, 0, 2, 1, 0, 80))
                assertEquals(-1, client.getInputStream().read())
            }
        }
    }
    @Test fun noAuthAndLoopbackDestinationsAreRejected() {
        LocalForwarder("arm", "secret", { error("must not connect") }, { false }, FlowMonitor(null)).use { relay ->
            Socket("127.0.0.1", relay.port).use { client ->
                client.soTimeout = 3000
                client.getOutputStream().write(byteArrayOf(5, 1, 0))
                val input = DataInputStream(client.getInputStream())
                assertEquals(5, input.readUnsignedByte()); assertEquals(255, input.readUnsignedByte())
            }
            connect(relay).use { assertEquals(2, request(it, 1, InetAddress.getByName("127.0.0.1"), 80)[1].toInt()) }
        }
    }
    @Test fun stopClosesAuthenticatedControlConnections() {
        val relay = LocalForwarder("arm", "secret", { true }, { true }, FlowMonitor(null))
        connect(relay).use { client ->
            request(client, 3, InetAddress.getByName("0.0.0.0"), 0)
            relay.close(); relay.close()
            assertEquals(-1, client.getInputStream().read())
        }
    }
}
