package com.arm.threatassistant.network

import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.Selector
import java.nio.channels.SelectionKey
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Authenticated loopback SOCKS5 relay. All external sockets must be protected before connect. */
class LocalForwarder(
    private val username: String,
    private val password: String,
    private val protectTcp: (Socket) -> Boolean,
    private val protectUdp: (DatagramSocket) -> Boolean,
    private val monitor: FlowMonitor,
    private val onFailure: () -> Unit = {},
    private val onFlowError: (String) -> Unit = {}
) : Closeable {
    private val running = AtomicBoolean(true)
    private val slots = Semaphore(64)
    private val udpSlots = Semaphore(256)
    private val workers = Executors.newCachedThreadPool { r -> Thread(r, "ARM-relay").apply { isDaemon = true } }
    private val resources = ConcurrentHashMap.newKeySet<Closeable>()
    private val server = ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort

    init {
        resources.add(server)
        workers.execute {
            try {
                while (running.get()) {
                    val client = server.accept()
                    if (!slots.tryAcquire()) { client.close(); continue }
                    resources.add(client)
                    try { workers.execute {
                        try { handle(client) } catch (e: IOException) { onFlowError(e.javaClass.simpleName) }
                        finally { release(client); slots.release() }
                    } } catch (_: java.util.concurrent.RejectedExecutionException) { release(client); slots.release() }
                }
            } catch (_: IOException) { if (running.get()) onFailure() }
        }
    }

    private fun release(resource: Closeable) { resources.remove(resource); runCatching { resource.close() } }
    private fun reply(client: Socket, code: Int, port: Int = 0) {
        client.getOutputStream().write(byteArrayOf(5, code.toByte(), 0, 1, 127, 0, 0, 1,
            (port ushr 8).toByte(), port.toByte()))
    }
    private fun address(input: DataInputStream): InetAddress {
        val size = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> throw IOException("Only numeric destinations supported") }
        return InetAddress.getByAddress(ByteArray(size).also { input.readFully(it) })
    }
    private fun credential(input: DataInputStream): String = ByteArray(input.readUnsignedByte())
        .also { input.readFully(it) }.toString(Charsets.UTF_8)

    private fun handle(client: Socket) {
        client.soTimeout = 10_000
        client.tcpNoDelay = true
        val input = DataInputStream(client.getInputStream())
        if (input.readUnsignedByte() != 5) return
        val methods = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
        if (2.toByte() !in methods) { client.getOutputStream().write(byteArrayOf(5, -1)); return }
        client.getOutputStream().write(byteArrayOf(5, 2))
        if (input.readUnsignedByte() != 1) return
        val user = credential(input)
        val pass = credential(input)
        val valid = user == username && pass == password
        client.getOutputStream().write(byteArrayOf(1, if (valid) 0 else 1))
        if (!valid || input.readUnsignedByte() != 5) return
        val command = input.readUnsignedByte()
        if (input.readUnsignedByte() != 0) return
        val destination = address(input)
        val destinationPort = input.readUnsignedShort()
        when (command) {
            1 -> tcp(client, destination, destinationPort)
            3 -> udp(client)
            else -> reply(client, 7)
        }
    }

    private fun tcp(client: Socket, destination: InetAddress, port: Int) {
        // Avoid local relay recursion; local-only services do not traverse the underlying network.
        if (destination.isLoopbackAddress || destination.isAnyLocalAddress || destination.isMulticastAddress || port == 0) {
            reply(client, 2); return
        }
        val id = monitor.open("tcp", destination.hostAddress!!, port)
        val remote = Socket()
        resources.add(remote)
        try {
            // Android creates a TCP descriptor lazily. Bind before protect so
            // the VPN exemption applies to a real socket, before connect.
            remote.bind(InetSocketAddress(0))
            if (!protectTcp(remote)) throw IOException("Socket protection failed")
            try { remote.connect(InetSocketAddress(destination, port), 10_000) }
            catch (e: IOException) { onFlowError(e.javaClass.simpleName); reply(client, 5); return }
            remote.soTimeout = 300_000
            client.soTimeout = 300_000
            remote.tcpNoDelay = true
            reply(client, 0)
            val downstream = workers.submit {
                try { copy(remote, client, id, false) }
                catch (_: IOException) { release(client); release(remote) }
            }
            try { copy(client, remote, id, true); downstream.get() }
            catch (_: Exception) { downstream.cancel(true) }
        } finally { release(remote); monitor.finish(id) }
    }

    private fun copy(from: Socket, to: Socket, id: Long, outbound: Boolean) {
        val buffer = ByteArray(16_384)
        val input = from.getInputStream()
        val output = to.getOutputStream()
        while (running.get()) {
            val size = input.read(buffer)
            if (size < 0) { to.shutdownOutput(); return }
            output.write(buffer, 0, size)
            monitor.transfer(id, outbound, size)
        }
    }

    private data class UdpPeer(val channel: DatagramChannel, val id: Long, var last: Long)

    private fun udp(client: Socket) {
        val relay = DatagramChannel.open()
        val selector = Selector.open()
        val peers = LinkedHashMap<InetSocketAddress, UdpPeer>()
        resources.add(relay); resources.add(selector)
        val alive = AtomicBoolean(true)
        try {
            relay.bind(InetSocketAddress("127.0.0.1", 0))
            relay.configureBlocking(false)
            relay.register(selector, SelectionKey.OP_READ)
            reply(client, 0, (relay.localAddress as InetSocketAddress).port)
            client.soTimeout = 0
            val control = workers.submit {
                try { while (running.get() && client.getInputStream().read() >= 0) { /* control only */ } }
                catch (_: IOException) { }
                finally { alive.set(false); selector.wakeup() }
            }
            var source: InetSocketAddress? = null
            val buffer = ByteBuffer.allocate(65_535)
            try {
                while (running.get() && alive.get()) {
                    selector.select(1_000)
                    val now = System.nanoTime() / 1_000_000
                    val keys = selector.selectedKeys().iterator()
                    while (keys.hasNext()) {
                        val key = keys.next(); keys.remove()
                        if (!key.isValid) continue
                        buffer.clear()
                        val channel = key.channel() as DatagramChannel
                        val sender = channel.receive(buffer) as? InetSocketAddress ?: continue
                        buffer.flip()
                        if (channel === relay) {
                            if (!sender.address.isLoopbackAddress || (source != null && source != sender)) continue
                            if (buffer.remaining() < 10 || buffer.short.toInt() != 0 || buffer.get().toInt() != 0) continue
                            val size = when (buffer.get().toInt()) { 1 -> 4; 4 -> 16; else -> continue }
                            if (buffer.remaining() < size + 2) continue
                            val destination = InetAddress.getByAddress(ByteArray(size).also { buffer.get(it) })
                            val port = buffer.short.toInt() and 65535
                            if (destination.isAnyLocalAddress || destination.isLoopbackAddress || destination.isMulticastAddress || port == 0) continue
                            source = sender
                            val endpoint = InetSocketAddress(destination, port)
                            val peer = peers[endpoint] ?: run {
                                if (peers.size >= 16) {
                                    val oldest = peers.minBy { it.value.last }
                                    release(oldest.value.channel); udpSlots.release(); monitor.finish(oldest.value.id); peers.remove(oldest.key)
                                }
                                if (!udpSlots.tryAcquire()) throw IOException("UDP flow capacity reached")
                                val socket = DatagramChannel.open()
                                resources.add(socket)
                                try {
                                    if (!protectUdp(socket.socket())) throw IOException("Socket protection failed")
                                    socket.connect(endpoint)
                                    socket.configureBlocking(false)
                                    val entry = UdpPeer(socket, monitor.open("udp", destination.hostAddress!!, port), now)
                                    socket.register(selector, SelectionKey.OP_READ, entry)
                                    peers[endpoint] = entry
                                    entry
                                } catch (e: IOException) { release(socket); udpSlots.release(); throw e }
                            }
                            val count = buffer.remaining()
                            try {
                                if (peer.channel.write(buffer) == count) monitor.transfer(peer.id, true, count, true)
                            } catch (_: IOException) { release(peer.channel); udpSlots.release(); monitor.finish(peer.id); peers.remove(endpoint) }
                            peer.last = now
                        } else {
                            val peer = key.attachment() as UdpPeer
                            val destination = source ?: continue
                            val count = buffer.remaining()
                            val response = ByteBuffer.allocate(count + 22)
                            response.put(0.toByte()).put(0.toByte()).put(0.toByte())
                            response.put(if (sender.address.address.size == 4) 1.toByte() else 4.toByte())
                            response.put(sender.address.address).putShort(sender.port.toShort()).put(buffer).flip()
                            val size = response.remaining()
                            if (relay.send(response, destination) == size) monitor.transfer(peer.id, false, count, true)
                            peer.last = now
                        }
                    }
                    val expired = peers.filterValues { now - it.last >= 60_000 }.keys.toList()
                    expired.forEach { endpoint -> peers.remove(endpoint)?.let { release(it.channel); udpSlots.release(); monitor.finish(it.id) } }
                }
            } finally { release(client); control.cancel(true) }
        } finally {
            peers.values.forEach { release(it.channel); udpSlots.release(); monitor.finish(it.id) }
            release(relay); release(selector)
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        resources.toList().forEach(::release)
        workers.shutdownNow()
        workers.awaitTermination(3, TimeUnit.SECONDS)
    }
}
