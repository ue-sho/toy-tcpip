package com.toy.tcpip.arp

import com.toy.tcpip.ethernet.EthernetFrame
import com.toy.tcpip.ethernet.EthernetLayer
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.bytesToMacAddress
import com.toy.tcpip.util.ipv4ToBytes
import java.nio.ByteBuffer
import java.util.Arrays
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.function.BiConsumer

/**
 * Handles ARP protocol operations
 */
class ArpLayer(
    private val ethernetLayer: EthernetLayer,
    private val ipAddress: ByteArray
) {
    // Map of IP address to MAC address
    private data class ArpEntry(
        val macAddress: ByteArray,
        var timestamp: Long
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as ArpEntry
            return macAddress.contentEquals(other.macAddress)
        }

        override fun hashCode(): Int {
            return macAddress.contentHashCode()
        }
    }

    // ARP table: IP address (string) -> ArpEntry
    private val arpTable = ConcurrentHashMap<String, ArpEntry>()

    // Pending ARP requests: IP address (string) -> List of buffers waiting for resolution
    private val pendingRequests = ConcurrentHashMap<String, MutableList<ByteBuffer>>()

    // List of pending resolution callbacks
    private val pendingCallbacks = ConcurrentHashMap<String, MutableList<BiConsumer<ByteArray, ByteArray>>>()

    // Executor for scheduling tasks
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()

    // Flag to indicate if the layer is running
    @Volatile
    private var running = false

    // ARP timeout in milliseconds (20 minutes)
    private val arpTimeout = 1200000L

    // Maximum ARP request attempts
    private val maxArpRetries = 3

    /**
     * Initialize the ARP layer
     */
    init {
        // Add our own IP -> MAC mapping
        updateArpTable(ipAddress, ethernetLayer.device.macAddress)
    }

    /**
     * Start the ARP layer
     */
    fun start() {
        if (running) {
            return
        }

        running = true

        // Register to receive ARP packets from Ethernet layer
        ethernetLayer.registerProtocolHandler(Constants.ETH_TYPE_ARP) { frame ->
            handleArpFrame(frame)
        }

        // Schedule periodic cleanup of ARP table
        scheduler.scheduleAtFixedRate(this::cleanArpTable, 60, 60, TimeUnit.SECONDS)

        println("ARP layer started with IP ${bytesToIpv4(ipAddress)}")
    }

    /**
     * Stop the ARP layer
     */
    fun stop() {
        running = false

        // Unregister from Ethernet layer
        ethernetLayer.unregisterProtocolHandler(Constants.ETH_TYPE_ARP)

        // Shutdown scheduler
        scheduler.shutdown()

        println("ARP layer stopped")
    }

    /**
     * Handle an ARP frame
     */
    private fun handleArpFrame(frame: EthernetFrame) {
        val arpPacket = ArpPacket.parse(frame.payload) ?: return

        println("Received ARP packet: $arpPacket")

        // Update ARP table with sender's information
        updateArpTable(arpPacket.senderProtocolAddress, arpPacket.senderHardwareAddress)

        // Check if this is a request for our IP
        if (arpPacket.operation == Constants.ARP_OP_REQUEST &&
            Arrays.equals(arpPacket.targetProtocolAddress, ipAddress)) {

            // Send ARP reply
            val reply = ArpPacket.createReply(
                senderMac = ethernetLayer.device.macAddress,
                senderIp = ipAddress,
                targetMac = arpPacket.senderHardwareAddress,
                targetIp = arpPacket.senderProtocolAddress
            )

            val replyBuffer = reply.toByteBuffer()
            ethernetLayer.send(
                arpPacket.senderHardwareAddress,
                Constants.ETH_TYPE_ARP,
                replyBuffer
            )

            println("Sent ARP reply: $reply")
        }
        // Check if this is a reply to one of our requests
        else if (arpPacket.operation == Constants.ARP_OP_REPLY) {
            val ipStr = bytesToIpv4(arpPacket.senderProtocolAddress)

            // Process any pending packets for this IP
            processPendingPackets(ipStr, arpPacket.senderHardwareAddress)

            // Notify any pending callbacks
            processPendingCallbacks(ipStr, arpPacket.senderProtocolAddress, arpPacket.senderHardwareAddress)
        }
    }

    /**
     * Send an ARP request for the specified IP address
     */
    fun sendArpRequest(targetIp: ByteArray) {
        val request = ArpPacket.createRequest(
            senderMac = ethernetLayer.device.macAddress,
            senderIp = ipAddress,
            targetIp = targetIp
        )

        val requestBuffer = request.toByteBuffer()
        ethernetLayer.send(
            EthernetFrame.MAC_BROADCAST,
            Constants.ETH_TYPE_ARP,
            requestBuffer
        )

        println("Sent ARP request: $request")
    }

    /**
     * Resolve an IP address to a MAC address
     *
     * @param ipAddress The IP address to resolve
     * @param packet The packet to send once the address is resolved (or null if not sending a packet)
     * @param callback The callback to invoke with the resolved MAC address (or null if not using callback)
     * @return The MAC address if already in cache, or null if resolution is pending
     */
    fun resolve(ipAddress: ByteArray, packet: ByteBuffer? = null,
                callback: BiConsumer<ByteArray, ByteArray>? = null): ByteArray? {

        val ipStr = bytesToIpv4(ipAddress)

        // Check if we already have the MAC address in our table
        val entry = arpTable[ipStr]
        if (entry != null) {
            // Update timestamp
            entry.timestamp = System.currentTimeMillis()

            // If we have a packet, the caller will send it since we're returning the MAC
            // If we have a callback, notify it
            callback?.accept(ipAddress, entry.macAddress)

            return entry.macAddress
        }

        // We need to send an ARP request and queue the packet
        if (packet != null) {
            // Add packet to pending list
            pendingRequests.computeIfAbsent(ipStr) { CopyOnWriteArrayList() }.add(packet)
        }

        // Add callback to pending list
        if (callback != null) {
            pendingCallbacks.computeIfAbsent(ipStr) { CopyOnWriteArrayList() }.add(callback)
        }

        // Start ARP resolution process
        scheduler.execute {
            startArpResolution(ipStr, ipAddress)
        }

        return null
    }

    /**
     * Start the ARP resolution process for an IP address
     */
    private fun startArpResolution(ipStr: String, ipAddress: ByteArray) {
        // Skip if we already have this entry or if we're not running
        if (arpTable.containsKey(ipStr) || !running) {
            return
        }

        // Send ARP requests with exponential backoff
        for (attempt in 0 until maxArpRetries) {
            if (!running || arpTable.containsKey(ipStr)) {
                break
            }

            // Send ARP request
            sendArpRequest(ipAddress)

            // Wait with exponential backoff
            try {
                Thread.sleep((200L * (1 shl attempt)).coerceAtMost(2000))
            } catch (e: InterruptedException) {
                break
            }
        }

        // If still no response, clean up pending packets and callbacks
        if (!arpTable.containsKey(ipStr) && running) {
            // Remove pending packets
            val packets = pendingRequests.remove(ipStr)
            packets?.forEach { packet ->
                println("ARP resolution failed for $ipStr, dropping packet")
            }

            // Notify callbacks of failure
            val callbacks = pendingCallbacks.remove(ipStr)
            callbacks?.forEach { callback ->
                callback.accept(ipAddress, null)
            }
        }
    }

    /**
     * Process packets that were waiting for an ARP resolution
     */
    private fun processPendingPackets(ipStr: String, macAddress: ByteArray) {
        val packets = pendingRequests.remove(ipStr) ?: return

        packets.forEach { packet ->
            // Caller will resend the packet using the resolved MAC
            println("ARP resolved $ipStr -> ${bytesToMacAddress(macAddress)}, " +
                   "processing pending packet")
        }
    }

    /**
     * Process callbacks that were waiting for an ARP resolution
     */
    private fun processPendingCallbacks(ipStr: String, ipAddress: ByteArray, macAddress: ByteArray) {
        val callbacks = pendingCallbacks.remove(ipStr) ?: return

        callbacks.forEach { callback ->
            callback.accept(ipAddress, macAddress)
        }
    }

    /**
     * Update the ARP table with a new IP-MAC mapping
     */
    fun updateArpTable(ipAddress: ByteArray, macAddress: ByteArray) {
        val ipStr = bytesToIpv4(ipAddress)
        arpTable[ipStr] = ArpEntry(macAddress.clone(), System.currentTimeMillis())

        println("Updated ARP table: $ipStr -> ${bytesToMacAddress(macAddress)}")
    }

    /**
     * Clean up old entries from the ARP table
     */
    private fun cleanArpTable() {
        val now = System.currentTimeMillis()

        // Remove entries older than arpTimeout
        val iterator = arpTable.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()

            // Skip our own IP address
            if (entry.key == bytesToIpv4(ipAddress)) {
                continue
            }

            if (now - entry.value.timestamp > arpTimeout) {
                iterator.remove()
                println("Removed old ARP entry: ${entry.key}")
            }
        }
    }

    /**
     * Get the current ARP table (for debugging)
     */
    fun getArpTable(): Map<String, String> {
        return arpTable.mapValues { bytesToMacAddress(it.value.macAddress) }
    }
}