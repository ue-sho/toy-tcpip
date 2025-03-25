package com.toy.tcpip.ip

import com.toy.tcpip.arp.ArpLayer
import com.toy.tcpip.ethernet.EthernetFrame
import com.toy.tcpip.ethernet.EthernetLayer
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.createNetworkBuffer
import com.toy.tcpip.util.ipv4ToBytes
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.function.Consumer

/**
 * Handles IP layer operations
 */
class IpLayer(
    private val ethernetLayer: EthernetLayer,
    private val arpLayer: ArpLayer,
    val ipAddress: ByteArray,
    val subnetMask: Int = 24  // Default subnet mask = 255.255.255.0
) {
    // Map of protocol handlers
    private val protocolHandlers = ConcurrentHashMap<Int, Consumer<IpPacket>>()

    // IP packet fragmenter
    private val fragmenter = IpFragmenter()

    // Scheduler for periodic tasks
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()

    // Flag to indicate if the layer is running
    @Volatile
    private var running = false

    /**
     * Register a handler for a specific IP protocol
     */
    fun registerProtocolHandler(protocol: Int, handler: Consumer<IpPacket>) {
        protocolHandlers[protocol] = handler
    }

    /**
     * Unregister a handler for a specific IP protocol
     */
    fun unregisterProtocolHandler(protocol: Int) {
        protocolHandlers.remove(protocol)
    }

    /**
     * Start the IP layer
     */
    fun start() {
        if (running) {
            return
        }

        running = true

        // Register to receive IP packets from Ethernet layer
        ethernetLayer.registerProtocolHandler(Constants.ETH_TYPE_IP) { frame ->
            handleIpFrame(frame)
        }

        // Schedule periodic cleanup of IP fragments
        scheduler.scheduleAtFixedRate(fragmenter::cleanupFragments, 10, 10, TimeUnit.SECONDS)

        println("IP layer started with address ${bytesToIpv4(ipAddress)}/$subnetMask")
    }

    /**
     * Stop the IP layer
     */
    fun stop() {
        running = false

        // Unregister from Ethernet layer
        ethernetLayer.unregisterProtocolHandler(Constants.ETH_TYPE_IP)

        // Shutdown scheduler
        scheduler.shutdown()

        println("IP layer stopped")
    }

    /**
     * Handle an IP frame
     */
    private fun handleIpFrame(frame: EthernetFrame) {
        val ipPacket = IpPacket.parse(frame.payload) ?: return

        println("Received IP packet: $ipPacket")

        // Check if packet is for us
        if (!isForUs(ipPacket.destinationAddress)) {
            // If not for us, we might want to forward it (router functionality)
            // But we'll skip that for now
            return
        }

        // Handle fragmented packets
        val packet = fragmenter.reassemble(ipPacket) ?: return

        // Find and call the appropriate handler
        val handler = protocolHandlers[packet.protocol]
        if (handler != null) {
            handler.accept(packet)
        }
    }

    /**
     * Check if an IP address is intended for this host
     */
    private fun isForUs(destIp: ByteArray): Boolean {
        // Check if it's our exact IP
        if (destIp.contentEquals(ipAddress)) {
            return true
        }

        // Check if it's a broadcast address
        if (isBroadcast(destIp)) {
            return true
        }

        // Could add multicast checks here

        return false
    }

    /**
     * Check if an address is a broadcast address
     */
    private fun isBroadcast(ip: ByteArray): Boolean {
        // Check if it's the limited broadcast address (255.255.255.255)
        val allOnes = ByteArray(4) { 0xFF.toByte() }
        if (ip.contentEquals(allOnes)) {
            return true
        }

        // Check if it's a directed broadcast address for our subnet
        val ipInt = ip[0].toInt() and 0xFF shl 24 or
                   (ip[1].toInt() and 0xFF shl 16) or
                   (ip[2].toInt() and 0xFF shl 8) or
                   (ip[3].toInt() and 0xFF)

        val ipAddrInt = ipAddress[0].toInt() and 0xFF shl 24 or
                       (ipAddress[1].toInt() and 0xFF shl 16) or
                       (ipAddress[2].toInt() and 0xFF shl 8) or
                       (ipAddress[3].toInt() and 0xFF)

        val netmask = Constants.IP_NETMASK[subnetMask] ?: return false
        val invertedNetmask = netmask.inv()

        // Check if the host part is all ones
        return (ipInt and netmask) == (ipAddrInt and netmask) &&  // Same network
               (ipInt and invertedNetmask) == invertedNetmask      // Host part all ones
    }

    /**
     * Send an IP packet
     *
     * @param packet The IP packet to send
     * @return True if the packet was sent, false otherwise
     */
    fun send(packet: IpPacket): Boolean {
        if (!running) {
            return false
        }

        // Fragment packet if necessary
        val fragments = fragmenter.fragment(packet, ethernetLayer.device.mtu)

        for (fragment in fragments) {
            // Generate a buffer with the complete packet
            val buffer = fragment.toByteBuffer()

            // Determine next hop
            val nextHop = getNextHop(fragment.destinationAddress)

            // Resolve next hop's MAC address
            val targetMac = if (nextHop == null) {
                // Direct delivery
                arpLayer.resolve(fragment.destinationAddress, buffer) { ip, mac ->
                    if (mac != null) {
                        // We have the MAC, send the packet
                        val packetToSend = buffer.duplicate()
                        ethernetLayer.send(mac, Constants.ETH_TYPE_IP, packetToSend)
                    }
                }
            } else {
                // Via gateway
                arpLayer.resolve(nextHop, buffer) { ip, mac ->
                    if (mac != null) {
                        // We have the MAC, send the packet
                        val packetToSend = buffer.duplicate()
                        ethernetLayer.send(mac, Constants.ETH_TYPE_IP, packetToSend)
                    }
                }
            }

            // If we already have the MAC address, send the packet now
            if (targetMac != null) {
                ethernetLayer.send(targetMac, Constants.ETH_TYPE_IP, buffer)
            }
        }

        return true
    }

    /**
     * Create and send an IP packet
     *
     * @param destIp Destination IP address
     * @param protocol IP protocol number
     * @param payload Packet payload
     * @param id Packet identification (for fragmentation) or null to generate one
     * @param ttl Time to Live
     * @param dontFragment Set the Don't Fragment flag
     * @return True if the packet was sent, false otherwise
     */
    fun send(
        destIp: ByteArray,
        protocol: Int,
        payload: ByteBuffer,
        id: Int? = null,
        ttl: Int = Constants.DEFAULT_IP_TTL,
        dontFragment: Boolean = false
    ): Boolean {

        // Create basic IP header
        val headerLength = Constants.IP_HEADER_MIN_SIZE
        val packetLength = headerLength + payload.remaining()

        // Set up flags
        var flags = 0
        if (dontFragment) {
            flags = flags or IpPacket.FLAG_DONT_FRAGMENT
        }

        // Create IP packet
        val packet = IpPacket(
            ihl = headerLength / 4,  // IHL is in 32-bit words
            totalLength = packetLength,
            identification = id ?: IpPacket.generateId(),
            flags = flags,
            ttl = ttl,
            protocol = protocol,
            sourceAddress = ipAddress,
            destinationAddress = destIp,
            payload = payload
        )

        return send(packet)
    }

    /**
     * Get the next hop for reaching a specific destination
     *
     * @param destIp The destination IP address
     * @return The IP address of the next hop, or null if direct delivery
     */
    private fun getNextHop(destIp: ByteArray): ByteArray? {
        // Convert to integers for easy bit manipulation
        val destIpInt = destIp[0].toInt() and 0xFF shl 24 or
                       (destIp[1].toInt() and 0xFF shl 16) or
                       (destIp[2].toInt() and 0xFF shl 8) or
                       (destIp[3].toInt() and 0xFF)

        val ipAddrInt = ipAddress[0].toInt() and 0xFF shl 24 or
                       (ipAddress[1].toInt() and 0xFF shl 16) or
                       (ipAddress[2].toInt() and 0xFF shl 8) or
                       (ipAddress[3].toInt() and 0xFF)

        val netmask = Constants.IP_NETMASK[subnetMask] ?: return null

        // If destination is on our subnet, deliver directly
        if ((destIpInt and netmask) == (ipAddrInt and netmask)) {
            return null  // Direct delivery
        }

        // Otherwise, we need to go via a gateway/router
        // For now, we don't have routing logic, so just return null
        // In a real implementation, you'd look up the route in a routing table

        return null
    }
}