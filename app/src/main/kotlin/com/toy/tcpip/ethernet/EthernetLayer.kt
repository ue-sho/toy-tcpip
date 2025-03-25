package com.toy.tcpip.ethernet

import com.toy.tcpip.device.NetworkDevice
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToMacAddress
import com.toy.tcpip.util.createNetworkBuffer
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Consumer

/**
 * Handles Ethernet layer operations
 */
class EthernetLayer(private val device: NetworkDevice) {

    // Map of ethertype handlers
    private val protocolHandlers = ConcurrentHashMap<Int, Consumer<EthernetFrame>>()

    // Flag to indicate if the layer is running
    @Volatile
    private var running = false

    // Thread for receiving packets
    private var receiveThread: Thread? = null

    /**
     * Register a handler for a specific EtherType
     */
    fun registerProtocolHandler(etherType: Int, handler: Consumer<EthernetFrame>) {
        protocolHandlers[etherType] = handler
    }

    /**
     * Unregister a handler for a specific EtherType
     */
    fun unregisterProtocolHandler(etherType: Int) {
        protocolHandlers.remove(etherType)
    }

    /**
     * Start the Ethernet layer
     */
    fun start() {
        if (running) {
            return
        }

        // Open the device if not already open
        if (!device.isOpen()) {
            device.open()
        }

        running = true

        // Start the receive thread
        receiveThread = Thread(this::receiveLoop, "ethernet-rx")
        receiveThread?.isDaemon = true
        receiveThread?.start()

        println("Ethernet layer started with device ${device.name}, " +
               "MAC address: ${bytesToMacAddress(device.macAddress)}")
    }

    /**
     * Stop the Ethernet layer
     */
    fun stop() {
        running = false
        receiveThread?.join(1000)
        receiveThread = null

        // Close the device if it was opened by us
        device.close()

        println("Ethernet layer stopped")
    }

    /**
     * Send an Ethernet frame
     */
    fun send(frame: EthernetFrame) {
        if (!running) {
            throw IllegalStateException("Ethernet layer not running")
        }

        val buffer = frame.toByteBuffer()
        val sent = device.send(buffer)

        if (sent < 0) {
            println("Failed to send Ethernet frame: $frame")
        } else {
            println("Sent Ethernet frame: $frame")
        }
    }

    /**
     * Create and send an Ethernet frame
     */
    fun send(destMac: ByteArray, etherType: Int, payload: ByteBuffer) {
        val frame = EthernetFrame(destMac, device.macAddress, etherType, payload)
        send(frame)
    }

    /**
     * Main receive loop
     */
    private fun receiveLoop() {
        val buffer = createNetworkBuffer(device.mtu + Constants.ETH_HEADER_SIZE)

        while (running) {
            try {
                // Reset buffer for next packet
                buffer.clear()

                // Receive packet
                val received = device.receive(buffer)

                if (received <= 0) {
                    // No data or error
                    Thread.sleep(10)
                    continue
                }

                // Prepare buffer for reading
                buffer.flip()

                // Parse Ethernet frame
                val frame = EthernetFrame.parse(buffer)

                if (frame != null) {
                    println("Received Ethernet frame: $frame")

                    // Find and call the appropriate handler
                    val handler = protocolHandlers[frame.etherType]
                    if (handler != null) {
                        handler.accept(frame)
                    }
                }
            } catch (e: Exception) {
                if (running) {
                    e.printStackTrace()
                }
            }
        }
    }
}