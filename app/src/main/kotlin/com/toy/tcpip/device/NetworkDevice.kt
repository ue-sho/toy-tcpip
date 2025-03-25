package com.toy.tcpip.device

import java.nio.ByteBuffer

/**
 * Interface for network devices that can send and receive packets
 */
interface NetworkDevice {
    /**
     * Get the device name
     */
    val name: String

    /**
     * Get the MTU (Maximum Transmission Unit) for this device
     */
    val mtu: Int

    /**
     * Get the MAC address of this device
     */
    val macAddress: ByteArray

    /**
     * Open the network device for communication
     */
    fun open()

    /**
     * Close the network device
     */
    fun close()

    /**
     * Send a packet through this device
     *
     * @param buffer The packet data to send
     * @return Number of bytes sent or -1 on error
     */
    fun send(buffer: ByteBuffer): Int

    /**
     * Receive a packet from this device
     *
     * @param buffer The buffer to store received data
     * @return Number of bytes received or -1 on error
     */
    fun receive(buffer: ByteBuffer): Int

    /**
     * Check if the device is currently open
     */
    fun isOpen(): Boolean
}