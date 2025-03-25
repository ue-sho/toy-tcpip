package com.toy.tcpip

import com.toy.tcpip.arp.ArpLayer
import com.toy.tcpip.device.TapDevice
import com.toy.tcpip.ethernet.EthernetLayer
import com.toy.tcpip.ip.IpLayer
import com.toy.tcpip.util.ipv4ToBytes
import java.nio.ByteBuffer

/**
 * Main application entry point
 */
fun main(args: Array<String>) {
    println("Toy TCP/IP Stack")

    // Parse command line arguments
    val tapDevice = if (args.isNotEmpty()) args[0] else "tap0"
    val ipAddress = if (args.size > 1) args[1] else "192.168.7.2"
    val subnetMask = if (args.size > 2) args[2].toInt() else 24

    println("Using TAP device: $tapDevice")
    println("IP address: $ipAddress/$subnetMask")

    // Initialize network device
    val device = TapDevice(tapDevice)

    // Initialize layers
    val ethernetLayer = EthernetLayer(device)
    val arpLayer = ArpLayer(ethernetLayer, ipv4ToBytes(ipAddress))
    val ipLayer = IpLayer(ethernetLayer, arpLayer, ipv4ToBytes(ipAddress), subnetMask)

    // Start layers
    try {
        println("Starting Ethernet layer...")
        ethernetLayer.start()

        println("Starting ARP layer...")
        arpLayer.start()

        println("Starting IP layer...")
        ipLayer.start()

        // Example: Send a ping packet to 192.168.7.1
        println("Sending ping to 192.168.7.1...")

        // Wait for user to press enter
        println("Press Enter to shutdown...")
        readLine()

    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        // Shutdown in reverse order
        println("Shutting down IP layer...")
        ipLayer.stop()

        println("Shutting down ARP layer...")
        arpLayer.stop()

        println("Shutting down Ethernet layer...")
        ethernetLayer.stop()
    }
}