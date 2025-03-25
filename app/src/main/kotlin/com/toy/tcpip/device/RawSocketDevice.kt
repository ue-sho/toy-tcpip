package com.toy.tcpip.device

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.IntByReference
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToMacAddress
import com.toy.tcpip.util.macAddressToBytes
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Implementation of NetworkDevice that uses Linux AF_PACKET(PF_PACKET) sockets
 */
class RawSocketDevice(
    val interfaceName: String,
    override val name: String = interfaceName,
    override val mtu: Int = Constants.DEFAULT_MTU,
    var macAddressStr: String? = null
) : NetworkDevice {

    // Native Linux C library interface for socket operations
    private interface CLibrary : Library {
        fun socket(domain: Int, type: Int, protocol: Int): Int
        fun close(fd: Int): Int
        fun bind(sockfd: Int, addr: Structure, addrlen: Int): Int
        fun send(sockfd: Int, buf: Pointer, len: Int, flags: Int): Int
        fun recv(sockfd: Int, buf: Pointer, len: Int, flags: Int): Int
        fun ioctl(fd: Int, request: Long, argp: Pointer): Int
    }

    // Socket constants
    companion object {
        // same as PF_PACKET
        // https://www.linuxquestions.org/questions/programming-9/sockets-af_packet-versus-pf_packet-942143/
        private const val AF_PACKET = 17
        private const val SOCK_RAW = 3
        private const val ETH_P_ALL = 0x0003
        private const val SIOCGIFINDEX = 0x8933L
        private const val SIOCGIFHWADDR = 0x8927L

        private val cLibrary: CLibrary = Native.load("c", CLibrary::class.java)
    }

    // Structure for sockaddr_ll, which is used to bind to a specific interface
    @Structure.FieldOrder("sll_family", "sll_protocol", "sll_ifindex", "sll_hatype",
                         "sll_pkttype", "sll_halen", "sll_addr")
    class SockAddrLl : Structure() {
        @JvmField var sll_family: Short = 0
        @JvmField var sll_protocol: Short = 0
        @JvmField var sll_ifindex: Int = 0
        @JvmField var sll_hatype: Short = 0
        @JvmField var sll_pkttype: Byte = 0
        @JvmField var sll_halen: Byte = 0
        @JvmField var sll_addr = ByteArray(8)
    }

    // Structure for ifreq, which is used to get interface information
    @Structure.FieldOrder("ifr_name", "ifr_ifindex")
    class IfreqIndex : Structure() {
        @JvmField var ifr_name = ByteArray(16)
        @JvmField var ifr_ifindex: Int = 0
    }

    @Structure.FieldOrder("ifr_name", "ifr_hwaddr")
    class IfreqHwaddr : Structure() {
        @JvmField var ifr_name = ByteArray(16)
        @JvmField var ifr_hwaddr = ByteArray(14) // sa_family (2 bytes) + sa_data (14 bytes)
    }

    // Socket file descriptor
    private var fd: Int = -1

    // Interface index
    private var ifindex: Int = -1

    // MAC address of the device
    override val macAddress: ByteArray = macAddressStr?.let {
        macAddressToBytes(it)
    } ?: ByteArray(6)

    /**
     * Open the raw socket
     */
    override fun open() {
        if (isOpen()) {
            return
        }

        // Create raw socket
        fd = cLibrary.socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL).toShort().toInt())
        if (fd < 0) {
            throw IOException("Could not create raw socket")
        }

        try {
            // Get the interface index
            val ifr = IfreqIndex()
            System.arraycopy(
                interfaceName.toByteArray(),
                0,
                ifr.ifr_name,
                0,
                Math.min(interfaceName.length, ifr.ifr_name.size - 1)
            )

            val ret = cLibrary.ioctl(fd, SIOCGIFINDEX, ifr.pointer)
            if (ret < 0) {
                throw IOException("Could not get interface index for $interfaceName")
            }

            ifindex = ifr.ifr_ifindex

            // If no MAC address was provided, try to get it from the interface
            if (macAddressStr == null) {
                val ifrHw = getIfreqHwaddr()
                // Copy MAC address (skip first 2 bytes, which are sa_family)
                System.arraycopy(ifrHw.ifr_hwaddr, 2, macAddress, 0, 6)
            }

            // Bind the socket to the interface
            val addr = SockAddrLl()
            addr.sll_family = AF_PACKET.toShort()
            addr.sll_protocol = ETH_P_ALL.toShort()
            addr.sll_ifindex = ifindex
            addr.sll_halen = 6

            val bindRet = cLibrary.bind(fd, addr, addr.size())
            if (bindRet < 0) {
                throw IOException("Could not bind to interface $interfaceName")
            }

            println("Raw socket opened on interface $interfaceName (index=$ifindex). " +
                   "MAC address: ${bytesToMacAddress(macAddress)}")

        } catch (e: Exception) {
            cLibrary.close(fd)
            fd = -1
            throw e
        }
    }

    /**
     * Close the raw socket
     */
    override fun close() {
        if (fd >= 0) {
            cLibrary.close(fd)
            fd = -1
        }
    }

    /**
     * Send a packet using the raw socket
     */
    override fun send(buffer: ByteBuffer): Int {
        if (!isOpen()) {
            throw IOException("Device not open")
        }

        val position = buffer.position()
        val length = buffer.remaining()

        val memory = Memory(length.toLong())

        if (buffer.hasArray()) {
            memory.write(0, buffer.array(), buffer.arrayOffset() + position, length)
        } else {
            val bytes = ByteArray(length)
            buffer.duplicate().get(bytes)
            memory.write(0, bytes, 0, length)
        }

        val sent = cLibrary.send(fd, memory, length, 0)
        if (sent > 0) {
            buffer.position(position + sent)
        }

        return sent
    }

    /**
     * Receive a packet from the raw socket
     */
    override fun receive(buffer: ByteBuffer): Int {
        if (!isOpen()) {
            throw IOException("Device not open")
        }

        val position = buffer.position()
        val length = buffer.remaining()

        val memory = Memory(length.toLong())

        val received = cLibrary.recv(fd, memory, length, 0)
        if (received <= 0) {
            return received
        }

        if (buffer.hasArray()) {
            memory.read(0, buffer.array(), buffer.arrayOffset() + position, received)
        } else {
            val bytes = ByteArray(received)
            memory.read(0, bytes, 0, received)
            buffer.put(bytes)
        }

        buffer.position(position + received)
        return received
    }

    /**
     * Check if the device is currently open
     */
    override fun isOpen(): Boolean {
        return fd >= 0
    }

    private fun getIfreqHwaddr(): IfreqHwaddr {
        val ifrHw = IfreqHwaddr()
        System.arraycopy(
            interfaceName.toByteArray(),
            0,
            ifrHw.ifr_name,
            0,
            Math.min(interfaceName.length, ifrHw.ifr_name.size - 1)
        )

        val retHw = cLibrary.ioctl(fd, SIOCGIFHWADDR, ifrHw.pointer)
        if (retHw < 0) {
            throw IOException("Could not get MAC address for $interfaceName")
        }

        return ifrHw
    }
}