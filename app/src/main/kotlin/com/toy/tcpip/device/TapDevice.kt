package com.toy.tcpip.device

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.IntByReference
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToMacAddress
import java.io.Closeable
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.lang.reflect.Field
import java.nio.ByteBuffer
import java.util.Random

/**
 * Implementation of NetworkDevice that uses Linux TAP interfaces
 */
class TapDevice(
    override val name: String = "tap0",
    override val mtu: Int = Constants.DEFAULT_MTU,
    macAddressStr: String? = null
) : NetworkDevice {

    // Native Linux C library interface
    private interface CLibrary : Library {
        fun open(path: String, flags: Int): Int
        fun close(fd: Int): Int
        fun ioctl(fd: Int, request: NativeLong, vararg args: Any?): Int
    }

    // Structure for ifreq, which is used to control network interfaces
    @Structure.FieldOrder("ifr_name", "ifr_flags")
    class IfreqFlags : Structure() {
        @JvmField
        var ifr_name = ByteArray(16)
        @JvmField
        var ifr_flags = Short()

        companion object {
            const val IFF_TAP = 0x0002
            const val IFF_NO_PI = 0x1000
        }
    }

    companion object {
        // Linux system call flags
        private const val O_RDWR = 2
        private const val TUNSETIFF: Long = 0x400454caL

        private val cLibrary: CLibrary = Native.load("c", CLibrary::class.java)

        // Random object for generating MAC addresses
        private val random = Random()

        // Generate a random locally administered MAC address
        private fun generateMacAddress(): ByteArray {
            val mac = ByteArray(6)
            random.nextBytes(mac)
            // Set locally administered bit and clear multicast bit
            mac[0] = (mac[0].toInt() and 0xFC or 0x02).toByte()
            return mac
        }

        // Get the fd int value from a FileDescriptor object using reflection
        private fun getFd(fileDescriptor: FileDescriptor): Int {
            try {
                val field: Field = fileDescriptor.javaClass.getDeclaredField("fd")
                field.isAccessible = true
                return field.getInt(fileDescriptor)
            } catch (e: Exception) {
                throw IOException("Could not get file descriptor value", e)
            }
        }
    }

    // Device file descriptor
    private var fd: Int = -1

    // Input and output streams for the device
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null

    // MAC address of the device
    override val macAddress: ByteArray = macAddressStr?.let {
        val parts = it.split(":")
        if (parts.size != 6) {
            throw IllegalArgumentException("Invalid MAC address format: $it")
        }
        parts.map { part -> part.toInt(16).toByte() }.toByteArray()
    } ?: generateMacAddress()

    /**
     * Open the TAP device for reading and writing
     */
    override fun open() {
        if (isOpen()) {
            return
        }

        // Check if we're on Linux
        if (!Platform.isLinux()) {
            throw UnsupportedOperationException("TapDevice is only supported on Linux")
        }

        // Open the TUN/TAP device
        fd = cLibrary.open("/dev/net/tun", O_RDWR)
        if (fd < 0) {
            throw IOException("Could not open /dev/net/tun")
        }

        // Configure the device
        val ifr = IfreqFlags()
        System.arraycopy(name.toByteArray(), 0, ifr.ifr_name, 0,
                         Math.min(name.length, ifr.ifr_name.size - 1))
        ifr.ifr_flags = (IfreqFlags.IFF_TAP or IfreqFlags.IFF_NO_PI).toShort()

        val ret = cLibrary.ioctl(fd, NativeLong(TUNSETIFF), ifr)
        if (ret < 0) {
            cLibrary.close(fd)
            fd = -1
            throw IOException("Could not configure TAP device: $name")
        }

        // Create Java FileDescriptor
        val fdObj = FileDescriptor()
        try {
            val field = fdObj.javaClass.getDeclaredField("fd")
            field.isAccessible = true
            field.setInt(fdObj, fd)
        } catch (e: Exception) {
            cLibrary.close(fd)
            fd = -1
            throw IOException("Could not create FileDescriptor", e)
        }

        // Create streams from the FileDescriptor
        inputStream = FileInputStream(fdObj)
        outputStream = FileOutputStream(fdObj)

        println("TAP device $name opened. MAC address: ${bytesToMacAddress(macAddress)}")
    }

    /**
     * Close the TAP device
     */
    override fun close() {
        try {
            inputStream?.close()
            outputStream?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }

        if (fd >= 0) {
            cLibrary.close(fd)
            fd = -1
        }
    }

    /**
     * Send a packet to the TAP device
     */
    override fun send(buffer: ByteBuffer): Int {
        if (!isOpen()) {
            throw IOException("Device not open")
        }

        val outputStream = this.outputStream ?: throw IOException("Output stream is null")

        val position = buffer.position()
        val limit = buffer.limit()
        val length = limit - position

        try {
            if (buffer.hasArray()) {
                outputStream.write(buffer.array(), buffer.arrayOffset() + position, length)
            } else {
                val bytes = ByteArray(length)
                val duplicate = buffer.duplicate()
                duplicate.get(bytes)
                outputStream.write(bytes)
            }

            buffer.position(limit)
            return length
        } catch (e: IOException) {
            e.printStackTrace()
            return -1
        }
    }

    /**
     * Receive a packet from the TAP device
     */
    override fun receive(buffer: ByteBuffer): Int {
        if (!isOpen()) {
            throw IOException("Device not open")
        }

        val inputStream = this.inputStream ?: throw IOException("Input stream is null")

        val position = buffer.position()
        val remaining = buffer.remaining()

        try {
            if (buffer.hasArray()) {
                val read = inputStream.read(buffer.array(), buffer.arrayOffset() + position, remaining)
                if (read > 0) {
                    buffer.position(position + read)
                }
                return read
            } else {
                val bytes = ByteArray(remaining)
                val read = inputStream.read(bytes, 0, remaining)
                if (read > 0) {
                    buffer.put(bytes, 0, read)
                }
                return read
            }
        } catch (e: IOException) {
            e.printStackTrace()
            return -1
        }
    }

    /**
     * Check if the device is currently open
     */
    override fun isOpen(): Boolean {
        return fd >= 0
    }
}