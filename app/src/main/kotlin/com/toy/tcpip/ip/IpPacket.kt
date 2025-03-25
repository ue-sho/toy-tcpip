package com.toy.tcpip.ip

import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.calculateChecksum
import com.toy.tcpip.util.createNetworkBuffer
import com.toy.tcpip.util.getUnsignedByte
import com.toy.tcpip.util.getUnsignedShort
import java.nio.ByteBuffer

/**
 * Represents an IPv4 packet
 */
data class IpPacket(
    val version: Int = 4,                      // IP version (4 for IPv4)
    val ihl: Int,                              // Internet Header Length (in 32-bit words)
    val dscp: Int = 0,                         // Differentiated Services Code Point
    val ecn: Int = 0,                          // Explicit Congestion Notification
    val totalLength: Int,                      // Total length of the packet
    val identification: Int,                   // Identification field for fragmentation
    val flags: Int = 0,                        // Fragmentation flags
    val fragmentOffset: Int = 0,               // Fragment offset
    val ttl: Int = Constants.DEFAULT_IP_TTL,   // Time to Live
    val protocol: Int,                         // Protocol (TCP, UDP, etc.)
    val checksum: Int = 0,                     // Header checksum
    val sourceAddress: ByteArray,              // Source IP address (4 bytes)
    val destinationAddress: ByteArray,         // Destination IP address (4 bytes)
    val options: ByteArray = ByteArray(0),     // IP options (if any)
    val payload: ByteBuffer                    // IP payload
) {
    /**
     * Convert the IP packet to a ByteBuffer
     */
    fun toByteBuffer(calculateChecksum: Boolean = true): ByteBuffer {
        val headerLength = ihl * 4  // IHL is in 32-bit words
        val packetSize = totalLength

        val buffer = createNetworkBuffer(packetSize)

        // Version and IHL
        buffer.put(((version shl 4) or ihl).toByte())

        // DSCP and ECN
        buffer.put(((dscp shl 2) or ecn).toByte())

        // Total length
        buffer.putShort(totalLength.toShort())

        // Identification
        buffer.putShort(identification.toShort())

        // Flags and fragment offset
        val flagsAndOffset = (flags shl 13) or fragmentOffset
        buffer.putShort(flagsAndOffset.toShort())

        // TTL
        buffer.put(ttl.toByte())

        // Protocol
        buffer.put(protocol.toByte())

        // Checksum (initially 0)
        val checksumPosition = buffer.position()
        buffer.putShort(0)  // Initial value

        // Source address
        buffer.put(sourceAddress)

        // Destination address
        buffer.put(destinationAddress)

        // Options (if any)
        if (options.isNotEmpty()) {
            buffer.put(options)
        }

        // Calculate checksum if requested
        if (calculateChecksum) {
            // Save position
            val endOfHeader = buffer.position()

            // Calculate checksum
            buffer.position(0)
            val computedChecksum = calculateChecksum(buffer, 0, headerLength)

            // Set checksum in header
            buffer.position(checksumPosition)
            buffer.putShort(computedChecksum.toShort())

            // Restore position
            buffer.position(endOfHeader)
        } else {
            // Use the provided checksum
            buffer.position(checksumPosition)
            buffer.putShort(checksum.toShort())
            buffer.position(headerLength)
        }

        // Payload
        val payloadDuplicate = payload.duplicate()
        buffer.put(payloadDuplicate)

        // Prepare for reading
        buffer.flip()

        return buffer
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IpPacket

        if (version != other.version) return false
        if (ihl != other.ihl) return false
        if (dscp != other.dscp) return false
        if (ecn != other.ecn) return false
        if (totalLength != other.totalLength) return false
        if (identification != other.identification) return false
        if (flags != other.flags) return false
        if (fragmentOffset != other.fragmentOffset) return false
        if (ttl != other.ttl) return false
        if (protocol != other.protocol) return false
        if (checksum != other.checksum) return false
        if (!sourceAddress.contentEquals(other.sourceAddress)) return false
        if (!destinationAddress.contentEquals(other.destinationAddress)) return false
        if (!options.contentEquals(other.options)) return false
        if (payload != other.payload) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + ihl
        result = 31 * result + dscp
        result = 31 * result + ecn
        result = 31 * result + totalLength
        result = 31 * result + identification
        result = 31 * result + flags
        result = 31 * result + fragmentOffset
        result = 31 * result + ttl
        result = 31 * result + protocol
        result = 31 * result + checksum
        result = 31 * result + sourceAddress.contentHashCode()
        result = 31 * result + destinationAddress.contentHashCode()
        result = 31 * result + options.contentHashCode()
        result = 31 * result + payload.hashCode()
        return result
    }

    override fun toString(): String {
        return "IpPacket(" +
               "version=$version, " +
               "ihl=$ihl, " +
               "len=$totalLength, " +
               "id=$identification, " +
               "flags=${flags.toString(2)}, " +
               "offset=$fragmentOffset, " +
               "ttl=$ttl, " +
               "proto=$protocol, " +
               "csum=0x${checksum.toString(16)}, " +
               "src=${bytesToIpv4(sourceAddress)}, " +
               "dst=${bytesToIpv4(destinationAddress)}, " +
               "options=${options.size}B, " +
               "payload=${payload.remaining()}B)"
    }

    companion object {
        // IP fragmentation flags
        const val FLAG_RESERVED = 0x4
        const val FLAG_DONT_FRAGMENT = 0x2
        const val FLAG_MORE_FRAGMENTS = 0x1

        // Generate an identifier (for fragmentation)
        private var nextId = 0
        fun generateId(): Int {
            synchronized(IpPacket::class.java) {
                nextId = (nextId + 1) and 0xFFFF
                return nextId
            }
        }

        /**
         * Parse an IP packet from a ByteBuffer
         */
        fun parse(buffer: ByteBuffer): IpPacket? {
            if (buffer.remaining() < Constants.IP_HEADER_MIN_SIZE) {
                return null
            }

            val startPosition = buffer.position()

            // Version and IHL
            val versionIhl = buffer.getUnsignedByte()
            val version = versionIhl shr 4
            val ihl = versionIhl and 0x0F

            // Sanity checks
            if (version != 4 || ihl < 5) {
                // Reset position and return null
                buffer.position(startPosition)
                return null
            }

            val headerLength = ihl * 4  // IHL is in 32-bit words

            // Check if we have enough data for the entire header
            if (buffer.remaining() < headerLength - 1) {  // -1 because we already read 1 byte
                // Reset position and return null
                buffer.position(startPosition)
                return null
            }

            // DSCP and ECN
            val dscpEcn = buffer.getUnsignedByte()
            val dscp = dscpEcn shr 2
            val ecn = dscpEcn and 0x03

            // Total length
            val totalLength = buffer.getUnsignedShort()

            // Check if we have enough data for the entire packet
            if (startPosition + totalLength > buffer.limit()) {
                // Reset position and return null
                buffer.position(startPosition)
                return null
            }

            // Identification
            val identification = buffer.getUnsignedShort()

            // Flags and fragment offset
            val flagsOffset = buffer.getUnsignedShort()
            val flags = flagsOffset shr 13
            val fragmentOffset = flagsOffset and 0x1FFF

            // TTL
            val ttl = buffer.getUnsignedByte()

            // Protocol
            val protocol = buffer.getUnsignedByte()

            // Checksum
            val checksum = buffer.getUnsignedShort()

            // Source address
            val sourceAddress = ByteArray(4)
            buffer.get(sourceAddress)

            // Destination address
            val destinationAddress = ByteArray(4)
            buffer.get(destinationAddress)

            // Options (if any)
            val optionsLength = headerLength - Constants.IP_HEADER_MIN_SIZE
            val options = if (optionsLength > 0) {
                val opts = ByteArray(optionsLength)
                buffer.get(opts)
                opts
            } else {
                ByteArray(0)
            }

            // Create payload buffer (points to remaining data in original buffer)
            val payloadSize = totalLength - headerLength
            val payloadBuffer = if (payloadSize > 0) {
                val payloadLimit = buffer.position() + payloadSize
                val payload = buffer.slice()
                payload.limit(payloadSize)

                // Advance the original buffer's position to after the payload
                buffer.position(payloadLimit)

                payload
            } else {
                // Empty payload
                ByteBuffer.allocate(0)
            }

            return IpPacket(
                version = version,
                ihl = ihl,
                dscp = dscp,
                ecn = ecn,
                totalLength = totalLength,
                identification = identification,
                flags = flags,
                fragmentOffset = fragmentOffset,
                ttl = ttl,
                protocol = protocol,
                checksum = checksum,
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                options = options,
                payload = payloadBuffer
            )
        }
    }
}