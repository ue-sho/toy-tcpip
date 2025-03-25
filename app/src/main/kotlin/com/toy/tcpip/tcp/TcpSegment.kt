package com.toy.tcpip.tcp

import com.toy.tcpip.ip.IpPacket
import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.calculateChecksum
import com.toy.tcpip.util.createNetworkBuffer
import com.toy.tcpip.util.getUnsignedByte
import com.toy.tcpip.util.getUnsignedShort
import java.nio.ByteBuffer

/**
 * Represents a TCP segment
 */
data class TcpSegment(
    val sourcePort: Int,
    val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgmentNumber: Long,
    val dataOffset: Int,      // Header length in 32-bit words
    val reserved: Int = 0,
    val flags: Int,           // Control bits (URG, ACK, PSH, RST, SYN, FIN)
    val windowSize: Int,
    val checksum: Int,
    val urgentPointer: Int = 0,
    val options: ByteArray = ByteArray(0),
    val payload: ByteBuffer,
    // IP header fields needed for checksum calculation
    val sourceAddress: ByteArray? = null,
    val destinationAddress: ByteArray? = null
) {
    /**
     * Convert the TCP segment to a ByteBuffer
     */
    fun toByteBuffer(calculateChecksumValue: Boolean = false): ByteBuffer {
        val headerLength = dataOffset * 4  // Data offset is in 32-bit words
        val segmentSize = headerLength + payload.remaining()

        val buffer = createNetworkBuffer(segmentSize)

        // Source port
        buffer.putShort(sourcePort.toShort())

        // Destination port
        buffer.putShort(destinationPort.toShort())

        // Sequence number
        buffer.putInt(sequenceNumber.toInt())

        // Acknowledgment number
        buffer.putInt(acknowledgmentNumber.toInt())

        // Data offset, reserved, and flags
        buffer.put(((dataOffset shl 4) or (reserved and 0x0F)).toByte())
        buffer.put(flags.toByte())

        // Window size
        buffer.putShort(windowSize.toShort())

        // Checksum (initially 0 if we're calculating it)
        val checksumPosition = buffer.position()
        if (calculateChecksumValue) {
            buffer.putShort(0)  // Initial value for calculation
        } else {
            buffer.putShort(checksum.toShort())
        }

        // Urgent pointer
        buffer.putShort(urgentPointer.toShort())

        // Options (if any)
        if (options.isNotEmpty()) {
            buffer.put(options)
        }

        // Padding to align to 32-bit boundary
        val optionsLength = options.size
        val paddingBytes = headerLength - Constants.TCP_HEADER_MIN_SIZE - optionsLength
        for (i in 0 until paddingBytes) {
            buffer.put(0)
        }

        // Payload
        val payloadDuplicate = payload.duplicate()
        buffer.put(payloadDuplicate)

        // Calculate checksum if requested
        if (calculateChecksumValue && sourceAddress != null && destinationAddress != null) {
            val tcpLength = segmentSize

            // Create pseudo-header for checksum calculation
            val pseudoHeader = ByteBuffer.allocate(12)
            pseudoHeader.put(sourceAddress)
            pseudoHeader.put(destinationAddress)
            pseudoHeader.put(0)  // Zero
            pseudoHeader.put(Constants.IP_PROTO_TCP.toByte())  // Protocol
            pseudoHeader.putShort(tcpLength.toShort())  // TCP length
            pseudoHeader.flip()

            // Calculate checksum
            val computedChecksum = calculateTcpChecksum(pseudoHeader, buffer)

            // Set checksum in header
            buffer.position(checksumPosition)
            buffer.putShort(computedChecksum.toShort())
        }

        // Prepare for reading
        buffer.flip()

        return buffer
    }

    /**
     * Calculate TCP checksum
     */
    private fun calculateTcpChecksum(pseudoHeader: ByteBuffer, tcpData: ByteBuffer): Int {
        // Create a buffer with pseudo-header and TCP data
        val totalLength = pseudoHeader.remaining() + tcpData.limit()
        val combinedBuffer = ByteBuffer.allocate(totalLength)

        // Copy pseudo-header
        combinedBuffer.put(pseudoHeader.duplicate())

        // Copy TCP data
        combinedBuffer.put(tcpData.duplicate())

        // Reset position
        combinedBuffer.flip()

        // Calculate checksum
        return calculateChecksum(combinedBuffer, 0, totalLength)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TcpSegment

        if (sourcePort != other.sourcePort) return false
        if (destinationPort != other.destinationPort) return false
        if (sequenceNumber != other.sequenceNumber) return false
        if (acknowledgmentNumber != other.acknowledgmentNumber) return false
        if (dataOffset != other.dataOffset) return false
        if (reserved != other.reserved) return false
        if (flags != other.flags) return false
        if (windowSize != other.windowSize) return false
        if (checksum != other.checksum) return false
        if (urgentPointer != other.urgentPointer) return false
        if (!options.contentEquals(other.options)) return false
        if (payload != other.payload) return false
        if (sourceAddress != null && other.sourceAddress != null) {
            if (!sourceAddress.contentEquals(other.sourceAddress)) return false
        } else if (sourceAddress != other.sourceAddress) return false
        if (destinationAddress != null && other.destinationAddress != null) {
            if (!destinationAddress.contentEquals(other.destinationAddress)) return false
        } else if (destinationAddress != other.destinationAddress) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sourcePort
        result = 31 * result + destinationPort
        result = 31 * result + sequenceNumber.toInt()
        result = 31 * result + acknowledgmentNumber.toInt()
        result = 31 * result + dataOffset
        result = 31 * result + reserved
        result = 31 * result + flags
        result = 31 * result + windowSize
        result = 31 * result + checksum
        result = 31 * result + urgentPointer
        result = 31 * result + options.contentHashCode()
        result = 31 * result + payload.hashCode()
        result = 31 * result + (sourceAddress?.contentHashCode() ?: 0)
        result = 31 * result + (destinationAddress?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        val flagStr = StringBuilder()
        if (flags and Constants.TCP_FLAG_FIN != 0) flagStr.append("F")
        if (flags and Constants.TCP_FLAG_SYN != 0) flagStr.append("S")
        if (flags and Constants.TCP_FLAG_RST != 0) flagStr.append("R")
        if (flags and Constants.TCP_FLAG_PSH != 0) flagStr.append("P")
        if (flags and Constants.TCP_FLAG_ACK != 0) flagStr.append("A")
        if (flags and Constants.TCP_FLAG_URG != 0) flagStr.append("U")

        val srcAddrStr = sourceAddress?.let { bytesToIpv4(it) } ?: "?"
        val destAddrStr = destinationAddress?.let { bytesToIpv4(it) } ?: "?"

        return "TcpSegment(" +
               "$srcAddrStr:$sourcePort -> $destAddrStr:$destinationPort, " +
               "seq=${sequenceNumber}, " +
               "ack=${acknowledgmentNumber}, " +
               "flags=$flagStr, " +
               "win=$windowSize, " +
               "len=${payload.remaining()})"
    }

    companion object {
        /**
         * Parse a TCP segment from a ByteBuffer
         *
         * @param buffer The buffer containing the TCP segment
         * @param sourceAddress The source IP address (for checksum verification)
         * @param destinationAddress The destination IP address (for checksum verification)
         * @return The parsed TCP segment or null if parsing failed
         */
        fun parse(
            buffer: ByteBuffer,
            sourceAddress: ByteArray? = null,
            destinationAddress: ByteArray? = null
        ): TcpSegment? {

            if (buffer.remaining() < Constants.TCP_HEADER_MIN_SIZE) {
                return null
            }

            val startPosition = buffer.position()

            // Source port
            val sourcePort = buffer.getUnsignedShort()

            // Destination port
            val destinationPort = buffer.getUnsignedShort()

            // Sequence number
            val sequenceNumber = buffer.getUnsignedInt()

            // Acknowledgment number
            val acknowledgmentNumber = buffer.getUnsignedInt()

            // Data offset, reserved, and flags
            val dataOffsetReserved = buffer.getUnsignedByte()
            val dataOffset = dataOffsetReserved shr 4
            val reserved = dataOffsetReserved and 0x0F

            // Flags
            val flags = buffer.getUnsignedByte()

            // Window size
            val windowSize = buffer.getUnsignedShort()

            // Checksum
            val checksum = buffer.getUnsignedShort()

            // Urgent pointer
            val urgentPointer = buffer.getUnsignedShort()

            // Sanity check for data offset
            if (dataOffset < 5) {
                // Invalid data offset, TCP header must be at least 20 bytes
                buffer.position(startPosition)
                return null
            }

            val headerLength = dataOffset * 4  // 32-bit words to bytes

            // Check if we have enough data for the entire header
            if (buffer.remaining() < headerLength - Constants.TCP_HEADER_MIN_SIZE) {
                buffer.position(startPosition)
                return null
            }

            // Options (if any)
            val optionsLength = headerLength - Constants.TCP_HEADER_MIN_SIZE
            val options = if (optionsLength > 0) {
                val opts = ByteArray(optionsLength)
                buffer.get(opts)
                opts
            } else {
                ByteArray(0)
            }

            // Create payload buffer (points to remaining data in original buffer)
            val payload = buffer.slice()

            // Advance the original buffer's position to the end
            buffer.position(buffer.limit())

            return TcpSegment(
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                sequenceNumber = sequenceNumber,
                acknowledgmentNumber = acknowledgmentNumber,
                dataOffset = dataOffset,
                reserved = reserved,
                flags = flags,
                windowSize = windowSize,
                checksum = checksum,
                urgentPointer = urgentPointer,
                options = options,
                payload = payload,
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress
            )
        }
    }
}