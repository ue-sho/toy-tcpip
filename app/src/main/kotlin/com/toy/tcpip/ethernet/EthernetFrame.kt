package com.toy.tcpip.ethernet

import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToMacAddress
import com.toy.tcpip.util.createNetworkBuffer
import java.nio.ByteBuffer

/**
 * Represents an Ethernet frame
 */
data class EthernetFrame(
    val destinationMac: ByteArray,
    val sourceMac: ByteArray,
    val etherType: Int,
    val payload: ByteBuffer
) {
    /**
     * Convert the Ethernet frame to a ByteBuffer
     */
    fun toByteBuffer(): ByteBuffer {
        val frameSize = Constants.ETH_HEADER_SIZE + payload.remaining()
        val buffer = createNetworkBuffer(frameSize)

        // Destination MAC
        buffer.put(destinationMac)

        // Source MAC
        buffer.put(sourceMac)

        // EtherType
        buffer.putShort(etherType.toShort())

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

        other as EthernetFrame

        if (!destinationMac.contentEquals(other.destinationMac)) return false
        if (!sourceMac.contentEquals(other.sourceMac)) return false
        if (etherType != other.etherType) return false
        if (payload != other.payload) return false

        return true
    }

    override fun hashCode(): Int {
        var result = destinationMac.contentHashCode()
        result = 31 * result + sourceMac.contentHashCode()
        result = 31 * result + etherType
        result = 31 * result + payload.hashCode()
        return result
    }

    override fun toString(): String {
        return "EthernetFrame(" +
               "destination=${bytesToMacAddress(destinationMac)}, " +
               "source=${bytesToMacAddress(sourceMac)}, " +
               "etherType=0x${etherType.toString(16)}, " +
               "payloadSize=${payload.remaining()})"
    }

    companion object {
        // Well-known MAC addresses
        val MAC_BROADCAST = ByteArray(6) { 0xFF.toByte() }

        /**
         * Parse an Ethernet frame from a ByteBuffer
         */
        fun parse(buffer: ByteBuffer): EthernetFrame? {
            // Check if there's enough data for an Ethernet header
            if (buffer.remaining() < Constants.ETH_HEADER_SIZE) {
                return null
            }

            val startPosition = buffer.position()

            // Read destination MAC
            val dstMac = ByteArray(6)
            buffer.get(dstMac)

            // Read source MAC
            val srcMac = ByteArray(6)
            buffer.get(srcMac)

            // Read EtherType
            val etherType = buffer.short.toInt() and 0xFFFF

            // Create payload buffer (points to remaining data in original buffer)
            val payloadBuffer = buffer.slice()

            // Advance the original buffer's position to the end
            buffer.position(buffer.limit())

            return EthernetFrame(dstMac, srcMac, etherType, payloadBuffer)
        }
    }
}