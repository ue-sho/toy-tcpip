package com.toy.tcpip.arp

import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.bytesToMacAddress
import com.toy.tcpip.util.createNetworkBuffer
import java.nio.ByteBuffer

/**
 * Represents an ARP packet
 */
data class ArpPacket(
    val hardwareType: Int,
    val protocolType: Int,
    val hardwareAddressLength: Int,
    val protocolAddressLength: Int,
    val operation: Int,
    val senderHardwareAddress: ByteArray,
    val senderProtocolAddress: ByteArray,
    val targetHardwareAddress: ByteArray,
    val targetProtocolAddress: ByteArray
) {
    /**
     * Convert the ARP packet to a ByteBuffer
     */
    fun toByteBuffer(): ByteBuffer {
        // ARP packet size = 8 bytes for header + addresses
        val size = 8 + hardwareAddressLength * 2 + protocolAddressLength * 2
        val buffer = createNetworkBuffer(size)

        // Hardware type (Ethernet = 1)
        buffer.putShort(hardwareType.toShort())

        // Protocol type (IPv4 = 0x0800)
        buffer.putShort(protocolType.toShort())

        // Hardware address length (MAC = 6)
        buffer.put(hardwareAddressLength.toByte())

        // Protocol address length (IPv4 = 4)
        buffer.put(protocolAddressLength.toByte())

        // Operation (1=request, 2=reply)
        buffer.putShort(operation.toShort())

        // Sender hardware address (MAC)
        buffer.put(senderHardwareAddress)

        // Sender protocol address (IP)
        buffer.put(senderProtocolAddress)

        // Target hardware address (MAC)
        buffer.put(targetHardwareAddress)

        // Target protocol address (IP)
        buffer.put(targetProtocolAddress)

        // Prepare for reading
        buffer.flip()

        return buffer
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ArpPacket

        if (hardwareType != other.hardwareType) return false
        if (protocolType != other.protocolType) return false
        if (hardwareAddressLength != other.hardwareAddressLength) return false
        if (protocolAddressLength != other.protocolAddressLength) return false
        if (operation != other.operation) return false
        if (!senderHardwareAddress.contentEquals(other.senderHardwareAddress)) return false
        if (!senderProtocolAddress.contentEquals(other.senderProtocolAddress)) return false
        if (!targetHardwareAddress.contentEquals(other.targetHardwareAddress)) return false
        if (!targetProtocolAddress.contentEquals(other.targetProtocolAddress)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hardwareType
        result = 31 * result + protocolType
        result = 31 * result + hardwareAddressLength
        result = 31 * result + protocolAddressLength
        result = 31 * result + operation
        result = 31 * result + senderHardwareAddress.contentHashCode()
        result = 31 * result + senderProtocolAddress.contentHashCode()
        result = 31 * result + targetHardwareAddress.contentHashCode()
        result = 31 * result + targetProtocolAddress.contentHashCode()
        return result
    }

    override fun toString(): String {
        val opStr = when (operation) {
            Constants.ARP_OP_REQUEST -> "REQUEST"
            Constants.ARP_OP_REPLY -> "REPLY"
            else -> "UNKNOWN($operation)"
        }

        return "ArpPacket(" +
               "op=$opStr, " +
               "sender=${bytesToMacAddress(senderHardwareAddress)}-${bytesToIpv4(senderProtocolAddress)}, " +
               "target=${bytesToMacAddress(targetHardwareAddress)}-${bytesToIpv4(targetProtocolAddress)})"
    }

    companion object {
        /**
         * Create an ARP request packet
         */
        fun createRequest(
            senderMac: ByteArray,
            senderIp: ByteArray,
            targetIp: ByteArray
        ): ArpPacket {
            // For ARP request, target MAC is all zeros
            val targetMac = ByteArray(6)

            return ArpPacket(
                hardwareType = Constants.ARP_HWTYPE_ETHERNET,
                protocolType = Constants.ETH_TYPE_IP,
                hardwareAddressLength = 6,  // MAC address length
                protocolAddressLength = 4,  // IPv4 address length
                operation = Constants.ARP_OP_REQUEST,
                senderHardwareAddress = senderMac,
                senderProtocolAddress = senderIp,
                targetHardwareAddress = targetMac,
                targetProtocolAddress = targetIp
            )
        }

        /**
         * Create an ARP reply packet
         */
        fun createReply(
            senderMac: ByteArray,
            senderIp: ByteArray,
            targetMac: ByteArray,
            targetIp: ByteArray
        ): ArpPacket {
            return ArpPacket(
                hardwareType = Constants.ARP_HWTYPE_ETHERNET,
                protocolType = Constants.ETH_TYPE_IP,
                hardwareAddressLength = 6,  // MAC address length
                protocolAddressLength = 4,  // IPv4 address length
                operation = Constants.ARP_OP_REPLY,
                senderHardwareAddress = senderMac,
                senderProtocolAddress = senderIp,
                targetHardwareAddress = targetMac,
                targetProtocolAddress = targetIp
            )
        }

        /**
         * Parse an ARP packet from a ByteBuffer
         */
        fun parse(buffer: ByteBuffer): ArpPacket? {
            // Check for minimum ARP packet size (8 bytes + addresses)
            if (buffer.remaining() < 8) {
                return null
            }

            val startPosition = buffer.position()

            // Hardware type
            val hwType = buffer.short.toInt() and 0xFFFF

            // Protocol type
            val protoType = buffer.short.toInt() and 0xFFFF

            // Hardware address length
            val hwAddrLen = buffer.get().toInt() and 0xFF

            // Protocol address length
            val protoAddrLen = buffer.get().toInt() and 0xFF

            // Check if there's enough data for the addresses
            if (buffer.remaining() < 2 + hwAddrLen * 2 + protoAddrLen * 2) {
                // Reset position and return null
                buffer.position(startPosition)
                return null
            }

            // Operation
            val operation = buffer.short.toInt() and 0xFFFF

            // Sender hardware address
            val senderHwAddr = ByteArray(hwAddrLen)
            buffer.get(senderHwAddr)

            // Sender protocol address
            val senderProtoAddr = ByteArray(protoAddrLen)
            buffer.get(senderProtoAddr)

            // Target hardware address
            val targetHwAddr = ByteArray(hwAddrLen)
            buffer.get(targetHwAddr)

            // Target protocol address
            val targetProtoAddr = ByteArray(protoAddrLen)
            buffer.get(targetProtoAddr)

            return ArpPacket(
                hardwareType = hwType,
                protocolType = protoType,
                hardwareAddressLength = hwAddrLen,
                protocolAddressLength = protoAddrLen,
                operation = operation,
                senderHardwareAddress = senderHwAddr,
                senderProtocolAddress = senderProtoAddr,
                targetHardwareAddress = targetHwAddr,
                targetProtocolAddress = targetProtoAddr
            )
        }
    }
}