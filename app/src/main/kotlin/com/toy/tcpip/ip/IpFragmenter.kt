package com.toy.tcpip.ip

import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.createNetworkBuffer
import java.nio.ByteBuffer
import java.util.ArrayList

/**
 * Handles IP packet fragmentation and reassembly
 */
class IpFragmenter {

    // Data structure for holding fragment information
    private data class FragmentKey(
        val id: Int,
        val protocol: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as FragmentKey

            if (id != other.id) return false
            if (protocol != other.protocol) return false
            if (!sourceAddress.contentEquals(other.sourceAddress)) return false
            if (!destinationAddress.contentEquals(other.destinationAddress)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = id
            result = 31 * result + protocol
            result = 31 * result + sourceAddress.contentHashCode()
            result = 31 * result + destinationAddress.contentHashCode()
            return result
        }
    }

    private data class Fragment(
        val packet: IpPacket,
        val offset: Int,
        val moreFragments: Boolean,
        val data: ByteBuffer,
        val timestamp: Long = System.currentTimeMillis()
    )

    // Map of fragment key to list of fragments
    private val fragments = mutableMapOf<FragmentKey, MutableList<Fragment>>()

    // Fragment timeout in milliseconds (30 seconds)
    private val fragmentTimeout = 30000L

    /**
     * Clean up old fragments
     */
    fun cleanupFragments() {
        val now = System.currentTimeMillis()

        val iterator = fragments.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()

            // Remove this entry if all fragments are old
            if (entry.value.all { now - it.timestamp > fragmentTimeout }) {
                iterator.remove()
            }
        }
    }

    /**
     * Fragment an IP packet into smaller packets if it exceeds the MTU
     *
     * @param packet The IP packet to fragment
     * @param mtu The Maximum Transmission Unit (in bytes)
     * @return List of fragmented packets, or the original packet if no fragmentation is needed
     */
    fun fragment(packet: IpPacket, mtu: Int): List<IpPacket> {
        val headerSize = packet.ihl * 4
        val maxPayloadSize = mtu - headerSize

        // Don't fragment if the packet fits within MTU or if DF flag is set
        if (packet.totalLength <= mtu || (packet.flags and IpPacket.FLAG_DONT_FRAGMENT) != 0) {
            return listOf(packet)
        }

        val fragments = ArrayList<IpPacket>()
        val payloadBuffer = packet.payload.duplicate()
        val payloadSize = payloadBuffer.remaining()

        // Fragment data must be aligned on 8-byte boundaries
        val fragmentDataSize = (maxPayloadSize / 8) * 8
        var offset = 0

        while (offset < payloadSize) {
            // Calculate this fragment's size
            val currentSize = minOf(fragmentDataSize, payloadSize - offset)
            val moreFragments = offset + currentSize < payloadSize

            // Create fragment payload
            val fragmentPayload = createNetworkBuffer(currentSize)
            val limitPos = payloadBuffer.position() + currentSize
            val tempBuffer = payloadBuffer.duplicate()
            tempBuffer.limit(limitPos)
            fragmentPayload.put(tempBuffer)
            fragmentPayload.flip()

            // Advance payload buffer position
            payloadBuffer.position(limitPos)

            // Create fragment packet
            val fragmentPacket = IpPacket(
                ihl = packet.ihl,
                dscp = packet.dscp,
                ecn = packet.ecn,
                totalLength = headerSize + currentSize,
                identification = packet.identification,
                flags = if (moreFragments) packet.flags or IpPacket.FLAG_MORE_FRAGMENTS else packet.flags and IpPacket.FLAG_MORE_FRAGMENTS.inv(),
                fragmentOffset = (offset / 8) + packet.fragmentOffset,  // Offset is in 8-byte units
                ttl = packet.ttl,
                protocol = packet.protocol,
                sourceAddress = packet.sourceAddress,
                destinationAddress = packet.destinationAddress,
                options = packet.options,
                payload = fragmentPayload
            )

            fragments.add(fragmentPacket)
            offset += currentSize
        }

        return fragments
    }

    /**
     * Process an IP fragment and try to reassemble the original packet
     *
     * @param packet The IP fragment
     * @return Reassembled IP packet if complete, null if still waiting for more fragments
     */
    fun reassemble(packet: IpPacket): IpPacket? {
        // Skip if this is not a fragment
        if (packet.fragmentOffset == 0 && (packet.flags and IpPacket.FLAG_MORE_FRAGMENTS) == 0) {
            return packet
        }

        val key = FragmentKey(
            id = packet.identification,
            protocol = packet.protocol,
            sourceAddress = packet.sourceAddress,
            destinationAddress = packet.destinationAddress
        )

        // Add this fragment to our list
        val offset = packet.fragmentOffset * 8  // Convert from 8-byte units to bytes
        val moreFragments = (packet.flags and IpPacket.FLAG_MORE_FRAGMENTS) != 0
        val data = packet.payload.duplicate()

        val fragmentList = fragments.getOrPut(key) { mutableListOf() }
        fragmentList.add(Fragment(packet, offset, moreFragments, data))

        // Try to reassemble
        val reassembled = tryReassemble(key, fragmentList)

        // Clean up if we succeeded
        if (reassembled != null) {
            fragments.remove(key)
        }

        return reassembled
    }

    /**
     * Try to reassemble a complete packet from fragments
     */
    private fun tryReassemble(key: FragmentKey, fragments: List<Fragment>): IpPacket? {
        // Make sure we have the final fragment
        if (fragments.none { !it.moreFragments }) {
            return null
        }

        // Sort fragments by offset
        val sortedFragments = fragments.sortedBy { it.offset }

        // Check for holes in the sequence
        var expectedOffset = 0
        for (fragment in sortedFragments) {
            if (fragment.offset != expectedOffset) {
                return null  // Gap detected
            }
            expectedOffset = fragment.offset + fragment.data.remaining()

            // If this is the last fragment, we're done
            if (!fragment.moreFragments) {
                break
            }
        }

        // Calculate total packet size
        val lastFragment = sortedFragments.first { !it.moreFragments }
        val totalPayloadSize = lastFragment.offset + lastFragment.data.remaining()

        // Sample packet to base reassembled packet on
        val samplePacket = sortedFragments.first().packet

        // Create payload buffer
        val reassembledPayload = createNetworkBuffer(totalPayloadSize)

        // Copy data from each fragment in order
        for (fragment in sortedFragments) {
            val fragmentData = fragment.data.duplicate()
            reassembledPayload.position(fragment.offset)
            reassembledPayload.put(fragmentData)

            // If this is the last fragment, we're done
            if (!fragment.moreFragments) {
                break
            }
        }

        // Prepare buffer for reading
        reassembledPayload.flip()

        // Create reassembled packet
        return IpPacket(
            ihl = samplePacket.ihl,
            dscp = samplePacket.dscp,
            ecn = samplePacket.ecn,
            totalLength = samplePacket.ihl * 4 + totalPayloadSize,
            identification = samplePacket.identification,
            flags = samplePacket.flags and IpPacket.FLAG_MORE_FRAGMENTS.inv(),  // Clear MF flag
            fragmentOffset = 0,  // No offset in reassembled packet
            ttl = samplePacket.ttl,
            protocol = samplePacket.protocol,
            sourceAddress = samplePacket.sourceAddress,
            destinationAddress = samplePacket.destinationAddress,
            options = samplePacket.options,
            payload = reassembledPayload
        )
    }
}