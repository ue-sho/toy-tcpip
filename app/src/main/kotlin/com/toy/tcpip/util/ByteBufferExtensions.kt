package com.toy.tcpip.util

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Extensions for ByteBuffer to help with network packet manipulation
 */

fun ByteBuffer.getUnsignedByte(): Int = this.get().toInt() and 0xFF

fun ByteBuffer.getUnsignedShort(): Int = this.short.toInt() and 0xFFFF

fun ByteBuffer.getUnsignedInt(): Long = this.int.toLong() and 0xFFFFFFFF

fun ByteBuffer.putUnsignedByte(value: Int): ByteBuffer = this.put(value.toByte())

fun ByteBuffer.putUnsignedShort(value: Int): ByteBuffer = this.putShort(value.toShort())

fun ByteBuffer.putUnsignedInt(value: Long): ByteBuffer = this.putInt(value.toInt())

/**
 * Creates a new ByteBuffer with network byte order (big endian)
 */
fun createNetworkBuffer(capacity: Int): ByteBuffer {
    return ByteBuffer.allocate(capacity).order(ByteOrder.BIG_ENDIAN)
}

/**
 * Calculate Internet Checksum (RFC 1071)
 */
fun calculateChecksum(data: ByteBuffer, offset: Int, length: Int): Int {
    var sum = 0
    val savedPosition = data.position()
    val savedLimit = data.limit()

    try {
        data.position(offset)
        data.limit(offset + length)

        // Process two bytes at a time
        while (data.remaining() > 1) {
            sum += data.getShort().toInt() and 0xFFFF
        }

        // Add leftover byte if any
        if (data.hasRemaining()) {
            sum += (data.get().toInt() and 0xFF) << 8
        }

        // Add carries
        sum = (sum and 0xFFFF) + (sum ushr 16)
        sum = (sum and 0xFFFF) + (sum ushr 16)

        // Take one's complement
        return sum.inv() and 0xFFFF
    } finally {
        data.position(savedPosition)
        data.limit(savedLimit)
    }
}

/**
 * Convert MAC address string to byte array
 */
fun macAddressToBytes(macAddress: String): ByteArray {
    return macAddress.split(":")
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

/**
 * Convert byte array to MAC address string
 */
fun bytesToMacAddress(bytes: ByteArray): String {
    return bytes.joinToString(":") { "%02x".format(it.toInt() and 0xFF) }
}

/**
 * Convert IPv4 address string to integer representation
 */
fun ipv4ToInt(ipv4Address: String): Int {
    val parts = ipv4Address.split(".")
    return ((parts[0].toInt() and 0xFF) shl 24) or
           ((parts[1].toInt() and 0xFF) shl 16) or
           ((parts[2].toInt() and 0xFF) shl 8) or
           (parts[3].toInt() and 0xFF)
}

/**
 * Convert integer to IPv4 address string
 */
fun intToIpv4(ipv4Int: Int): String {
    return "${(ipv4Int ushr 24) and 0xFF}." +
           "${(ipv4Int ushr 16) and 0xFF}." +
           "${(ipv4Int ushr 8) and 0xFF}." +
           "${ipv4Int and 0xFF}"
}

/**
 * Convert IPv4 address string to byte array
 */
fun ipv4ToBytes(ipv4Address: String): ByteArray {
    val parts = ipv4Address.split(".")
    return byteArrayOf(
        parts[0].toInt().toByte(),
        parts[1].toInt().toByte(),
        parts[2].toInt().toByte(),
        parts[3].toInt().toByte()
    )
}

/**
 * Convert byte array to IPv4 address string
 */
fun bytesToIpv4(bytes: ByteArray): String {
    return "${bytes[0].toInt() and 0xFF}." +
           "${bytes[1].toInt() and 0xFF}." +
           "${bytes[2].toInt() and 0xFF}." +
           "${bytes[3].toInt() and 0xFF}"
}