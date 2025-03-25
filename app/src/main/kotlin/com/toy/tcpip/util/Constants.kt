package com.toy.tcpip.util

/**
 * Protocol constants and configuration values
 */
object Constants {
    // Ethernet frame type codes
    const val ETH_TYPE_IP: Int = 0x0800
    const val ETH_TYPE_ARP: Int = 0x0806
    const val ETH_TYPE_IPV6: Int = 0x86DD

    // Ethernet header size in bytes
    const val ETH_HEADER_SIZE: Int = 14

    // Maximum Transmission Unit (bytes) - standard Ethernet
    const val DEFAULT_MTU: Int = 1500

    // Maximum segment size (TCP data) = MTU - IP header - TCP header
    const val DEFAULT_MSS: Int = DEFAULT_MTU - 20 - 20

    // ARP hardware types
    const val ARP_HWTYPE_ETHERNET: Int = 1

    // ARP operation types
    const val ARP_OP_REQUEST: Int = 1
    const val ARP_OP_REPLY: Int = 2

    // IP Protocol numbers
    const val IP_PROTO_ICMP: Int = 1
    const val IP_PROTO_TCP: Int = 6
    const val IP_PROTO_UDP: Int = 17

    // IP header size in bytes (without options)
    const val IP_HEADER_MIN_SIZE: Int = 20

    // Default IP TTL (Time to Live)
    const val DEFAULT_IP_TTL: Int = 64

    // TCP header size in bytes (without options)
    const val TCP_HEADER_MIN_SIZE: Int = 20

    // TCP flags
    const val TCP_FLAG_FIN: Int = 0x01
    const val TCP_FLAG_SYN: Int = 0x02
    const val TCP_FLAG_RST: Int = 0x04
    const val TCP_FLAG_PSH: Int = 0x08
    const val TCP_FLAG_ACK: Int = 0x10
    const val TCP_FLAG_URG: Int = 0x20

    // TCP states (RFC 793)
    const val TCP_STATE_CLOSED: Int = 0
    const val TCP_STATE_LISTEN: Int = 1
    const val TCP_STATE_SYN_SENT: Int = 2
    const val TCP_STATE_SYN_RECEIVED: Int = 3
    const val TCP_STATE_ESTABLISHED: Int = 4
    const val TCP_STATE_FIN_WAIT_1: Int = 5
    const val TCP_STATE_FIN_WAIT_2: Int = 6
    const val TCP_STATE_CLOSE_WAIT: Int = 7
    const val TCP_STATE_CLOSING: Int = 8
    const val TCP_STATE_LAST_ACK: Int = 9
    const val TCP_STATE_TIME_WAIT: Int = 10

    // TCP socket timeout values (in milliseconds)
    const val TCP_USER_TIMEOUT: Long = 30000L  // 30 seconds
    const val TCP_RETRANSMISSION_TIMEOUT: Long = 3000L  // 3 seconds
    const val TCP_TIME_WAIT_TIMEOUT: Long = 60000L  // 60 seconds (2MSL)

    // Socket options
    const val SO_RCVBUF: Int = 65536  // Receive buffer size
    const val SO_SNDBUF: Int = 65536  // Send buffer size
    const val SO_MAX_CONN_BACKLOG: Int = 128  // Maximum connection backlog

    // Subnet mask bit patterns
    val IP_NETMASK = mapOf(
        0 to 0x00000000,
        1 to 0x80000000,
        2 to 0xC0000000,
        3 to 0xE0000000,
        4 to 0xF0000000,
        5 to 0xF8000000,
        6 to 0xFC000000,
        7 to 0xFE000000,
        8 to 0xFF000000,
        9 to 0xFF800000,
        10 to 0xFFC00000,
        11 to 0xFFE00000,
        12 to 0xFFF00000,
        13 to 0xFFF80000,
        14 to 0xFFFC0000,
        15 to 0xFFFE0000,
        16 to 0xFFFF0000,
        17 to 0xFFFF8000,
        18 to 0xFFFFC000,
        19 to 0xFFFFE000,
        20 to 0xFFFFF000,
        21 to 0xFFFFF800,
        22 to 0xFFFFFC00,
        23 to 0xFFFFFE00,
        24 to 0xFFFFFF00,
        25 to 0xFFFFFF80,
        26 to 0xFFFFFFC0,
        27 to 0xFFFFFFE0,
        28 to 0xFFFFFFF0,
        29 to 0xFFFFFFF8,
        30 to 0xFFFFFFFC,
        31 to 0xFFFFFFFE,
        32 to 0xFFFFFFFF
    )
}