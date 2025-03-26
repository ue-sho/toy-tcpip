#ifndef IP_H
#define IP_H

#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <functional>
#include <chrono>
#include "../arp/arp.h"
#include "../ethernet/ethernet.h"
#include "../common/common.h"

// IP Protocol Version
constexpr uint8_t IPV4 = 4;

// Maximum IP packet size
constexpr size_t IP_MAX_PACKET_SIZE = 65535;

// Default IP TTL (Time to Live)
constexpr uint8_t IP_DEFAULT_TTL = 64;

// IP header structure (as per RFC 791)
#pragma pack(push, 1)
struct IPHeader {
    uint8_t version_ihl;        // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t dscp_ecn;           // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;      // Total length (header + data)
    uint16_t identification;    // Identification
    uint16_t flags_fragment;    // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;                // Time to Live
    uint8_t protocol;           // Protocol
    uint16_t checksum;          // Header checksum
    IPv4Address src_ip;         // Source IP address
    IPv4Address dst_ip;         // Destination IP address
    // Options may follow
};
#pragma pack(pop)

// IP header size constants
constexpr size_t IP_HEADER_MIN_SIZE = sizeof(IPHeader);
constexpr size_t IP_HEADER_MAX_SIZE = IP_HEADER_MIN_SIZE + 40; // Max 40 bytes of options

// IP protocol numbers (as per IANA assignments)
namespace IPProtocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
}

// Flags for IP header
namespace IPFlags {
    constexpr uint16_t RESERVED = 0x8000;    // Reserved (must be zero)
    constexpr uint16_t DONT_FRAGMENT = 0x4000; // Don't Fragment
    constexpr uint16_t MORE_FRAGMENTS = 0x2000; // More Fragments
    constexpr uint16_t FRAGMENT_OFFSET_MASK = 0x1FFF; // Fragment Offset mask
}

// IP packet class
class IPPacket {
public:
    // Constructors
    IPPacket();
    IPPacket(uint8_t protocol, IPv4Address src_ip, IPv4Address dst_ip);

    // Create IP packet from buffer
    static std::unique_ptr<IPPacket> fromBuffer(const uint8_t* buffer, size_t length);

    // Header field getters/setters
    uint8_t getVersion() const;
    void setVersion(uint8_t version);

    uint8_t getHeaderLength() const; // In 32-bit words
    void setHeaderLength(uint8_t ihl);

    uint8_t getDSCP() const;
    void setDSCP(uint8_t dscp);

    uint8_t getECN() const;
    void setECN(uint8_t ecn);

    uint16_t getTotalLength() const;
    void setTotalLength(uint16_t length);

    uint16_t getIdentification() const;
    void setIdentification(uint16_t id);

    bool getDontFragment() const;
    void setDontFragment(bool df);

    bool getMoreFragments() const;
    void setMoreFragments(bool mf);

    uint16_t getFragmentOffset() const;
    void setFragmentOffset(uint16_t offset);

    uint8_t getTTL() const;
    void setTTL(uint8_t ttl);

    uint8_t getProtocol() const;
    void setProtocol(uint8_t protocol);

    uint16_t getChecksum() const;
    void setChecksum(uint16_t checksum);

    IPv4Address getSourceIP() const;
    void setSourceIP(IPv4Address ip);

    IPv4Address getDestinationIP() const;
    void setDestinationIP(IPv4Address ip);

    // Payload handling
    const std::vector<uint8_t>& getPayload() const;
    void setPayload(const uint8_t* data, size_t length);

    // Calculate header checksum
    uint16_t calculateChecksum() const;
    void updateChecksum();

    // Serialize packet to buffer
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Get header size in bytes
    size_t getHeaderSize() const;

    // Get total packet size
    size_t getTotalSize() const;

private:
    IPHeader header_;
    std::vector<uint8_t> payload_;
};

// IP fragment entry
struct IPFragmentEntry {
    uint16_t id;                // Fragment identification
    IPv4Address src_ip;         // Source IP
    IPv4Address dst_ip;         // Destination IP
    uint8_t protocol;           // Protocol
    std::vector<uint8_t> data;  // Reassembled data
    std::vector<bool> received; // Bit field for received fragments
    size_t total_length;        // Total expected length
    std::chrono::steady_clock::time_point timestamp; // Last fragment time

    IPFragmentEntry(uint16_t frag_id, IPv4Address source, IPv4Address dest, uint8_t proto)
        : id(frag_id), src_ip(source), dst_ip(dest), protocol(proto),
          total_length(0), timestamp(std::chrono::steady_clock::now()) {}
};

// Protocol handler type
using IPProtocolHandler = std::function<void(const uint8_t* data, size_t length,
                                           IPv4Address src_ip, IPv4Address dst_ip)>;

// IP send completion callback type
using IPSendCallback = std::function<void(bool success, IPv4Address dst_ip)>;

// IP options for sending
struct IPSendOptions {
    bool dont_fragment;     // Set Don't Fragment flag
    uint8_t ttl;            // Time to Live
    uint8_t dscp;           // DSCP (Differentiated Services Code Point)
    uint8_t ecn;            // ECN (Explicit Congestion Notification)

    IPSendOptions()
        : dont_fragment(false), ttl(IP_DEFAULT_TTL), dscp(0), ecn(0) {}
};

// IP layer class
class IP {
public:
    // Constructor
    IP(std::shared_ptr<Ethernet> ethernet, std::shared_ptr<ARP> arp,
           IPv4Address local_ip);

    // Initialize IP layer
    bool init();

    // Send IP packet (synchronous version)
    bool sendPacket(IPv4Address dst_ip, uint8_t protocol,
                   const uint8_t* data, size_t length,
                   const IPSendOptions& options = IPSendOptions());

    // Send IP packet (asynchronous version with callback)
    void sendPacketAsync(IPv4Address dst_ip, uint8_t protocol,
                       const uint8_t* data, size_t length,
                       IPSendCallback callback,
                       const IPSendOptions& options = IPSendOptions());

    // Register protocol handler
    void registerProtocolHandler(uint8_t protocol, IPProtocolHandler handler);

    // Unregister protocol handler
    void unregisterProtocolHandler(uint8_t protocol);

    // Get local IP address
    IPv4Address getLocalIP() const;

    // Set local IP address
    void setLocalIP(IPv4Address ip);

    // Check if IP address is local
    bool isLocalIP(IPv4Address ip) const;

    // Process IP fragment timeouts
    void processFragmentTimeouts();

    // Process ARP timeouts
    void processTimeouts();

private:
    // Internal send function (handles both sync and async cases)
    bool sendPacketInternal(IPv4Address dst_ip, uint8_t protocol,
                          const uint8_t* data, size_t length,
                          const MacAddress& dst_mac,
                          const IPSendOptions& options);

    // IP packet handler (called by Ethernet layer)
    void handleIPPacket(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac);

    // Process received IP packet
    void processIPPacket(std::unique_ptr<IPPacket> packet, size_t length);

    // Handle fragmented IP packet
    bool handleFragment(std::unique_ptr<IPPacket> packet);

    // Try to reassemble fragments
    bool tryReassemble(IPFragmentEntry& entry);

    // Generate IP identification
    uint16_t generateIPId();

    // Fragment parameters
    static constexpr std::chrono::seconds FRAGMENT_TIMEOUT{30}; // Fragment timeout

    // IP identification counter
    uint16_t ip_id_counter_;

    // References to lower layers
    std::shared_ptr<Ethernet> ethernet_;
    std::shared_ptr<ARP> arp_;

    // Local IP address
    IPv4Address local_ip_;

    // Protocol handlers
    std::map<uint8_t, IPProtocolHandler> protocol_handlers_;

    // IP fragment reassembly
    std::vector<IPFragmentEntry> fragment_entries_;
    std::mutex fragment_mutex_;
};

// IP checksum calculation utility
uint16_t calculateIPChecksum(const void* data, size_t length);

#endif // IP_H