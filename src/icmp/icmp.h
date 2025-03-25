#ifndef ICMP_H
#define ICMP_H

#include <cstdint>
#include <memory>
#include <functional>
#include <vector>
#include <map>
#include <mutex>
#include "../ip/ip.h"
#include "../common/common.h"

// ICMP message types as defined in RFC 792
namespace ICMPType {
    constexpr uint8_t ECHO_REPLY = 0;
    constexpr uint8_t DESTINATION_UNREACHABLE = 3;
    constexpr uint8_t SOURCE_QUENCH = 4;
    constexpr uint8_t REDIRECT = 5;
    constexpr uint8_t ECHO_REQUEST = 8;
    constexpr uint8_t TIME_EXCEEDED = 11;
    constexpr uint8_t PARAMETER_PROBLEM = 12;
    constexpr uint8_t TIMESTAMP_REQUEST = 13;
    constexpr uint8_t TIMESTAMP_REPLY = 14;
    constexpr uint8_t INFORMATION_REQUEST = 15;
    constexpr uint8_t INFORMATION_REPLY = 16;
}

// ICMP destination unreachable codes
namespace ICMPDestinationUnreachableCode {
    constexpr uint8_t NET_UNREACHABLE = 0;
    constexpr uint8_t HOST_UNREACHABLE = 1;
    constexpr uint8_t PROTOCOL_UNREACHABLE = 2;
    constexpr uint8_t PORT_UNREACHABLE = 3;
    constexpr uint8_t FRAGMENTATION_NEEDED = 4;
    constexpr uint8_t SOURCE_ROUTE_FAILED = 5;
}

// ICMP time exceeded codes
namespace ICMPTimeExceededCode {
    constexpr uint8_t TTL_EXCEEDED = 0;
    constexpr uint8_t FRAGMENT_REASSEMBLY_EXCEEDED = 1;
}

// ICMP header structure (RFC 792)
#pragma pack(push, 1)
struct ICMPHeader {
    uint8_t type;      // ICMP message type
    uint8_t code;      // ICMP message code
    uint16_t checksum; // Checksum of ICMP header and data
    union {
        // Echo request/reply
        struct {
            uint16_t identifier;
            uint16_t sequence;
        } echo;

        // Destination unreachable, source quench, time exceeded, parameter problem
        struct {
            uint32_t unused; // Unused for these message types
        } error;

        // Redirect
        struct {
            uint32_t gateway_address;
        } redirect;

        uint32_t raw_data; // Raw access to the 4 bytes
    } un;
};
#pragma pack(pop)

// ICMP packet class
class ICMPPacket {
public:
    // Constructors
    ICMPPacket();
    ICMPPacket(uint8_t type, uint8_t code);

    // Create ICMP packet from buffer
    static std::unique_ptr<ICMPPacket> fromBuffer(const uint8_t* buffer, size_t length);

    // Header field getters/setters
    uint8_t getType() const;
    void setType(uint8_t type);

    uint8_t getCode() const;
    void setCode(uint8_t code);

    uint16_t getChecksum() const;
    void setChecksum(uint16_t checksum);

    // Echo specific
    uint16_t getIdentifier() const;
    void setIdentifier(uint16_t identifier);

    uint16_t getSequence() const;
    void setSequence(uint16_t sequence);

    // Payload handling
    const std::vector<uint8_t>& getPayload() const;
    void setPayload(const uint8_t* data, size_t length);

    // Calculate checksum
    uint16_t calculateChecksum() const;
    void updateChecksum();

    // Serialize packet to buffer
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Get total packet size
    size_t getTotalSize() const;

private:
    ICMPHeader header_;
    std::vector<uint8_t> payload_;
};

// ICMP handler type
using ICMPHandler = std::function<void(const ICMPPacket& packet,
                                      IPv4Address src_ip,
                                      IPv4Address dst_ip)>;

// ICMP layer class
class ICMP {
public:
    // Constructor
    explicit ICMP(std::shared_ptr<IP> ip);

    // Initialize ICMP layer
    bool init();

    // Send ICMP packet
    bool sendPacket(IPv4Address dst_ip, const ICMPPacket& packet);

    // Create and send Echo Request (ping)
    bool sendEchoRequest(IPv4Address dst_ip, uint16_t identifier,
                         uint16_t sequence, const uint8_t* data = nullptr,
                         size_t data_length = 0);

    // Register handler for specific ICMP type
    void registerTypeHandler(uint8_t type, ICMPHandler handler);

    // Unregister handler for specific ICMP type
    void unregisterTypeHandler(uint8_t type);

    // Get IP layer
    std::shared_ptr<IP> getIP() const;

private:
    // IP packet handler (called by IP layer)
    void handleIPPacket(const uint8_t* data, size_t length,
                       IPv4Address src_ip, IPv4Address dst_ip);

    // Handle Echo Request (ping)
    void handleEchoRequest(const ICMPPacket& request,
                          IPv4Address src_ip, IPv4Address dst_ip);

    // Send ICMP error message
    bool sendErrorMessage(uint8_t type, uint8_t code,
                         IPv4Address dst_ip, const uint8_t* original_packet,
                         size_t original_length);

    std::shared_ptr<IP> ip_; // IP layer
    std::map<uint8_t, ICMPHandler> type_handlers_; // ICMP type handlers
    std::mutex handlers_mutex_; // Mutex for type handlers
};

#endif // ICMP_H