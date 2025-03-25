#ifndef ARP_H
#define ARP_H

#include <cstdint>
#include <map>
#include <vector>
#include <memory>
#include <chrono>
#include <mutex>
#include <functional>
#include "../ethernet/ethernet.h"
#include "../common/common.h"

// ARP operation codes
enum class ARPOperation : uint16_t {
    REQUEST = 1,
    REPLY = 2
};

// ARP header structure (ARP over Ethernet)
#pragma pack(push, 1)
struct ARPHeader {
    uint16_t hardware_type;     // Hardware type (Ethernet = 1)
    uint16_t protocol_type;     // Protocol type (IPv4 = 0x0800)
    uint8_t hardware_size;      // Hardware address size (Ethernet MAC = 6)
    uint8_t protocol_size;      // Protocol address size (IPv4 = 4)
    uint16_t operation;         // Operation (REQUEST = 1, REPLY = 2)
    MacAddress sender_mac;      // Sender MAC address
    IPv4Address sender_ip;      // Sender IP address
    MacAddress target_mac;      // Target MAC address
    IPv4Address target_ip;      // Target IP address
};
#pragma pack(pop)

// ARP packet class
class ARPPacket {
public:
    // Constructors
    ARPPacket();
    ARPPacket(ARPOperation op, const MacAddress& sender_mac, IPv4Address sender_ip,
              const MacAddress& target_mac, IPv4Address target_ip);

    // Create ARP packet from buffer
    static std::unique_ptr<ARPPacket> fromBuffer(const uint8_t* buffer, size_t length);

    // Field getters/setters
    ARPOperation getOperation() const;
    void setOperation(ARPOperation op);

    const MacAddress& getSenderMAC() const;
    void setSenderMAC(const MacAddress& mac);

    IPv4Address getSenderIP() const;
    void setSenderIP(IPv4Address ip);

    const MacAddress& getTargetMAC() const;
    void setTargetMAC(const MacAddress& mac);

    IPv4Address getTargetIP() const;
    void setTargetIP(IPv4Address ip);

    // Serialize packet to buffer
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Get packet size
    size_t getSize() const;

private:
    ARPHeader header_;
};

// ARP entry states
enum class ARPEntryState {
    INCOMPLETE,  // Resolution in progress
    RESOLVED,    // Successfully resolved
    PERMANENT    // Static entry
};

// ARP cache entry
struct ARPEntry {
    MacAddress mac;      // MAC address
    ARPEntryState state; // State
    std::chrono::steady_clock::time_point timestamp; // Last update time

    ARPEntry() : state(ARPEntryState::INCOMPLETE),
                 timestamp(std::chrono::steady_clock::now()) {}

    ARPEntry(const MacAddress& mac_addr, ARPEntryState entry_state)
        : mac(mac_addr),
          state(entry_state),
          timestamp(std::chrono::steady_clock::now()) {}
};

// ARP resolution callback type
using ARPResolveCallback = std::function<void(IPv4Address ip, const MacAddress& mac, bool success)>;

// Pending ARP request
struct PendingARPRequest {
    IPv4Address ip;                    // IP address to resolve
    std::vector<ARPResolveCallback> callbacks; // Callbacks to call on completion
    std::chrono::steady_clock::time_point timestamp; // Request time
    int retries;                       // Retry count

    PendingARPRequest(IPv4Address ip_addr)
        : ip(ip_addr),
          timestamp(std::chrono::steady_clock::now()),
          retries(0) {}
};

// ARP module
class ARP {
public:
    // Constructor
    ARP(std::shared_ptr<Ethernet> ethernet, IPv4Address local_ip);

    // Initialize ARP module
    bool init();

    // Resolve MAC address for IP
    bool resolve(IPv4Address ip, ARPResolveCallback callback = nullptr);

    // Lookup MAC address in cache
    bool lookup(IPv4Address ip, MacAddress& mac);

    // Add entry to cache
    void addEntry(IPv4Address ip, const MacAddress& mac, ARPEntryState state = ARPEntryState::RESOLVED);

    // Remove entry from ARP cache
    void removeEntry(IPv4Address ip);

    // Clear ARP cache
    void clearCache();

    // Process pending requests
    void processPendingRequests();

    // Check ARP cache entries for timeout
    void checkCacheTimeout();

    // Set local IP address
    void setLocalIP(IPv4Address ip);

    // Get local IP address
    IPv4Address getLocalIP() const;

private:
    // ARP packet handler
    void handleARPPacket(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac);

    // Send ARP request
    void sendARPRequest(IPv4Address target_ip);

    // Send ARP reply
    void sendARPReply(IPv4Address target_ip, const MacAddress& target_mac);

    // Complete pending request
    void completePendingRequest(IPv4Address ip, const MacAddress& mac, bool success);

    // Entry timeout constants
    static constexpr std::chrono::seconds CACHE_TIMEOUT{60 * 20}; // 20 minutes
    static constexpr std::chrono::seconds REQUEST_TIMEOUT{1};    // 1 second
    static constexpr int MAX_RETRIES = 3;                        // Maximum retry count

    std::shared_ptr<Ethernet> ethernet_;    // Ethernet layer
    IPv4Address local_ip_;                  // Local IP address

    std::map<IPv4Address, ARPEntry> cache_; // ARP cache
    std::vector<PendingARPRequest> pending_requests_; // Pending requests

    std::mutex cache_mutex_;               // Mutex for cache access
};

#endif // ARP_H