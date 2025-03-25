# ARP Protocol Implementation

## Overview

The Address Resolution Protocol (ARP) implementation provides the functionality to resolve IP addresses to MAC addresses. It is a critical component for IP-based communication over Ethernet networks.

## Architecture

The implementation consists of several key components:

1. **ARPPacket Class**
   - Represents an ARP packet with header and methods
   - Provides serialization and deserialization

2. **ARP Class**
   - Manages the ARP protocol functionality
   - Maintains the ARP cache
   - Handles sending and processing ARP requests/replies

3. **Cache and State Management**
   - ARP cache with timeout
   - Pending request handling
   - Retry mechanism

## Dependencies

The ARP implementation depends on:
- [Ethernet Layer](ethernet.md) - for sending and receiving ARP packets
- Network device - for accessing the network interface

## IPv4 Address Representation

IPv4 addresses are represented as 32-bit unsigned integers:

```cpp
using IPv4Address = uint32_t;

namespace IP {
    // Special IPv4 addresses
    constexpr IPv4Address ZERO = 0x00000000;
    constexpr IPv4Address BROADCAST = 0xFFFFFFFF;

    // Utility functions
    std::string toString(IPv4Address ip);
    IPv4Address fromString(const std::string& ip_str);
}
```

## ARP Operations

The implementation supports the following ARP operations:

```cpp
enum class ARPOperation : uint16_t {
    REQUEST = 1,
    REPLY = 2
};
```

## ARP Header Structure

The ARP header is defined as a packed structure:

```cpp
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
```

## ARPPacket Class

The `ARPPacket` class provides the following functionality:

```cpp
class ARPPacket {
public:
    // Constructors
    ARPPacket();
    ARPPacket(ARPOperation op, const MacAddress& sender_mac, IPv4Address sender_ip,
              const MacAddress& target_mac, IPv4Address target_ip);

    // Create packet from raw buffer
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

    // Serialization
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Size calculation
    size_t getSize() const;

private:
    ARPHeader header_;
};
```

## ARP Cache Management

The implementation includes a sophisticated ARP cache:

```cpp
// ARP entry states
enum class ARPEntryState {
    INCOMPLETE,  // Resolution in progress
    RESOLVED,    // Successfully resolved
    PERMANENT    // Static entry
};

// ARP cache entry
struct ARPEntry {
    MacAddress mac;      // MAC address
    ARPEntryState state; // Entry state
    std::chrono::steady_clock::time_point timestamp; // Last update time
};
```

## ARP Resolution Callbacks

Asynchronous ARP resolution is supported through callbacks:

```cpp
// ARP resolution callback type
using ARPResolveCallback = std::function<void(IPv4Address ip, const MacAddress& mac, bool success)>;

// Pending ARP request structure
struct PendingARPRequest {
    IPv4Address ip;                     // IP address to resolve
    std::vector<ARPResolveCallback> callbacks; // Callbacks to call on completion
    std::chrono::steady_clock::time_point timestamp; // Request time
    int retries;                        // Number of retries
};
```

## ARP Class

The `ARP` class manages the ARP protocol:

```cpp
class ARP {
public:
    // Constructor
    ARP(std::shared_ptr<Ethernet> ethernet, IPv4Address local_ip);

    // Initialize the ARP module
    bool init();

    // Resolve MAC address for an IP address
    bool resolve(IPv4Address ip, ARPResolveCallback callback = nullptr);

    // Look up MAC address in cache
    bool lookup(IPv4Address ip, MacAddress& mac);

    // Add/update an entry in the cache
    void addEntry(IPv4Address ip, const MacAddress& mac, ARPEntryState state = ARPEntryState::RESOLVED);

    // Remove an entry from the cache
    void removeEntry(IPv4Address ip);

    // Clear the cache
    void clearCache();

    // Process pending requests (timeouts, retries)
    void processPendingRequests();

    // Check cache timeouts
    void checkCacheTimeout();

    // Set local IP address
    void setLocalIP(IPv4Address ip);

    // Get local IP address
    IPv4Address getLocalIP() const;

private:
    // ARP packet handler
    void handleARPPacket(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac);

    // Send an ARP request
    void sendARPRequest(IPv4Address target_ip);

    // Send an ARP reply
    void sendARPReply(IPv4Address target_ip, const MacAddress& target_mac);

    // Complete a pending request
    void completePendingRequest(IPv4Address ip, const MacAddress& mac, bool success);

    // Timeouts and retry parameters
    static constexpr std::chrono::seconds CACHE_TIMEOUT{60 * 20}; // 20 minutes
    static constexpr std::chrono::seconds REQUEST_TIMEOUT{1};    // 1 second
    static constexpr int MAX_RETRIES = 3;                        // Max retry count

    // Member variables
    std::shared_ptr<Ethernet> ethernet_;    // Ethernet layer
    IPv4Address local_ip_;                  // Local IP address
    std::map<IPv4Address, ARPEntry> cache_; // ARP cache
    std::vector<PendingARPRequest> pending_requests_; // Pending requests
    std::mutex cache_mutex_;               // Cache access mutex
};
```

## Key Features

1. **Automatic Resolution**: Simple API to resolve IP addresses to MAC addresses.
2. **Caching**: Maintains a cache of resolved addresses with timeout.
3. **Asynchronous Resolution**: Supports callbacks for non-blocking address resolution.
4. **Retry Mechanism**: Automatically retries failed requests.
5. **Thread Safety**: The cache is protected by a mutex for thread-safe access.
6. **Efficient Handling**: Responds to ARP requests and processes ARP replies.

## Usage Example

```cpp
#include "arp.h"
#include "ethernet.h"
#include "raw_socket_device.h"
#include <iostream>
#include <memory>

// ARP resolution callback
void onARPResolved(IPv4Address ip, const MacAddress& mac, bool success) {
    if (success) {
        std::cout << "IP " << IP::toString(ip) << " resolved to MAC "
                  << EthernetUtils::macToString(mac) << std::endl;
    } else {
        std::cout << "Failed to resolve IP " << IP::toString(ip) << std::endl;
    }
}

int main() {
    try {
        // Create and initialize network device
        auto device = std::make_shared<RawSocketDevice>("eth0");

        // Create and initialize Ethernet layer
        auto ethernet = std::make_shared<Ethernet>(device);
        ethernet->init();

        // Create and initialize ARP module
        IPv4Address local_ip = IP::fromString("192.168.1.100");
        ARP arp(ethernet, local_ip);
        arp.init();

        // Resolve an IP address
        IPv4Address target_ip = IP::fromString("192.168.1.1");
        arp.resolve(target_ip, onARPResolved);

        // Main loop
        while (true) {
            ethernet->receiveFrames(100); // 100ms timeout
            arp.processPendingRequests();
            arp.checkCacheTimeout();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Implementation Details

1. **Byte Order**: All multi-byte fields are stored in network byte order.
2. **Standard Compliance**: Implements the ARP protocol as defined in RFC 826.
3. **Timeout Management**: Entries are automatically removed from the cache after 20 minutes.
4. **Resolution Process**: ARP requests are sent up to 3 times with 1-second intervals.
5. **Thread Safety**: The cache is protected with a mutex for thread-safe access.

## Limitations

1. The implementation only supports IPv4 addresses.
2. It does not implement Proxy ARP.
3. It does not support gratuitous ARP.
4. There is no built-in IPv6 Neighbor Discovery Protocol (NDP) implementation.

## Future Improvements

1. Add support for gratuitous ARP.
2. Implement Proxy ARP functionality.
3. Add support for IPv6 Neighbor Discovery Protocol.
4. Add static ARP table configuration support.
5. Implement ARP poisoning detection and prevention.