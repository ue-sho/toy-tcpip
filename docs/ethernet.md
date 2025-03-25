# Ethernet Layer Implementation

## Overview

The Ethernet layer implementation provides the functionality to create, send, receive, and process Ethernet frames. It serves as the foundation for higher-level protocols like IP and ARP.

## Architecture

The implementation consists of several key components:

1. **EthernetFrame Class**
   - Represents an Ethernet frame with header and payload
   - Provides methods for serialization and deserialization

2. **Ethernet Class**
   - Manages the Ethernet layer functionality
   - Handles sending and receiving frames
   - Routes received frames to appropriate protocol handlers

3. **Utility Functions**
   - MAC address manipulation
   - Byte order conversion

## Dependencies

The Ethernet implementation depends on the NetworkDevice interface (see [Raw Socket Implementation](raw_socket.md)) for sending and receiving raw packets.

## Ethernet Types

The implementation supports various Ethernet frame types:

```cpp
enum class EtherType : uint16_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    // Additional types can be added as needed
};
```

## MAC Address Representation

MAC addresses are represented as a fixed-size array of 6 bytes:

```cpp
using MacAddress = std::array<uint8_t, 6>;

// Special MAC addresses
namespace MAC {
    const MacAddress BROADCAST = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const MacAddress ZERO = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}
```

## Ethernet Header Structure

The Ethernet header is defined as a packed structure:

```cpp
#pragma pack(push, 1)
struct EthernetHeader {
    MacAddress dst_mac;     // Destination MAC address
    MacAddress src_mac;     // Source MAC address
    uint16_t ether_type;    // Protocol type (in network byte order)
};
#pragma pack(pop)
```

## Size Constants

The implementation defines several size constants:

```cpp
constexpr size_t ETHERNET_HEADER_SIZE = sizeof(EthernetHeader);
constexpr size_t ETHERNET_MIN_FRAME_SIZE = 60; // Without FCS
constexpr size_t ETHERNET_MAX_FRAME_SIZE = 1514; // Without FCS
constexpr size_t ETHERNET_MTU = ETHERNET_MAX_FRAME_SIZE - ETHERNET_HEADER_SIZE;
```

## EthernetFrame Class

The `EthernetFrame` class provides the following functionality:

```cpp
class EthernetFrame {
public:
    // Constructors
    EthernetFrame();
    EthernetFrame(const MacAddress& dst, const MacAddress& src, EtherType type);

    // Create frame from raw buffer
    static std::unique_ptr<EthernetFrame> fromBuffer(const uint8_t* buffer, size_t length);

    // Header access methods
    const MacAddress& getDestinationMac() const;
    void setDestinationMac(const MacAddress& mac);

    const MacAddress& getSourceMac() const;
    void setSourceMac(const MacAddress& mac);

    EtherType getEtherType() const;
    void setEtherType(EtherType type);

    // Payload handling
    const std::vector<uint8_t>& getPayload() const;
    void setPayload(const uint8_t* data, size_t length);

    // Serialization
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Size calculation
    size_t getTotalSize() const;

private:
    EthernetHeader header_;
    std::vector<uint8_t> payload_;
};
```

## Ethernet Class

The `Ethernet` class manages the Ethernet layer:

```cpp
class Ethernet {
public:
    // Protocol handler type
    using ProtocolHandler = std::function<void(const uint8_t*, size_t, const MacAddress&, const MacAddress&)>;

    // Constructor
    explicit Ethernet(std::shared_ptr<NetworkDevice> device);

    // Initialize the Ethernet layer
    bool init();

    // Send a frame
    bool sendFrame(const MacAddress& dst_mac, EtherType type, const uint8_t* data, size_t length);

    // Receive and process frames
    void receiveFrames(int timeout_ms = 0);

    // Register protocol handlers
    void registerHandler(EtherType type, ProtocolHandler handler);

    // Get device MAC address
    MacAddress getMacAddress() const;

private:
    std::shared_ptr<NetworkDevice> device_;
    std::map<uint16_t, ProtocolHandler> handlers_;

    // Packet receive callback
    static void packetReceiveCallback(uint8_t* buffer, size_t length, void* arg);
};
```

## Utility Functions

The implementation provides several utility functions:

```cpp
namespace EthernetUtils {
    // Convert MAC address to string
    std::string macToString(const MacAddress& mac);

    // Convert string to MAC address
    MacAddress stringToMac(const std::string& mac_str);

    // Network to host byte order conversion
    uint16_t netToHost16(uint16_t netshort);

    // Host to network byte order conversion
    uint16_t hostToNet16(uint16_t hostshort);
}
```

## Key Features

1. **Frame Creation**: Simple API to create Ethernet frames.
2. **Protocol Handlers**: Register callbacks for different Ethernet types.
3. **Automatic Padding**: Ensures minimum Ethernet frame size.
4. **Byte Order Handling**: Handles network byte order conversions.
5. **MAC Address Utilities**: Convert between string and binary representations.

## Usage Example

```cpp
#include "ethernet.h"
#include "raw_socket_device.h"
#include <iostream>
#include <memory>

// Handler for IP packets
void handleIPPacket(const uint8_t* data, size_t length,
                    const MacAddress& src_mac, const MacAddress& dst_mac) {
    std::cout << "Received IP packet from " << EthernetUtils::macToString(src_mac)
              << " to " << EthernetUtils::macToString(dst_mac)
              << ", length: " << length << std::endl;
}

// Handler for ARP packets
void handleARPPacket(const uint8_t* data, size_t length,
                     const MacAddress& src_mac, const MacAddress& dst_mac) {
    std::cout << "Received ARP packet from " << EthernetUtils::macToString(src_mac)
              << " to " << EthernetUtils::macToString(dst_mac)
              << ", length: " << length << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface_name>" << std::endl;
        return 1;
    }

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(argv[1]);

        // Create Ethernet layer
        Ethernet ethernet(device);

        // Initialize Ethernet layer
        if (!ethernet.init()) {
            std::cerr << "Failed to initialize Ethernet layer" << std::endl;
            return 1;
        }

        // Register protocol handlers
        ethernet.registerHandler(EtherType::IPV4, handleIPPacket);
        ethernet.registerHandler(EtherType::ARP, handleARPPacket);

        // Print device MAC address
        std::cout << "Device MAC address: " << EthernetUtils::macToString(ethernet.getMacAddress()) << std::endl;

        // Receive frames in a loop (with timeout)
        while (true) {
            ethernet.receiveFrames(1000); // 1 second timeout
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Implementation Details

1. **Network Byte Order**: All multi-byte fields in the Ethernet header are stored in network byte order (big-endian).
2. **Minimum Frame Size**: The implementation ensures that all frames meet the minimum Ethernet frame size of 60 bytes (without FCS).
3. **Protocol Handler Routing**: Received frames are automatically routed to the appropriate protocol handler based on the EtherType.
4. **MAC Address Conversion**: Provides utility functions to convert between string and binary MAC address formats.
5. **Error Handling**: Returns boolean success/failure for operations and includes appropriate error checking.

## Limitations

1. The implementation does not handle VLAN tags (802.1Q).
2. It does not implement Ethernet flow control.
3. Jumbo frames are not supported.
4. No automatic fragmentation for payloads exceeding MTU.

## Future Improvements

1. Add support for VLAN tagging (802.1Q).
2. Implement support for jumbo frames.
3. Add Ethernet statistics collection.
4. Implement Ethernet checksum validation.
5. Add support for multicast MAC address filtering.