#ifndef ETHERNET_H
#define ETHERNET_H

#include <cstdint>
#include <array>
#include <memory>
#include <vector>
#include <map>
#include <functional>
#include <string>
#include "../device/network_device.h"
#include "../common/common.h"

// Ethernet Frame Type values
enum class EtherType : uint16_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    // Add more as needed
};

std::string getEtherTypeDescription(EtherType type);

// Ethernet header structure
#pragma pack(push, 1)
struct EthernetHeader {
    MacAddress dst_mac;     // Destination MAC address
    MacAddress src_mac;     // Source MAC address
    uint16_t ether_type;    // Protocol type (in network byte order)
};
#pragma pack(pop)

// Size constants
constexpr size_t ETHERNET_HEADER_SIZE = sizeof(EthernetHeader);
constexpr size_t ETHERNET_MIN_FRAME_SIZE = 60; // Without FCS
constexpr size_t ETHERNET_MAX_FRAME_SIZE = 1514; // Without FCS
constexpr size_t ETHERNET_MTU = ETHERNET_MAX_FRAME_SIZE - ETHERNET_HEADER_SIZE;

// Ethernet frame class
class EthernetFrame {
public:
    // Constructors
    EthernetFrame();
    EthernetFrame(const MacAddress& dst, const MacAddress& src, EtherType type);

    // Create frame from raw buffer
    static std::unique_ptr<EthernetFrame> fromBuffer(const uint8_t* buffer, size_t length);

    // Get/Set header fields
    const MacAddress& getDestinationMac() const;
    void setDestinationMac(const MacAddress& mac);

    const MacAddress& getSourceMac() const;
    void setSourceMac(const MacAddress& mac);

    EtherType getEtherType() const;
    void setEtherType(EtherType type);

    // Payload handling
    const std::vector<uint8_t>& getPayload() const;
    void setPayload(const uint8_t* data, size_t length);

    // Serialize the frame to a buffer
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Get total frame size
    size_t getTotalSize() const;

private:
    EthernetHeader header_;
    std::vector<uint8_t> payload_;
};

// Ethernet layer class
class Ethernet {
public:
    // Type for the upper layer protocol handlers
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

    int getDeviceMtu() const;
private:
    // Network device
    std::shared_ptr<NetworkDevice> device_;

    // Protocol handlers
    std::map<uint16_t, ProtocolHandler> handlers_;

    // Device packet receive callback
    static void packetReceiveCallback(uint8_t* buffer, size_t length, void* arg);
};

#endif // ETHERNET_H