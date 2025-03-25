#include "ethernet.h"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <map>

// EthernetFrame implementation

EthernetFrame::EthernetFrame() {
    // Initialize header with zeros
    std::memset(&header_, 0, sizeof(header_));
}

EthernetFrame::EthernetFrame(const MacAddress& dst, const MacAddress& src, EtherType type) : EthernetFrame() {
    // Set header fields
    header_.dst_mac = dst;
    header_.src_mac = src;
    header_.ether_type = htons(static_cast<uint16_t>(type));
}

std::unique_ptr<EthernetFrame> EthernetFrame::fromBuffer(const uint8_t* buffer, size_t length) {
    // Check minimum size
    if (length < ETHERNET_HEADER_SIZE) {
        return nullptr;
    }

    auto frame = std::make_unique<EthernetFrame>();

    // Copy header
    std::memcpy(&frame->header_, buffer, ETHERNET_HEADER_SIZE);

    // Copy payload if any
    if (length > ETHERNET_HEADER_SIZE) {
        frame->setPayload(buffer + ETHERNET_HEADER_SIZE, length - ETHERNET_HEADER_SIZE);
    }

    return frame;
}

const MacAddress& EthernetFrame::getDestinationMac() const {
    return header_.dst_mac;
}

void EthernetFrame::setDestinationMac(const MacAddress& mac) {
    header_.dst_mac = mac;
}

const MacAddress& EthernetFrame::getSourceMac() const {
    return header_.src_mac;
}

void EthernetFrame::setSourceMac(const MacAddress& mac) {
    header_.src_mac = mac;
}

EtherType EthernetFrame::getEtherType() const {
    return static_cast<EtherType>(ntohs(header_.ether_type));
}

void EthernetFrame::setEtherType(EtherType type) {
    header_.ether_type = htons(static_cast<uint16_t>(type));
}

const std::vector<uint8_t>& EthernetFrame::getPayload() const {
    return payload_;
}

void EthernetFrame::setPayload(const uint8_t* data, size_t length) {
    payload_.resize(length);
    std::memcpy(payload_.data(), data, length);
}

size_t EthernetFrame::serialize(uint8_t* buffer, size_t buffer_size) const {
    // Check buffer size
    size_t total_size = getTotalSize();
    if (buffer_size < total_size) {
        return 0;
    }

    // Copy header
    std::memcpy(buffer, &header_, ETHERNET_HEADER_SIZE);

    // Copy payload
    if (!payload_.empty()) {
        std::memcpy(buffer + ETHERNET_HEADER_SIZE, payload_.data(), payload_.size());
    }

    // Pad if necessary (Ethernet minimum frame size is 60 bytes without FCS)
    size_t frame_size = ETHERNET_HEADER_SIZE + payload_.size();
    if (frame_size < ETHERNET_MIN_FRAME_SIZE) {
        std::memset(buffer + frame_size, 0, ETHERNET_MIN_FRAME_SIZE - frame_size);
        return ETHERNET_MIN_FRAME_SIZE;
    }

    return total_size;
}

size_t EthernetFrame::getTotalSize() const {
    size_t size = ETHERNET_HEADER_SIZE + payload_.size();
    // Ensure minimum Ethernet frame size (without FCS)
    return std::max(size, ETHERNET_MIN_FRAME_SIZE);
}

// Ethernet implementation

Ethernet::Ethernet(std::shared_ptr<NetworkDevice> device) : device_(device) {
    if (!device_) {
        throw std::invalid_argument("NetworkDevice cannot be null");
    }
}

bool Ethernet::init() {
    // Open the network device
    if (device_->open() < 0) {
        return false;
    }

    return true;
}

bool Ethernet::sendFrame(const MacAddress& dst_mac, EtherType type, const uint8_t* data, size_t length) {
    // Create a frame
    EthernetFrame frame(dst_mac, getMacAddress(), type);
    frame.setPayload(data, length);

    // Allocate buffer for serialized frame
    size_t buffer_size = frame.getTotalSize();
    std::vector<uint8_t> buffer(buffer_size);

    // Serialize frame to buffer
    size_t serialized_size = frame.serialize(buffer.data(), buffer_size);
    if (serialized_size == 0) {
        return false;
    }

    // Send frame
    int sent = device_->send(buffer.data(), serialized_size);
    return sent > 0;
}

void Ethernet::receiveFrames(int timeout_ms) {
    // Allocate buffer for received frame
    std::vector<uint8_t> buffer(ETHERNET_MAX_FRAME_SIZE);

    // Receive packets
    device_->receive(buffer.data(), buffer.size(), packetReceiveCallback, this, timeout_ms);
}

void Ethernet::registerHandler(EtherType type, ProtocolHandler handler) {
    handlers_[static_cast<uint16_t>(type)] = std::move(handler);
}

MacAddress Ethernet::getMacAddress() const {
    MacAddress mac;
    std::memcpy(mac.data(), device_->getMacAddress().data(), mac.size());
    return mac;
}

int Ethernet::getDeviceMtu() const {
    return device_->getMtu();
}

void Ethernet::packetReceiveCallback(uint8_t* buffer, size_t length, void* arg) {
    auto* ethernet = static_cast<Ethernet*>(arg);

    // Parse Ethernet frame
    auto frame = EthernetFrame::fromBuffer(buffer, length);
    if (!frame) {
        // Invalid frame
        return;
    }

    // Get Ethernet type
    uint16_t ether_type = static_cast<uint16_t>(frame->getEtherType());

    // Find handler for this protocol
    auto it = ethernet->handlers_.find(ether_type);
    if (it != ethernet->handlers_.end()) {
        // Call handler
        const auto& payload = frame->getPayload();
        it->second(
            payload.data(),
            payload.size(),
            frame->getSourceMac(),
            frame->getDestinationMac()
        );
    }
    // Silently drop frames without a registered handler
}
