#include "icmp.h"
#include <cstring>
#include <iostream>
#include <random>
#include <arpa/inet.h>  // For htons and ntohs functions

// ICMPPacket constructors
ICMPPacket::ICMPPacket() {
    // Initialize header with zeros
    std::memset(&header_, 0, sizeof(ICMPHeader));
}

ICMPPacket::ICMPPacket(uint8_t type, uint8_t code) : ICMPPacket() {
    header_.type = type;
    header_.code = code;
}

// Create ICMP packet from buffer
std::unique_ptr<ICMPPacket> ICMPPacket::fromBuffer(const uint8_t* buffer, size_t length) {
    // Check if buffer is big enough to contain ICMP header
    if (!buffer || length < sizeof(ICMPHeader)) {
        return nullptr;
    }

    auto packet = std::make_unique<ICMPPacket>();

    // Copy header
    std::memcpy(&packet->header_, buffer, sizeof(ICMPHeader));

    // Copy payload if exists
    if (length > sizeof(ICMPHeader)) {
        packet->setPayload(buffer + sizeof(ICMPHeader), length - sizeof(ICMPHeader));
    }

    return packet;
}

// Header field getters/setters
uint8_t ICMPPacket::getType() const {
    return header_.type;
}

void ICMPPacket::setType(uint8_t type) {
    header_.type = type;
}

uint8_t ICMPPacket::getCode() const {
    return header_.code;
}

void ICMPPacket::setCode(uint8_t code) {
    header_.code = code;
}

uint16_t ICMPPacket::getChecksum() const {
    return ntohs(header_.checksum);
}

void ICMPPacket::setChecksum(uint16_t checksum) {
    header_.checksum = htons(checksum);
}

// Echo specific
uint16_t ICMPPacket::getIdentifier() const {
    return ntohs(header_.un.echo.identifier);
}

void ICMPPacket::setIdentifier(uint16_t identifier) {
    header_.un.echo.identifier = htons(identifier);
}

uint16_t ICMPPacket::getSequence() const {
    return ntohs(header_.un.echo.sequence);
}

void ICMPPacket::setSequence(uint16_t sequence) {
    header_.un.echo.sequence = htons(sequence);
}

// Payload handling
const std::vector<uint8_t>& ICMPPacket::getPayload() const {
    return payload_;
}

void ICMPPacket::setPayload(const uint8_t* data, size_t length) {
    if (data && length > 0) {
        payload_.assign(data, data + length);
    } else {
        payload_.clear();
    }
}

// Calculate checksum
uint16_t ICMPPacket::calculateChecksum() const {
    // Prepare buffer with header and payload
    std::vector<uint8_t> buffer(sizeof(ICMPHeader) + payload_.size());

    // Copy header to buffer
    ICMPHeader temp_header = header_;
    temp_header.checksum = 0; // Set checksum to 0 for calculation
    std::memcpy(buffer.data(), &temp_header, sizeof(ICMPHeader));

    // Copy payload to buffer
    if (!payload_.empty()) {
        std::memcpy(buffer.data() + sizeof(ICMPHeader), payload_.data(), payload_.size());
    }

    // Calculate Internet Checksum (RFC 1071)
    uint32_t sum = 0;

    // Handle 16-bit chunks
    for (size_t i = 0; i < buffer.size() - 1; i += 2) {
        sum += (buffer[i] << 8) | buffer[i + 1];
    }

    // Handle odd byte if exists
    if (buffer.size() % 2) {
        sum += buffer[buffer.size() - 1] << 8;
    }

    // Add carry and do one's complement
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

void ICMPPacket::updateChecksum() {
    header_.checksum = htons(calculateChecksum());
}

// Serialize packet to buffer
size_t ICMPPacket::serialize(uint8_t* buffer, size_t buffer_size) const {
    size_t total_size = getTotalSize();

    // Check if buffer is big enough
    if (!buffer || buffer_size < total_size) {
        return 0;
    }

    // Copy header
    std::memcpy(buffer, &header_, sizeof(ICMPHeader));

    // Copy payload if exists
    if (!payload_.empty()) {
        std::memcpy(buffer + sizeof(ICMPHeader), payload_.data(), payload_.size());
    }

    return total_size;
}

// Get total packet size
size_t ICMPPacket::getTotalSize() const {
    return sizeof(ICMPHeader) + payload_.size();
}

// ICMP layer constructor
ICMP::ICMP(std::shared_ptr<IP> ip) : ip_(ip) {
}

// Initialize ICMP layer
bool ICMP::init() {
    if (!ip_) {
        std::cerr << "ICMP init failed: IP layer not provided" << std::endl;
        return false;
    }

    // Register for ICMP packets from IP layer
    ip_->registerProtocolHandler(IPProtocol::ICMP,
        [this](const uint8_t* data, size_t length, IPv4Address src_ip, IPv4Address dst_ip) {
            this->handleIPPacket(data, length, src_ip, dst_ip);
        }
    );

    return true;
}

// Send ICMP packet
bool ICMP::sendPacket(IPv4Address dst_ip, const ICMPPacket& packet) {
    size_t total_size = packet.getTotalSize();
    std::vector<uint8_t> buffer(total_size);

    // Prepare a copy of the packet to ensure checksum is updated
    ICMPPacket packet_copy = packet;
    packet_copy.updateChecksum();

    // Serialize packet to buffer
    if (packet_copy.serialize(buffer.data(), buffer.size()) != total_size) {
        std::cerr << "ICMP sendPacket failed: Serialization error" << std::endl;
        return false;
    }

    // Send using IP layer
    IPSendOptions options;
    options.ttl = 64; // Default TTL for ICMP

    // ip_->sendPacketAsync(dst_ip, IPProtocol::ICMP, buffer.data(), buffer.size(), [](bool success, IPv4Address dst_ip) {
    //     std::cout << "ICMP packet sent: " << (success ? "success" : "failed") << std::endl;
    // }, options);
    // return true;

    return ip_->sendPacket(dst_ip, IPProtocol::ICMP, buffer.data(), buffer.size(), options);
}

// Create and send Echo Request (ping)
bool ICMP::sendEchoRequest(IPv4Address dst_ip, uint16_t identifier,
                          uint16_t sequence, const uint8_t* data,
                          size_t data_length) {
    // Create Echo Request packet
    ICMPPacket packet(ICMPType::ECHO_REQUEST, 0);
    packet.setIdentifier(identifier);
    packet.setSequence(sequence);

    // Add payload data if provided
    if (data && data_length > 0) {
        packet.setPayload(data, data_length);
    } else {
        // Default payload with timestamp and some padding
        std::vector<uint8_t> default_data(56); // Standard ping data size

        // Add timestamp
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::memcpy(default_data.data(), &now_ms, sizeof(now_ms));

        // Fill rest with incrementing values
        for (size_t i = sizeof(now_ms); i < default_data.size(); i++) {
            default_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        packet.setPayload(default_data.data(), default_data.size());
    }

    // Send packet
    return sendPacket(dst_ip, packet);
}

// Register handler for specific ICMP type
void ICMP::registerTypeHandler(uint8_t type, ICMPHandler handler) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    type_handlers_[type] = handler;
}

// Unregister handler for specific ICMP type
void ICMP::unregisterTypeHandler(uint8_t type) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    type_handlers_.erase(type);
}

// Get IP layer
std::shared_ptr<IP> ICMP::getIP() const {
    return ip_;
}

// IP packet handler (called by IP layer)
void ICMP::handleIPPacket(const uint8_t* data, size_t length,
                         IPv4Address src_ip, IPv4Address dst_ip) {
    // Parse ICMP packet
    auto packet = ICMPPacket::fromBuffer(data, length);
    if (!packet) {
        std::cerr << "ICMP handleIPPacket: Failed to parse ICMP packet" << std::endl;
        return;
    }

    // Check if this is an echo request to our IP
    if (packet->getType() == ICMPType::ECHO_REQUEST &&
        ip_->isLocalIP(dst_ip)) {
        // Automatically respond to echo requests (ping)
        handleEchoRequest(*packet, src_ip, dst_ip);
    }

    // Call registered handler if exists
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto it = type_handlers_.find(packet->getType());
    if (it != type_handlers_.end()) {
        it->second(*packet, src_ip, dst_ip);
    }
}

// Handle Echo Request (ping)
void ICMP::handleEchoRequest(const ICMPPacket& request,
                            IPv4Address src_ip, IPv4Address dst_ip) {
    // Create Echo Reply packet
    ICMPPacket reply(ICMPType::ECHO_REPLY, 0);

    // Copy identifier and sequence from request
    reply.setIdentifier(request.getIdentifier());
    reply.setSequence(request.getSequence());

    // Copy payload from request
    reply.setPayload(request.getPayload().data(), request.getPayload().size());

    // Send reply
    sendPacket(src_ip, reply);
}

// Send ICMP error message
bool ICMP::sendErrorMessage(uint8_t type, uint8_t code,
                           IPv4Address dst_ip, const uint8_t* original_packet,
                           size_t original_length) {
    // Create error packet
    ICMPPacket packet(type, code);

    // RFC 792: Include IP header + 8 bytes of original datagram's data
    size_t icmp_error_data_size = std::min(original_length,
                                          IP_HEADER_MIN_SIZE + 8);

    // Set error payload (IP header + 8 bytes)
    packet.setPayload(original_packet, icmp_error_data_size);

    // Send error message
    return sendPacket(dst_ip, packet);
}