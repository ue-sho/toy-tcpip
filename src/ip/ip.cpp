#include "ip.h"
#include <cstring>
#include <algorithm>
#include <iostream>
#include <arpa/inet.h>
#include <thread>

// IP checksum calculation
uint16_t calculateIPChecksum(const void* data, size_t length) {
    // Ensure data is 16-bit aligned
    uint32_t sum = 0;
    const uint16_t* ptr = static_cast<const uint16_t*>(data);

    // Sum up 16-bit words
    for (size_t i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }

    // If we have an odd number of bytes, add the last byte
    if (length % 2) {
        sum += static_cast<const uint8_t*>(data)[length - 1];
    }

    // Add carry bits to the sum
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement of the sum
    return static_cast<uint16_t>(~sum);
}

// IPPacket implementation
IPPacket::IPPacket() {
    // Initialize header with zeros
    std::memset(&header_, 0, sizeof(header_));

    // Set default values
    setVersion(IPV4);
    setHeaderLength(5); // 5 32-bit words = 20 bytes (no options)
    setTTL(IP_DEFAULT_TTL);
    setTotalLength(IP_HEADER_MIN_SIZE);
}

IPPacket::IPPacket(uint8_t protocol, IPv4Address src_ip, IPv4Address dst_ip) : IPPacket() {
    setProtocol(protocol);
    setSourceIP(src_ip);
    setDestinationIP(dst_ip);
}

std::unique_ptr<IPPacket> IPPacket::fromBuffer(const uint8_t* buffer, size_t length) {
    // Check minimum size
    if (length < IP_HEADER_MIN_SIZE) {
        return nullptr;
    }

    auto packet = std::make_unique<IPPacket>();

    // Copy header
    std::memcpy(&packet->header_, buffer, IP_HEADER_MIN_SIZE);

    // Check header length
    size_t header_size = packet->getHeaderSize();
    if (length < header_size) {
        return nullptr;
    }

    // Set payload if any
    if (length > header_size) {
        packet->setPayload(buffer + header_size, length - header_size);
    }

    return packet;
}

uint8_t IPPacket::getVersion() const {
    return (header_.version_ihl >> 4) & 0x0F;
}

void IPPacket::setVersion(uint8_t version) {
    header_.version_ihl = (header_.version_ihl & 0x0F) | ((version & 0x0F) << 4);
}

uint8_t IPPacket::getHeaderLength() const {
    return header_.version_ihl & 0x0F;
}

void IPPacket::setHeaderLength(uint8_t ihl) {
    header_.version_ihl = (header_.version_ihl & 0xF0) | (ihl & 0x0F);
}

uint8_t IPPacket::getDSCP() const {
    return (header_.dscp_ecn >> 2) & 0x3F;
}

void IPPacket::setDSCP(uint8_t dscp) {
    header_.dscp_ecn = (header_.dscp_ecn & 0x03) | ((dscp & 0x3F) << 2);
}

uint8_t IPPacket::getECN() const {
    return header_.dscp_ecn & 0x03;
}

void IPPacket::setECN(uint8_t ecn) {
    header_.dscp_ecn = (header_.dscp_ecn & 0xFC) | (ecn & 0x03);
}

uint16_t IPPacket::getTotalLength() const {
    return ntohs(header_.total_length);
}

void IPPacket::setTotalLength(uint16_t length) {
    header_.total_length = htons(length);
}

uint16_t IPPacket::getIdentification() const {
    return ntohs(header_.identification);
}

void IPPacket::setIdentification(uint16_t id) {
    header_.identification = htons(id);
}

bool IPPacket::getDontFragment() const {
    return (ntohs(header_.flags_fragment) & IPFlags::DONT_FRAGMENT) != 0;
}

void IPPacket::setDontFragment(bool df) {
    uint16_t flags_fragment = ntohs(header_.flags_fragment);
    if (df) {
        flags_fragment |= IPFlags::DONT_FRAGMENT;
    } else {
        flags_fragment &= ~IPFlags::DONT_FRAGMENT;
    }
    header_.flags_fragment = htons(flags_fragment);
}

bool IPPacket::getMoreFragments() const {
    return (ntohs(header_.flags_fragment) & IPFlags::MORE_FRAGMENTS) != 0;
}

void IPPacket::setMoreFragments(bool mf) {
    uint16_t flags_fragment = ntohs(header_.flags_fragment);
    if (mf) {
        flags_fragment |= IPFlags::MORE_FRAGMENTS;
    } else {
        flags_fragment &= ~IPFlags::MORE_FRAGMENTS;
    }
    header_.flags_fragment = htons(flags_fragment);
}

uint16_t IPPacket::getFragmentOffset() const {
    return ntohs(header_.flags_fragment) & IPFlags::FRAGMENT_OFFSET_MASK;
}

void IPPacket::setFragmentOffset(uint16_t offset) {
    uint16_t flags_fragment = ntohs(header_.flags_fragment);
    flags_fragment = (flags_fragment & ~IPFlags::FRAGMENT_OFFSET_MASK) | (offset & IPFlags::FRAGMENT_OFFSET_MASK);
    header_.flags_fragment = htons(flags_fragment);
}

uint8_t IPPacket::getTTL() const {
    return header_.ttl;
}

void IPPacket::setTTL(uint8_t ttl) {
    header_.ttl = ttl;
}

uint8_t IPPacket::getProtocol() const {
    return header_.protocol;
}

void IPPacket::setProtocol(uint8_t protocol) {
    header_.protocol = protocol;
}

uint16_t IPPacket::getChecksum() const {
    return header_.checksum;
}

void IPPacket::setChecksum(uint16_t checksum) {
    header_.checksum = checksum;
}

IPv4Address IPPacket::getSourceIP() const {
    return header_.src_ip;
}

void IPPacket::setSourceIP(IPv4Address ip) {
    header_.src_ip = ip;
}

IPv4Address IPPacket::getDestinationIP() const {
    return header_.dst_ip;
}

void IPPacket::setDestinationIP(IPv4Address ip) {
    header_.dst_ip = ip;
}

const std::vector<uint8_t>& IPPacket::getPayload() const {
    return payload_;
}

void IPPacket::setPayload(const uint8_t* data, size_t length) {
    payload_.resize(length);
    if (length > 0) {
        std::memcpy(payload_.data(), data, length);
    }

    // Update total length
    setTotalLength(getHeaderSize() + length);
}

uint16_t IPPacket::calculateChecksum() const {
    // Save the current checksum
    uint16_t old_checksum = header_.checksum;

    // Create a copy of the header and set checksum to 0
    IPHeader header_copy = header_;
    header_copy.checksum = 0;

    // Calculate checksum
    uint16_t checksum = calculateIPChecksum(&header_copy, getHeaderSize());

    // Restore the old checksum
    const_cast<IPHeader&>(header_).checksum = old_checksum;

    return checksum;
}

void IPPacket::updateChecksum() {
    // Set checksum to 0 before calculation
    header_.checksum = 0;

    // Calculate and set checksum
    header_.checksum = calculateChecksum();
}

size_t IPPacket::serialize(uint8_t* buffer, size_t buffer_size) const {
    size_t total_size = getTotalSize();
    if (buffer_size < total_size) {
        return 0;
    }

    // Copy header
    std::memcpy(buffer, &header_, getHeaderSize());

    // Copy payload
    if (!payload_.empty()) {
        std::memcpy(buffer + getHeaderSize(), payload_.data(), payload_.size());
    }

    return total_size;
}

size_t IPPacket::getHeaderSize() const {
    // Header length is in 32-bit words (4 bytes)
    return getHeaderLength() * 4;
}

size_t IPPacket::getTotalSize() const {
    return getTotalLength();
}

// IP layer implementation
IP::IP(std::shared_ptr<Ethernet> ethernet, std::shared_ptr<ARP> arp, IPv4Address local_ip)
    : ip_id_counter_(0), ethernet_(ethernet), arp_(arp), local_ip_(local_ip) {

    if (!ethernet_ || !arp_) {
        throw std::invalid_argument("Ethernet or ARP layer is null");
    }
}

bool IP::init() {
    // Register IP packet handler with Ethernet layer
    ethernet_->registerHandler(EtherType::IPV4,
        [this](const uint8_t* data, size_t length,
              const MacAddress& src_mac, const MacAddress& dst_mac) {
            this->handleIPPacket(data, length, src_mac, dst_mac);
        });

    return true;
}

bool IP::sendPacket(IPv4Address dst_ip, uint8_t protocol, const uint8_t* data,
                   size_t length, const IPSendOptions& options) {
    // Check maximum packet size
    if (length > IP_MAX_PACKET_SIZE - IP_HEADER_MIN_SIZE) {
        std::cerr << "IP packet too large" << std::endl;
        return false;
    }

    // If destination is local, don't send
    if (isLocalIP(dst_ip)) {
        std::cerr << "Cannot send IP packet to self" << std::endl;
        return false;
    }

    // Check if we need to fragment the packet
    size_t mtu = ethernet_->getDeviceMtu() - IP_HEADER_MIN_SIZE;

    if (length > mtu && options.dont_fragment) {
        // Packet is too large and DF is set
        std::cerr << "IP packet too large for MTU and DF is set" << std::endl;
        return false;
    }

    // Resolve destination MAC address through ARP
    MacAddress dst_mac;
    if (!arp_->lookup(dst_ip, dst_mac)) {
        // ARP resolution needed
        std::cout << "ARP resolution needed for " << ipToString(dst_ip) << std::endl;

        // Start ARP resolution
        bool resolved = false;
        arp_->resolve(dst_ip, [&](IPv4Address ip, const MacAddress& mac, bool success) {
            std::cout << "ARP callback received: IP=" << ipToString(ip)
                      << ", MAC=" << macToString(mac)
                      << ", success=" << (success ? "true" : "false") << std::endl;
            if (success) {
                dst_mac = mac;
                resolved = true;
            }
        });

        // Wait for resolution (in a real implementation, this would be asynchronous)
        std::cout << "Waiting for ARP resolution..." << std::endl;
        for (int i = 0; i < 10 && !resolved; i++) {  // Increased from 5 to 10 attempts
            // Process pending requests
            arp_->processArpTimeouts();

            // Wait for a bit
            std::cout << "ARP resolution attempt " << (i+1) << "/10..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));  // Increased from 500ms to 1000ms
        }

        if (!resolved) {
            std::cerr << "Failed to resolve MAC address for " << ipToString(dst_ip) << std::endl;
            return false;
        }

        std::cout << "Successfully resolved MAC address for " << ipToString(dst_ip)
                  << " -> " << macToString(dst_mac) << std::endl;
    }

    return sendPacketInternal(dst_ip, protocol, data, length, dst_mac, options);
}

void IP::sendPacketAsync(IPv4Address dst_ip, uint8_t protocol, const uint8_t* data,
                       size_t length, IPSendCallback callback, const IPSendOptions& options) {
    // Check maximum packet size
    if (length > IP_MAX_PACKET_SIZE - IP_HEADER_MIN_SIZE) {
        std::cerr << "IP packet too large" << std::endl;
        if (callback) {
            callback(false, dst_ip);
        }
        return;
    }

    // If destination is local, don't send
    if (isLocalIP(dst_ip)) {
        std::cerr << "Cannot send IP packet to self" << std::endl;
        if (callback) {
            callback(false, dst_ip);
        }
        return;
    }

    // Create a copy of the data since it may not be valid after this function returns
    uint8_t* data_copy = new uint8_t[length];
    std::memcpy(data_copy, data, length);

    // Resolve MAC address asynchronously
    MacAddress dst_mac;
    if (!arp_->lookup(dst_ip, dst_mac)) {
        // ARP resolution needed
        std::cout << "ARP resolution needed for " << ipToString(dst_ip) << " (async)" << std::endl;

        // Start ARP resolution with callback
        arp_->resolve(dst_ip, [this, dst_ip, protocol, data_copy, length, callback, options]
            (IPv4Address ip, const MacAddress& mac, bool success) {
            std::cout << "ARP async callback received: IP=" << ipToString(ip)
                      << ", MAC=" << macToString(mac)
                      << ", success=" << (success ? "true" : "false") << std::endl;

            if (success) {
                // ARP resolution successful, send the packet
                bool send_result = sendPacketInternal(dst_ip, protocol, data_copy, length, mac, options);

                // Call the user callback with the result
                if (callback) {
                    callback(send_result, dst_ip);
                }
            } else {
                // ARP resolution failed
                std::cerr << "Failed to resolve MAC address for " << ipToString(dst_ip) << " (async)" << std::endl;
                if (callback) {
                    callback(false, dst_ip);
                }
            }

            // Free the data copy
            delete[] data_copy;
        });
    } else {
        // MAC address already in cache, send immediately
        bool send_result = sendPacketInternal(dst_ip, protocol, data_copy, length, dst_mac, options);

        // Call the user callback with the result
        if (callback) {
            callback(send_result, dst_ip);
        }

        // Free the data copy
        delete[] data_copy;
    }
}

bool IP::sendPacketInternal(IPv4Address dst_ip, uint8_t protocol, const uint8_t* data,
                          size_t length, const MacAddress& dst_mac, const IPSendOptions& options) {
    // Create IP packet
    IPPacket packet(protocol, local_ip_, dst_ip);
    packet.setTTL(options.ttl);
    packet.setDSCP(options.dscp);
    packet.setECN(options.ecn);
    packet.setDontFragment(options.dont_fragment);
    packet.setIdentification(generateIPId());

    // Check if we need to fragment the packet
    size_t mtu = ethernet_->getDeviceMtu() - IP_HEADER_MIN_SIZE;

    // If packet fits in MTU, send it
    if (length <= mtu) {
        packet.setPayload(data, length);
        packet.updateChecksum();

        // Serialize packet
        std::vector<uint8_t> buffer(packet.getTotalSize());
        size_t serialized_size = packet.serialize(buffer.data(), buffer.size());

        if (serialized_size == 0) {
            std::cerr << "Failed to serialize IP packet" << std::endl;
            return false;
        }

        // Send through Ethernet layer
        std::cout << "Sending IP packet to " << ipToString(dst_ip)
                  << " via MAC " << macToString(dst_mac)
                  << ", protocol=" << (int)protocol
                  << ", size=" << serialized_size << " bytes" << std::endl;
        return ethernet_->sendFrame(dst_mac, EtherType::IPV4, buffer.data(), serialized_size);
    }

    // Fragment the packet if it's too large
    if (options.dont_fragment) {
        // Packet is too large and DF is set
        std::cerr << "IP packet too large for MTU and DF is set" << std::endl;
        return false;
    }

    // Fragment the packet
    size_t offset = 0;
    const size_t max_fragment_data = mtu & ~7; // Ensure 8-byte alignment

    while (offset < length) {
        // Calculate fragment size
        size_t fragment_size = std::min(max_fragment_data, length - offset);
        bool last_fragment = (offset + fragment_size >= length);

        // Create fragment packet
        IPPacket fragment(protocol, local_ip_, dst_ip);
        fragment.setTTL(options.ttl);
        fragment.setDSCP(options.dscp);
        fragment.setECN(options.ecn);
        fragment.setIdentification(packet.getIdentification());
        fragment.setFragmentOffset(offset / 8); // Offset is in 8-byte units
        fragment.setMoreFragments(!last_fragment);
        fragment.setPayload(data + offset, fragment_size);
        fragment.updateChecksum();

        // Serialize fragment
        std::vector<uint8_t> buffer(fragment.getTotalSize());
        size_t serialized_size = fragment.serialize(buffer.data(), buffer.size());

        if (serialized_size == 0) {
            std::cerr << "Failed to serialize IP fragment" << std::endl;
            return false;
        }

        // Send through Ethernet layer
        if (!ethernet_->sendFrame(dst_mac, EtherType::IPV4, buffer.data(), serialized_size)) {
            std::cerr << "Failed to send IP fragment" << std::endl;
            return false;
        }

        // Move to next fragment
        offset += fragment_size;
    }

    return true;
}

void IP::registerProtocolHandler(uint8_t protocol, IPProtocolHandler handler) {
    protocol_handlers_[protocol] = std::move(handler);
}

void IP::unregisterProtocolHandler(uint8_t protocol) {
    protocol_handlers_.erase(protocol);
}

IPv4Address IP::getLocalIP() const {
    return local_ip_;
}

void IP::setLocalIP(IPv4Address ip) {
    local_ip_ = ip;
    arp_->setLocalIP(ip);
}

bool IP::isLocalIP(IPv4Address ip) const {
    return ip == local_ip_;
}

void IP::processFragmentTimeouts() {
    std::lock_guard<std::mutex> lock(fragment_mutex_);

    auto now = std::chrono::steady_clock::now();

    // Remove timed out fragment entries
    fragment_entries_.erase(
        std::remove_if(
            fragment_entries_.begin(),
            fragment_entries_.end(),
            [now, this](const IPFragmentEntry& entry) {
                return (now - entry.timestamp) > FRAGMENT_TIMEOUT;
            }
        ),
        fragment_entries_.end()
    );
}

void IP::handleIPPacket(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac) {
    // Parse IP packet
    auto packet = IPPacket::fromBuffer(data, length);
    if (!packet) {
        std::cerr << "Invalid IP packet" << std::endl;
        return;
    }

    // Check version
    if (packet->getVersion() != IPV4) {
        std::cerr << "Unsupported IP version: " << static_cast<int>(packet->getVersion()) << std::endl;
        return;
    }

    // Verify checksum
    uint16_t calculated_checksum = packet->calculateChecksum();
    if (calculated_checksum != 0 && calculated_checksum != packet->getChecksum()) {
        std::cerr << "Invalid IP checksum" << std::endl;
        return;
    }

    // Check if packet is for us
    if (!isLocalIP(packet->getDestinationIP()) && packet->getDestinationIP() != IP_BROADCAST) {
        // Not for us, ignore
        return;
    }

    // Process the packet
    processIPPacket(std::move(packet), length);
}

void IP::processIPPacket(std::unique_ptr<IPPacket> packet, size_t length) {
    // Check if packet is fragmented
    if (packet->getFragmentOffset() > 0 || packet->getMoreFragments()) {
        // Handle fragmented packet
        if (!handleFragment(std::move(packet))) {
            return;
        }
    } else {
        // Find protocol handler
        auto it = protocol_handlers_.find(packet->getProtocol());
        if (it != protocol_handlers_.end()) {
            // Call protocol handler
            const auto& payload = packet->getPayload();
            it->second(
                payload.data(),
                payload.size(),
                packet->getSourceIP(),
                packet->getDestinationIP()
            );
        } else {
            std::cerr << "No handler for protocol: " << static_cast<int>(packet->getProtocol()) << std::endl;
        }
    }
}

bool IP::handleFragment(std::unique_ptr<IPPacket> packet) {
    std::lock_guard<std::mutex> lock(fragment_mutex_);

    uint16_t id = packet->getIdentification();
    IPv4Address src_ip = packet->getSourceIP();
    IPv4Address dst_ip = packet->getDestinationIP();
    uint8_t protocol = packet->getProtocol();

    // Find existing fragment entry or create a new one
    auto it = std::find_if(
        fragment_entries_.begin(),
        fragment_entries_.end(),
        [id, src_ip, dst_ip, protocol](const IPFragmentEntry& entry) {
            return entry.id == id && entry.src_ip == src_ip &&
                   entry.dst_ip == dst_ip && entry.protocol == protocol;
        }
    );

    if (it == fragment_entries_.end()) {
        // Create new fragment entry
        fragment_entries_.emplace_back(id, src_ip, dst_ip, protocol);
        it = fragment_entries_.end() - 1;
    }

    // Get fragment offset and size
    uint16_t offset = packet->getFragmentOffset() * 8; // Convert to bytes
    size_t data_size = packet->getPayload().size();

    // Update entry's timestamp
    it->timestamp = std::chrono::steady_clock::now();

    // If this is the last fragment, we can determine the total size
    if (!packet->getMoreFragments()) {
        it->total_length = offset + data_size;

        // Resize data and received vectors if needed
        if (it->data.size() < it->total_length) {
            it->data.resize(it->total_length);
            it->received.resize(it->total_length, false);
        }
    } else if (it->data.size() < offset + data_size) {
        // Resize as needed for this fragment
        it->data.resize(offset + data_size);
        it->received.resize(offset + data_size, false);
    }

    // Copy fragment data
    const auto& payload = packet->getPayload();
    std::memcpy(it->data.data() + offset, payload.data(), data_size);

    // Mark bytes as received
    for (size_t i = 0; i < data_size; i++) {
        it->received[offset + i] = true;
    }

    // Try to reassemble
    return tryReassemble(*it);
}

bool IP::tryReassemble(IPFragmentEntry& entry) {
    // Check if we have all fragments
    if (entry.total_length == 0) {
        // We don't know the total length yet
        return false;
    }

    // Check if all bytes are received
    for (size_t i = 0; i < entry.total_length; i++) {
        if (!entry.received[i]) {
            return false;
        }
    }

    // All fragments received, find protocol handler
    auto it = protocol_handlers_.find(entry.protocol);
    if (it != protocol_handlers_.end()) {
        // Call protocol handler
        it->second(
            entry.data.data(),
            entry.total_length,
            entry.src_ip,
            entry.dst_ip
        );

        // Remove the entry
        fragment_entries_.erase(
            std::remove_if(
                fragment_entries_.begin(),
                fragment_entries_.end(),
                [&entry](const IPFragmentEntry& e) {
                    return e.id == entry.id && e.src_ip == entry.src_ip &&
                           e.dst_ip == entry.dst_ip && e.protocol == entry.protocol;
                }
            ),
            fragment_entries_.end()
        );

        return true;
    } else {
        std::cerr << "No handler for protocol: " << static_cast<int>(entry.protocol) << std::endl;
        return false;
    }
}

uint16_t IP::generateIPId() {
    return ip_id_counter_++;
}

void IP::processTimeouts() {
    // Process fragment timeouts
    processFragmentTimeouts();

    // Process ARP timeouts
    arp_->processArpTimeouts();
}
