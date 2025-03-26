#include "arp.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <algorithm>


// ARP packet constants
constexpr uint16_t ARP_HARDWARE_TYPE_ETHERNET = 1;
constexpr uint16_t ARP_PROTOCOL_TYPE_IPV4 = 0x0800;
constexpr uint8_t ARP_HARDWARE_SIZE_ETHERNET = 6;
constexpr uint8_t ARP_PROTOCOL_SIZE_IPV4 = 4;

// ARPPacket implementation
ARPPacket::ARPPacket() {
    // Initialize header
    std::memset(&header_, 0, sizeof(header_));

    // Set fixed fields
    header_.hardware_type = htons(ARP_HARDWARE_TYPE_ETHERNET);
    header_.protocol_type = htons(ARP_PROTOCOL_TYPE_IPV4);
    header_.hardware_size = ARP_HARDWARE_SIZE_ETHERNET;
    header_.protocol_size = ARP_PROTOCOL_SIZE_IPV4;
}

ARPPacket::ARPPacket(ARPOperation op, const MacAddress& sender_mac, IPv4Address sender_ip,
                    const MacAddress& target_mac, IPv4Address target_ip) : ARPPacket() {
    setOperation(op);
    setSenderMAC(sender_mac);
    setSenderIP(sender_ip);
    setTargetMAC(target_mac);
    setTargetIP(target_ip);
}

std::unique_ptr<ARPPacket> ARPPacket::fromBuffer(const uint8_t* buffer, size_t length) {
    if (length < sizeof(ARPHeader)) {
        return nullptr;
    }

    auto packet = std::make_unique<ARPPacket>();
    std::memcpy(&packet->header_, buffer, sizeof(ARPHeader));

    return packet;
}

ARPOperation ARPPacket::getOperation() const {
    return static_cast<ARPOperation>(ntohs(header_.operation));
}

void ARPPacket::setOperation(ARPOperation op) {
    header_.operation = htons(static_cast<uint16_t>(op));
}

const MacAddress& ARPPacket::getSenderMAC() const {
    return header_.sender_mac;
}

void ARPPacket::setSenderMAC(const MacAddress& mac) {
    header_.sender_mac = mac;
}

IPv4Address ARPPacket::getSenderIP() const {
    return ntohl(header_.sender_ip);
}

void ARPPacket::setSenderIP(IPv4Address ip) {
    header_.sender_ip = htonl(ip);
}

const MacAddress& ARPPacket::getTargetMAC() const {
    return header_.target_mac;
}

void ARPPacket::setTargetMAC(const MacAddress& mac) {
    header_.target_mac = mac;
}

IPv4Address ARPPacket::getTargetIP() const {
    return ntohl(header_.target_ip);
}

void ARPPacket::setTargetIP(IPv4Address ip) {
    header_.target_ip = htonl(ip);
}

size_t ARPPacket::serialize(uint8_t* buffer, size_t buffer_size) const {
    if (buffer_size < sizeof(ARPHeader)) {
        return 0;
    }

    std::memcpy(buffer, &header_, sizeof(ARPHeader));
    return sizeof(ARPHeader);
}

size_t ARPPacket::getSize() const {
    return sizeof(ARPHeader);
}

// ARP module implementation
ARP::ARP(std::shared_ptr<Ethernet> ethernet, IPv4Address local_ip)
    : ethernet_(ethernet), local_ip_(local_ip) {

    if (!ethernet_) {
        throw std::invalid_argument("Ethernet layer is null");
    }
}

bool ARP::init() {
    // Register ARP packet handler
    ethernet_->registerHandler(EtherType::ARP,
        [this](const uint8_t* data, size_t length,
              const MacAddress& src_mac, const MacAddress& dst_mac) {
            this->handleARPPacket(data, length, src_mac, dst_mac);
        });

    return true;
}

bool ARP::resolve(IPv4Address ip, ARPResolveCallback callback) {
    // If IP is local IP, return local MAC
    if (ip == local_ip_) {
        MacAddress local_mac = ethernet_->getMacAddress();
        if (callback) {
            callback(ip, local_mac, true);
        }
        std::cout << "ARP resolve: " << ipToString(ip) << " is local IP, using local MAC" << std::endl;
        return true;
    }

    // If IP is broadcast, return broadcast MAC
    if (ip == IP_BROADCAST) {
        if (callback) {
            callback(ip, MAC_BROADCAST, true);
        }
        std::cout << "ARP resolve: " << ipToString(ip) << " is broadcast IP, using broadcast MAC" << std::endl;
        return true;
    }

    // Lock cache
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Search cache
    auto it = cache_.find(ip);
    if (it != cache_.end() && it->second.state == ARPEntryState::RESOLVED) {
        // If already resolved, return immediately
        if (callback) {
            callback(ip, it->second.mac, true);
        }
        std::cout << "ARP resolve: " << ipToString(ip) << " found in cache: "
                  << macToString(it->second.mac) << std::endl;
        return true;
    }

    // Search pending requests
    auto pending_it = std::find_if(pending_requests_.begin(), pending_requests_.end(),
                              [ip](const PendingARPRequest& req) { return req.ip == ip; });

    if (pending_it != pending_requests_.end()) {
        // If request already pending, add callback
        if (callback) {
            pending_it->callbacks.push_back(callback);
        }
        std::cout << "ARP resolve: " << ipToString(ip) << " request already pending" << std::endl;
        return true;
    }

    // Create new pending request
    PendingARPRequest request(ip);
    if (callback) {
        request.callbacks.push_back(callback);
    }
    pending_requests_.push_back(request);

    // Add incomplete entry to ARP cache
    if (it == cache_.end()) {
        cache_[ip] = ARPEntry(MAC_ZERO, ARPEntryState::INCOMPLETE);
    }

    // Send ARP request
    std::cout << "ARP resolve: Starting new resolution for " << ipToString(ip) << std::endl;
    sendARPRequest(ip);

    return true;
}

bool ARP::lookup(IPv4Address ip, MacAddress& mac) {
    // For broadcast IP address
    if (ip == IP_BROADCAST) {
        mac = MAC_BROADCAST;
        return true;
    }

    // For local IP address
    if (ip == local_ip_) {
        mac = ethernet_->getMacAddress();
        return true;
    }

    // Lock cache
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Search cache
    auto it = cache_.find(ip);
    if (it != cache_.end() && it->second.state == ARPEntryState::RESOLVED) {
        mac = it->second.mac;
        return true;
    }

    return false;
}

void ARP::addEntry(IPv4Address ip, const MacAddress& mac, ARPEntryState state) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Add or update entry
    cache_[ip] = ARPEntry(mac, state);

    // Complete pending requests
    completePendingRequest(ip, mac, true);
}

void ARP::removeEntry(IPv4Address ip) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.erase(ip);
}

void ARP::processArpTimeouts() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    auto now = std::chrono::steady_clock::now();

    // Process pending requests
    for (auto it = pending_requests_.begin(); it != pending_requests_.end();) {
        // Check if the request has timed out
        if (now - it->last_sent > ARP_RESPONSE_TIMEOUT) {
            // Check if we've tried too many times
            if (it->retries >= ARP_MAX_RETRIES) {
                // Failed to resolve
                std::cout << "ARP request timeout, max retries reached for IP: "
                          << ipToString(it->ip) << std::endl;

                // Call callbacks with failure
                completePendingRequest(it->ip, MAC_ZERO, false);

                // Remove entry from cache
                auto cache_it = cache_.find(it->ip);
                if (cache_it != cache_.end() && cache_it->second.state == ARPEntryState::INCOMPLETE) {
                    cache_.erase(cache_it);
                }

                // Remove from pending list
                it = pending_requests_.erase(it);
            } else {
                // Retry
                std::cout << "ARP request timeout, retrying (" << it->retries + 1
                          << "/" << (int)ARP_MAX_RETRIES << ") for IP: "
                          << ipToString(it->ip) << std::endl;

                // Send another request
                sendARPRequest(it->ip);

                // Update retry count and last sent time
                it->retries++;
                it->last_sent = now;

                ++it;
            }
        } else {
            ++it;
        }
    }

    // Process cache entries
    for (auto it = cache_.begin(); it != cache_.end();) {
        // Check if entry has expired
        if (now - it->second.timestamp > ARP_CACHE_TIMEOUT &&
            it->second.state == ARPEntryState::RESOLVED) {
            // Remove expired entry
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

void ARP::setLocalIP(IPv4Address ip) {
    local_ip_ = ip;
}

IPv4Address ARP::getLocalIP() const {
    return local_ip_;
}

void ARP::handleARPPacket(const uint8_t* data, size_t length,
                        const MacAddress& src_mac, const MacAddress& dst_mac) {
    // Parse ARP packet
    auto arp_packet = ARPPacket::fromBuffer(data, length);
    if (!arp_packet) {
        std::cerr << "Failed to parse ARP packet" << std::endl;
        return;
    }

    // Get packet information
    auto sender_ip = arp_packet->getSenderIP();
    auto sender_mac = arp_packet->getSenderMAC();
    auto target_ip = arp_packet->getTargetIP();
    auto operation = arp_packet->getOperation();

    std::cout << "Received ARP packet: "
              << (operation == ARPOperation::REQUEST ? "REQUEST" : "REPLY")
              << " from IP: " << ipToString(sender_ip)
              << ", MAC: " << macToString(sender_mac)
              << ", target IP: " << ipToString(target_ip)
              << std::endl;

    // Add sender IP and MAC to cache
    addEntry(sender_ip, sender_mac);

    // Check if this is a reply to one of our pending requests
    if (operation == ARPOperation::REPLY) {
        // Find in pending requests
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = std::find_if(pending_requests_.begin(), pending_requests_.end(),
                            [sender_ip](const PendingARPRequest& req) { return req.ip == sender_ip; });

        if (it != pending_requests_.end()) {
            std::cout << "ARP REPLY matches pending request for IP: " << ipToString(sender_ip)
                      << " with MAC: " << macToString(sender_mac) << std::endl;
            completePendingRequest(sender_ip, sender_mac, true);
        } else {
            std::cout << "ARP REPLY received but no matching pending request for IP: "
                      << ipToString(sender_ip) << std::endl;
        }
    }

    // If ARP request for our IP, send ARP reply
    if (operation == ARPOperation::REQUEST && target_ip == local_ip_) {
        std::cout << "Sending ARP reply to " << ipToString(sender_ip) << std::endl;
        sendARPReply(sender_ip, sender_mac);
    }
}

void ARP::sendARPRequest(IPv4Address target_ip) {
    // Create ARP packet
    MacAddress local_mac = ethernet_->getMacAddress();
    ARPPacket packet(ARPOperation::REQUEST, local_mac, local_ip_, MAC_ZERO, target_ip);

    // Serialize packet
    std::vector<uint8_t> buffer(packet.getSize());
    size_t packet_size = packet.serialize(buffer.data(), buffer.size());

    // Send through Ethernet layer
    bool sent = ethernet_->sendFrame(MAC_BROADCAST, EtherType::ARP, buffer.data(), packet_size);

    std::cout << "Sent ARP request for IP: " << ipToString(target_ip)
              << " from " << ipToString(local_ip_)
              << " (MAC: " << macToString(local_mac) << ") "
              << "[" << (sent ? "SUCCESS" : "FAILED") << "]" << std::endl;

    std::cout << "  ARP packet details: op=REQUEST, sender=" << macToString(local_mac)
              << "/" << ipToString(local_ip_) << ", target="
              << macToString(MAC_ZERO) << "/" << ipToString(target_ip)
              << ", size=" << packet_size << " bytes" << std::endl;
}

void ARP::sendARPReply(IPv4Address target_ip, const MacAddress& target_mac) {
    // Create ARP reply packet
    ARPPacket packet(ARPOperation::REPLY,
                   ethernet_->getMacAddress(), local_ip_,
                   target_mac, target_ip);

    // Allocate buffer
    std::vector<uint8_t> buffer(packet.getSize());

    // Serialize packet
    packet.serialize(buffer.data(), buffer.size());

    // Send through Ethernet layer
    ethernet_->sendFrame(target_mac, EtherType::ARP, buffer.data(), buffer.size());

    std::cout << "Sent ARP reply to IP: " << ipToString(target_ip)
              << ", MAC: " << macToString(target_mac) << std::endl;
}

void ARP::completePendingRequest(IPv4Address ip, const MacAddress& mac, bool success) {

    // Find pending request
    auto it = std::find_if(pending_requests_.begin(), pending_requests_.end(),
                      [ip](const PendingARPRequest& req) { return req.ip == ip; });

    if (it != pending_requests_.end()) {
        // Make a copy of callbacks before erasing the request
        std::vector<ARPResolveCallback> callbacks = it->callbacks;

        // Remove from list first
        pending_requests_.erase(it);

        // Call all registered callbacks using the copy
        for (const auto& callback : callbacks) {
            if (callback) {
                callback(ip, mac, success);
            }
        }
    }
}