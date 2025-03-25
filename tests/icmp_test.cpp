#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <random>
#include <map>
#include <mutex>

#include "../src/device/raw_socket_device.h"
#include "../src/device/network_device.h"
#include "../src/ethernet/ethernet.h"
#include "../src/arp/arp.h"
#include "../src/ip/ip.h"
#include "../src/icmp/icmp.h"
#include "../src/common/common.h"

bool running = true;

// Structure to track ping statistics
struct PingStatistics {
    uint16_t sequence;          // Current sequence number
    uint16_t sent;              // Number of echo requests sent
    uint16_t received;          // Number of echo replies received
    uint64_t min_rtt;           // Minimum round-trip time (ms)
    uint64_t max_rtt;           // Maximum round-trip time (ms)
    uint64_t total_rtt;         // Total round-trip time (ms)
    std::map<uint16_t, std::chrono::steady_clock::time_point> pending_pings;  // Map of sequence numbers to send times
    std::mutex stats_mutex;     // Mutex to protect statistics

    PingStatistics() : sequence(0), sent(0), received(0),
                       min_rtt(UINT64_MAX), max_rtt(0), total_rtt(0) {}
};

// Signal handler for clean termination
void signalHandler(int signum) {
    std::cout << "Signal " << signum << " received. Terminating..." << std::endl;
    running = false;
}

// Print ping statistics
void printPingStatistics(const PingStatistics& stats) {
    if (stats.sent == 0) {
        std::cout << "No ping statistics available" << std::endl;
        return;
    }

    float loss_percent = 0.0f;
    if (stats.sent > 0) {
        loss_percent = (stats.sent - stats.received) * 100.0f / stats.sent;
    }

    uint64_t avg_rtt = 0;
    if (stats.received > 0) {
        avg_rtt = stats.total_rtt / stats.received;
    }

    std::cout << "\n--- Ping Statistics ---" << std::endl;
    std::cout << stats.sent << " packets transmitted, "
              << stats.received << " packets received, "
              << loss_percent << "% packet loss" << std::endl;

    if (stats.received > 0) {
        std::cout << "round-trip min/avg/max = "
                  << stats.min_rtt << "/"
                  << avg_rtt << "/"
                  << stats.max_rtt << " ms" << std::endl;
    }
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <local_ip> <target_ip> [count]" << std::endl;
        return 1;
    }

    const char* interface_name = argv[1];
    const char* local_ip_str = argv[2];
    const char* target_ip_str = argv[3];
    int ping_count = (argc >= 5) ? std::atoi(argv[4]) : -1;  // -1 means ping indefinitely

    // Parse IP addresses
    IPv4Address local_ip;
    if (!parseIpAddress(local_ip_str, local_ip)) {
        std::cerr << "Invalid local IP address: " << local_ip_str << std::endl;
        return 1;
    }

    IPv4Address target_ip;
    if (!parseIpAddress(target_ip_str, target_ip)) {
        std::cerr << "Invalid target IP address: " << target_ip_str << std::endl;
        return 1;
    }

    // Register signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Setup ping statistics
    PingStatistics ping_stats;

    // Generate a random identifier for this ping session
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(1, 65535);
    uint16_t ping_id = dist(gen);

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(interface_name);
        if (device->open() == -1) {
            std::cerr << "Failed to initialize device: " << interface_name << std::endl;
            return 1;
        }

        // Create ethernet layer
        auto ethernet = std::make_shared<Ethernet>(device);
        if (!ethernet->init()) {
            std::cerr << "Failed to initialize ethernet layer" << std::endl;
            return 1;
        }

        // Create ARP module
        auto arp = std::make_shared<ARP>(ethernet, local_ip);
        if (!arp->init()) {
            std::cerr << "Failed to initialize ARP module" << std::endl;
            return 1;
        }

        // Create IP layer
        auto ip = std::make_shared<IP>(ethernet, arp, local_ip);
        if (!ip->init()) {
            std::cerr << "Failed to initialize IP module" << std::endl;
            return 1;
        }

        // Create ICMP module
        auto icmp = std::make_shared<ICMP>(ip);
        if (!icmp->init()) {
            std::cerr << "Failed to initialize ICMP module" << std::endl;
            return 1;
        }

        // Register handler for ECHO_REPLY
        icmp->registerTypeHandler(ICMPType::ECHO_REPLY,
            [&ping_stats, ping_id](const ICMPPacket& packet, IPv4Address src_ip, IPv4Address dst_ip) {
                // Check if this is a reply to our ping
                if (packet.getIdentifier() == ping_id) {
                    auto now = std::chrono::steady_clock::now();
                    uint16_t sequence = packet.getSequence();

                    std::lock_guard<std::mutex> lock(ping_stats.stats_mutex);

                    // Find the request time and calculate RTT
                    auto it = ping_stats.pending_pings.find(sequence);
                    if (it != ping_stats.pending_pings.end()) {
                        auto send_time = it->second;
                        uint64_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - send_time).count();

                        // Update statistics
                        ping_stats.received++;
                        ping_stats.total_rtt += rtt_ms;
                        ping_stats.min_rtt = std::min(ping_stats.min_rtt, rtt_ms);
                        ping_stats.max_rtt = std::max(ping_stats.max_rtt, rtt_ms);

                        // Remove from pending list
                        ping_stats.pending_pings.erase(it);

                        // Print echo reply info
                        std::cout << "Echo reply from " << ipToString(src_ip)
                                  << ": icmp_seq=" << sequence
                                  << " ttl=64 time=" << rtt_ms << " ms" << std::endl;
                    }
                }
            }
        );

        // Display device info
        std::cout << "PING " << target_ip_str << " (" << target_ip_str << ")" << std::endl;

        // Send pings periodically
        auto last_ping_time = std::chrono::steady_clock::now();
        auto ping_interval = std::chrono::seconds(1);  // 1 ping per second

        // Main loop
        while (running && (ping_count == -1 || ping_stats.sent < ping_count)) {
            // Receive ethernet frames
            ethernet->receiveFrames(100);

            // Process pending ARP requests
            arp->processPendingRequests();

            // Process fragment timeouts
            ip->processFragmentTimeouts();

            // Check if it's time to send another ping
            auto now = std::chrono::steady_clock::now();
            if (now - last_ping_time >= ping_interval) {
                last_ping_time = now;

                // Get next sequence number and update sent count
                uint16_t sequence;
                {
                    std::lock_guard<std::mutex> lock(ping_stats.stats_mutex);
                    sequence = ++ping_stats.sequence;
                    ping_stats.sent++;
                    ping_stats.pending_pings[sequence] = now;
                }

                // Send ICMP echo request
                if (!icmp->sendEchoRequest(target_ip, ping_id, sequence)) {
                    std::cerr << "Failed to send echo request" << std::endl;
                }
            }

            // Clean up old pending pings (timeout after 5 seconds)
            {
                std::lock_guard<std::mutex> lock(ping_stats.stats_mutex);
                auto it = ping_stats.pending_pings.begin();
                while (it != ping_stats.pending_pings.end()) {
                    if (now - it->second > std::chrono::seconds(5)) {
                        std::cout << "Echo request timeout: icmp_seq=" << it->first << std::endl;
                        it = ping_stats.pending_pings.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Sleep to reduce CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Print final statistics
        printPingStatistics(ping_stats);

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Exiting..." << std::endl;
    return 0;
}