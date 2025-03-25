#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

#include "../src/device/raw_socket_device.h"
#include "../src/device/network_device.h"
#include "../src/ethernet/ethernet.h"
#include "../src/arp/arp.h"
#include "../src/ip/ip.h"
#include "../src/common/common.h"

bool running = true;

// Signal handler for clean termination
void signalHandler(int signum) {
    std::cout << "Signal " << signum << " received. Terminating..." << std::endl;
    running = false;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <local_ip> [target_ip]" << std::endl;
        return 1;
    }

    const char* interface_name = argv[1];
    const char* local_ip_str = argv[2];
    const char* target_ip_str = (argc >= 4) ? argv[3] : nullptr;

    // Parse local IP address
    IPv4Address local_ip;
    if (!parseIpAddress(local_ip_str, local_ip)) {
        std::cerr << "Invalid local IP address: " << local_ip_str << std::endl;
        return 1;
    }

    // Parse optional target IP address
    IPv4Address target_ip = 0;
    if (target_ip_str && !parseIpAddress(target_ip_str, target_ip)) {
        std::cerr << "Invalid target IP address: " << target_ip_str << std::endl;
        return 1;
    }

    // Register signal handler
    signal(SIGINT, signalHandler);

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
        auto ip = std::make_shared<IPLayer>(ethernet, arp, local_ip);
        if (!ip->init()) {
            std::cerr << "Failed to initialize IP module" << std::endl;
            return 1;
        }

        // Display device MAC address and local IP
        std::cout << "Device: " << interface_name << std::endl;
        std::cout << "Local IP: " << ipToString(local_ip) << std::endl;

        // Register protocol handler for ICMP (just for demonstration)
        ip->registerProtocolHandler(IPProtocol::ICMP,
            [](const uint8_t* data, size_t length, IPv4Address src_ip, IPv4Address dst_ip) {
                std::cout << "Received ICMP packet from " << ipToString(src_ip)
                          << " to " << ipToString(dst_ip)
                          << " (" << length << " bytes)" << std::endl;
            });

        // Send a test packet to target IP if specified
        if (target_ip_str) {
            std::cout << "Sending test packet to: " << target_ip_str << std::endl;

            // Simple payload for testing
            const char* payload = "Hello, IP world!";
            size_t payload_len = strlen(payload);

            // Send via IP layer
            IPSendOptions options;
            options.ttl = 64;
            if (!ip->sendPacket(target_ip, IPProtocol::UDP,
                               reinterpret_cast<const uint8_t*>(payload),
                               payload_len, options)) {
                std::cerr << "Failed to send test packet" << std::endl;
            }
        }

        // Main loop
        std::cout << "Running... Press Ctrl+C to exit" << std::endl;
        while (running) {
            // Receive ethernet frames
            ethernet->receiveFrames(100);

            // Process pending ARP requests
            arp->processPendingRequests();

            // Process fragment timeouts
            ip->processFragmentTimeouts();

            // Sleep to reduce CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Exiting..." << std::endl;
    return 0;
}