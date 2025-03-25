#include "../src/ethernet/ethernet.h"
#include "../src/device/raw_socket_device.h"
#include "../src/arp/arp.h"
#include "../src/common/common.h"
#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

std::atomic<bool> running{true};

void signal_handler(int signal) {
    std::cout << "Caught signal " << signal << ", exiting..." << std::endl;
    running = false;
}

// ARP resolve callback
void arp_resolve_callback(IPv4Address ip, const MacAddress& mac, bool success) {
    if (success) {
        std::cout << "ARP resolved: IP " << ipToString(ip)
                  << " -> MAC " << macToString(mac) << std::endl;
    } else {
        std::cout << "ARP resolution failed for IP " << ipToString(ip) << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <interface_name> <local_ip_address> [target_ip_address]" << std::endl;
        return 1;
    }

    std::string interface_name = argv[1];
    std::string local_ip_str = argv[2];

    // Parse local IP address
    IPv4Address local_ip = stringToIp(local_ip_str);
    if (local_ip == IP_ZERO) {
        std::cerr << "Invalid local IP address" << std::endl;
        return 1;
    }

    // Optional target IP address
    IPv4Address target_ip = IP_ZERO;
    if (argc >= 4) {
        std::string target_ip_str = argv[3];
        target_ip = stringToIp(target_ip_str);
        if (target_ip == IP_ZERO) {
            std::cerr << "Invalid target IP address" << std::endl;
            return 1;
        }
    }

    // Register signal handler
    std::signal(SIGINT, signal_handler);

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(interface_name);

        // Create ethernet layer
        auto ethernet = std::make_shared<Ethernet>(device);

        // Initialize ethernet layer
        if (!ethernet->init()) {
            std::cerr << "Failed to initialize ethernet layer" << std::endl;
            return 1;
        }

        // Create ARP module
        ARP arp(ethernet, local_ip);

        // Initialize ARP module
        if (!arp.init()) {
            std::cerr << "Failed to initialize ARP module" << std::endl;
            return 1;
        }

        // Display device MAC address and local IP
        std::cout << "Device: " << interface_name << std::endl;
        std::cout << "MAC address: " << macToString(ethernet->getMacAddress()) << std::endl;
        std::cout << "Local IP: " << ipToString(local_ip) << std::endl;

        // Start ARP resolution for target IP if specified
        if (target_ip != IP_ZERO) {
            std::cout << "Resolving target IP: " << ipToString(target_ip) << std::endl;
            arp.resolve(target_ip, arp_resolve_callback);
        }

        // Main loop
        std::cout << "Running ARP service (Press Ctrl+C to exit)..." << std::endl;
        while (running) {
            // Receive ethernet frames
            ethernet->receiveFrames(100); // 100ms timeout

            // Process pending ARP requests
            arp.processPendingRequests();

            // Check ARP cache timeouts
            arp.checkCacheTimeout();

            // Sleep to reduce CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        std::cout << "Exiting..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}