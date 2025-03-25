#include "../src/ethernet/ethernet.h"
#include "../src/device/raw_socket_device.h"
#include "../src/common/common.h"
#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>

std::atomic<bool> running{true};

void signal_handler(int signal) {
    std::cout << "Caught signal " << signal << ", exiting..." << std::endl;
    running = false;
}

// Sample handler for IP packets
void ip_packet_handler(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac) {
    std::cout << "Received IP packet from " << macToString(src_mac)
              << " to " << macToString(dst_mac)
              << ", length: " << length << std::endl;
}

// Sample handler for ARP packets
void arp_packet_handler(const uint8_t* data, size_t length,
                       const MacAddress& src_mac, const MacAddress& dst_mac) {
    std::cout << "Received ARP packet from " << macToString(src_mac)
              << " to " << macToString(dst_mac)
              << ", length: " << length << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface_name>" << std::endl;
        return 1;
    }

    std::string interface_name = argv[1];

    // Register signal handler
    std::signal(SIGINT, signal_handler);

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(interface_name);

        // Create ethernet layer
        Ethernet ethernet(device);

        // Initialize ethernet layer
        if (!ethernet.init()) {
            std::cerr << "Failed to initialize ethernet layer" << std::endl;
            return 1;
        }

        // Register protocol handlers
        ethernet.registerHandler(EtherType::IPV4, ip_packet_handler);
        ethernet.registerHandler(EtherType::ARP, arp_packet_handler);

        // Print MAC address
        std::cout << "Device MAC address: "
                  << macToString(ethernet.getMacAddress()) << std::endl;

        // Receive frames in a loop
        std::cout << "Receiving ethernet frames (Press Ctrl+C to exit)..." << std::endl;
        while (running) {
            ethernet.receiveFrames(1000); // 1 second timeout
        }

        std::cout << "Exiting..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}