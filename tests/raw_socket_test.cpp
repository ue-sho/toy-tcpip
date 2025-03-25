#include <iostream>
#include <csignal>
#include <memory>
#include <array>
#include "../src/device/raw_socket_device.h"

// Volatile flag for termination
volatile std::sig_atomic_t terminate = 0;

// Signal handler for graceful termination
void signalHandler([[maybe_unused]] int signum) {
    terminate = 1;
}

// Callback function for received packets
void rxHandler([[maybe_unused]] uint8_t *frame, size_t len, [[maybe_unused]] void *arg) {
    std::cerr << "Received " << len << " octets" << std::endl;
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    // Create and initialize the device
    auto device = std::make_unique<RawSocketDevice>("en0", 1500);

    if (!device) {
        std::cerr << "Failed to create device" << std::endl;
        return 1;
    }

    // Set up signal handler for termination
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Open the device
    if (device->open() < 0) {
        std::cerr << "Failed to open device" << std::endl;
        return 1;
    }

    std::cout << "Device opened, waiting for packets..." << std::endl;

    // Buffer for receiving data
    std::array<uint8_t, 1500> frame;

    // Receiving data
    while (!terminate) {
        int length = device->receive(frame.data(), frame.size(), rxHandler, nullptr, 1000);

        if (length > 0) {
            std::cout << "Received " << length << " bytes" << std::endl;
            // Process the received frame as needed
        }
    }

    // Clean up (handled by unique_ptr automatically)
    device->close();

    std::cout << "Closed" << std::endl;
    return 0;
}