#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <mutex>
#include <condition_variable>

#include "../src/device/raw_socket_device.h"
#include "../src/ethernet/ethernet.h"
#include "../src/arp/arp.h"
#include "../src/ip/ip.h"
#include "../src/tcp/tcp.h"
#include "../src/common/common.h"

bool running = true;

// Signal handler for clean termination
void signalHandler(int signum) {
    std::cout << "Signal " << signum << " received. Terminating..." << std::endl;
    running = false;
}

// Mode options
enum class Mode {
    SERVER,
    CLIENT
};

// Connection status flags
struct ConnectionStatus {
    bool connected;
    bool data_sent;
    bool data_received;
    std::mutex mutex;
    std::condition_variable cv;

    ConnectionStatus() : connected(false), data_sent(false), data_received(false) {}
};

// Print connection status
void printConnectionStatus(const ConnectionStatus& status) {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(status.mutex));
    std::cout << "Connection status:" << std::endl;
    std::cout << "  Connected: " << (status.connected ? "Yes" : "No") << std::endl;
    std::cout << "  Data sent: " << (status.data_sent ? "Yes" : "No") << std::endl;
    std::cout << "  Data received: " << (status.data_received ? "Yes" : "No") << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <interface> <local_ip> <mode> <remote_ip> [port]" << std::endl;
        std::cerr << "  mode: server or client" << std::endl;
        return 1;
    }

    const char* interface_name = argv[1];
    const char* local_ip_str = argv[2];
    const char* mode_str = argv[3];
    const char* remote_ip_str = argv[4];
    uint16_t port = (argc >= 6) ? std::atoi(argv[5]) : 8080;  // Default port 8080

    // Parse mode
    Mode mode;
    if (std::string(mode_str) == "server") {
        mode = Mode::SERVER;
    } else if (std::string(mode_str) == "client") {
        mode = Mode::CLIENT;
    } else {
        std::cerr << "Invalid mode: " << mode_str << std::endl;
        std::cerr << "Mode must be 'server' or 'client'" << std::endl;
        return 1;
    }

    // Parse IP addresses
    IPv4Address local_ip;
    if (!parseIpAddress(local_ip_str, local_ip)) {
        std::cerr << "Invalid local IP address: " << local_ip_str << std::endl;
        return 1;
    }

    IPv4Address remote_ip;
    if (!parseIpAddress(remote_ip_str, remote_ip)) {
        std::cerr << "Invalid remote IP address: " << remote_ip_str << std::endl;
        return 1;
    }

    // Register signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Connection status
    ConnectionStatus status;

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(interface_name);
        if (device->open() == -1) {
            std::cerr << "Failed to initialize device: " << interface_name << std::endl;
            return 1;
        }
        std::cout << "Network device initialized successfully" << std::endl;

        // Create ethernet layer
        auto ethernet = std::make_shared<Ethernet>(device);
        if (!ethernet->init()) {
            std::cerr << "Failed to initialize ethernet layer" << std::endl;
            return 1;
        }
        std::cout << "Ethernet layer initialized successfully" << std::endl;

        // Create ARP module
        auto arp = std::make_shared<ARP>(ethernet, local_ip);
        if (!arp->init()) {
            std::cerr << "Failed to initialize ARP module" << std::endl;
            return 1;
        }
        std::cout << "ARP module initialized successfully" << std::endl;

        // Create IP layer
        auto ip = std::make_shared<IP>(ethernet, arp, local_ip);
        if (!ip->init()) {
            std::cerr << "Failed to initialize IP module" << std::endl;
            return 1;
        }
        std::cout << "IP layer initialized successfully" << std::endl;

        // Create TCP layer
        auto tcp = std::make_shared<TCP>(ip);
        if (!tcp->init()) {
            std::cerr << "Failed to initialize TCP module" << std::endl;
            return 1;
        }
        std::cout << "TCP layer initialized successfully" << std::endl;

        // TCP connection
        std::shared_ptr<TCPConnection> connection;
        TCPConnectionId conn_id;

        if (mode == Mode::SERVER) {
            std::cout << "Starting TCP server on port " << port << std::endl;

            // Listen for connections
            if (!tcp->listen(port, [&](bool success) {
                std::cout << "Connection " << (success ? "accepted" : "failed") << std::endl;
                std::lock_guard<std::mutex> lock(status.mutex);
                status.connected = success;
                status.cv.notify_all();
            })) {
                std::cerr << "Failed to listen on port " << port << std::endl;
                return 1;
            }

            std::cout << "Listening for connections..." << std::endl;

        } else { // CLIENT mode
            std::cout << "Connecting to " << remote_ip_str << ":" << port << std::endl;

            // Connect to remote server
            connection = tcp->connect(remote_ip, port, [&](bool success) {
                std::cout << "Connection callback received - "
                          << (success ? "success" : "failure") << std::endl;
                std::lock_guard<std::mutex> lock(status.mutex);
                status.connected = success;
                status.cv.notify_all();
            });

            if (!connection) {
                std::cerr << "Failed to initiate connection" << std::endl;
                return 1;
            }
            std::cout << "Connection object created successfully" << std::endl;

            // Get connection ID
            conn_id = connection->getConnectionId();
            std::cout << "Connection ID: local=" << conn_id.local_ip << ":"
                      << conn_id.local_port << ", remote=" << conn_id.remote_ip
                      << ":" << conn_id.remote_port << std::endl;

            // Register data received callback
            tcp->registerDataReceivedCallback(conn_id, [&](const uint8_t* data, size_t length) {
                std::string received_data(reinterpret_cast<const char*>(data), length);
                std::cout << "Received data: " << received_data << std::endl;

                std::lock_guard<std::mutex> lock(status.mutex);
                status.data_received = true;
                status.cv.notify_all();
            });
            std::cout << "Data received callback registered" << std::endl;
        }

        // Main loop
        auto start_time = std::chrono::steady_clock::now();
        bool data_sent = false;

        while (running) {
            // Process network layers
            ethernet->receiveFrames(100);
            arp->processArpTimeouts();
            ip->processFragmentTimeouts();
            tcp->processTimers();

            if (mode == Mode::CLIENT) {
                // Wait for connection to be established
                {
                    std::unique_lock<std::mutex> lock(status.mutex);
                    if (!status.connected) {
                        status.cv.wait_for(lock, std::chrono::milliseconds(100), [&] {
                            return status.connected;
                        });
                    }
                }

                // Send data when connected and not already sent
                if (status.connected && !data_sent) {
                    // Wait a moment to let connection stabilize
                    std::this_thread::sleep_for(std::chrono::seconds(1));

                    std::string message = "Hello from TCP client!";
                    std::cout << "Sending message: " << message << std::endl;

                    if (tcp->send(conn_id,
                                  reinterpret_cast<const uint8_t*>(message.c_str()),
                                  message.length())) {
                        data_sent = true;
                        std::lock_guard<std::mutex> lock(status.mutex);
                        status.data_sent = true;
                    } else {
                        std::cerr << "Failed to send data" << std::endl;
                    }
                }

                // Check if we're done (received a response)
                {
                    std::lock_guard<std::mutex> lock(status.mutex);
                    if (status.data_sent && status.data_received) {
                        std::cout << "Data exchange complete, closing connection" << std::endl;
                        tcp->close(conn_id);
                        break;
                    }
                }
            }

            // Check timeout
            auto now = std::chrono::steady_clock::now();
            if (now - start_time > std::chrono::seconds(30)) {
                std::cout << "Timeout" << std::endl;
                break;
            }

            // Sleep to reduce CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Print final status
        printConnectionStatus(status);

        // Cleanup
        tcp->closeAll();

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Exiting..." << std::endl;
    return 0;
}