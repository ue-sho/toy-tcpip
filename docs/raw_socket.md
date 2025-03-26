# Raw Socket Implementation

## Overview

The Raw Socket implementation provides a low-level network interface for sending and receiving Ethernet frames directly. It serves as the foundation of our TCP/IP stack, allowing direct access to network interfaces.

## Architecture

The implementation is divided into two main classes:

1. **NetworkDevice** (Abstract Base Class)
   - Defines the common interface for all network devices
   - Provides methods for packet sending and receiving

2. **RawSocketDevice** (Concrete Implementation)
   - Implements the NetworkDevice interface using libpcap
   - Handles the details of packet capture and transmission

## NetworkDevice Interface

The `NetworkDevice` class defines the following interface:

```cpp
class NetworkDevice {
public:
    // Callback type for received packets
    using PacketCallback = std::function<void(uint8_t*, size_t, void*)>;

    // Constructor and destructor
    NetworkDevice(const std::string& interface_name, int mtu = 1500);
    virtual ~NetworkDevice();

    // Interface methods
    virtual int open() = 0;
    virtual void close() = 0;
    virtual int send(uint8_t* buffer, int length) = 0;
    virtual int receive(uint8_t* buffer, int buffer_size,
                       const PacketCallback& callback, void* arg, int timeout) = 0;
    virtual bool isOpen() const = 0;

    // Common getters
    const std::string& getName() const;
    int getMtu() const;
    const uint8_t* getMacAddress() const;

protected:
    std::string name_;          // Interface name (e.g., "en0")
    int mtu_;                   // Maximum Transmission Unit
    uint8_t mac_address_[6];    // MAC address of the device
};
```

## RawSocketDevice Implementation

The `RawSocketDevice` class provides a concrete implementation using the libpcap library:

```cpp
class RawSocketDevice : public NetworkDevice {
public:
    // Constructor and destructor
    RawSocketDevice(const std::string& interface_name, int mtu = 1500);
    ~RawSocketDevice() override;

    // Implementation of NetworkDevice interface
    int open() override;
    void close() override;
    int send(uint8_t* buffer, int length) override;
    int receive(uint8_t* buffer, int buffer_size,
               const PacketCallback& callback, void* arg, int timeout) override;
    bool isOpen() const override;

private:
    // Get MAC address of the interface
    int getMacAddress();

    // PIMPL idiom - hides pcap details
    std::unique_ptr<PcapContext> context_;
};
```

## Key Features

1. **Packet Capture**: Uses libpcap to capture raw Ethernet frames from network interfaces.
2. **Packet Transmission**: Sends raw Ethernet frames directly to the network.
3. **Callback-based Reception**: Uses a callback mechanism to handle received packets.
4. **Platform Independence**: The implementation works on both Linux and macOS, utilizing appropriate system APIs.
5. **Timeout Support**: Allows specifying a timeout for packet reception.

## Usage Example

```cpp
#include "raw_socket_device.h"
#include <iostream>
#include <memory>

// Packet reception callback
void packet_handler(uint8_t* buffer, size_t length, void* arg) {
    std::cout << "Received packet of length: " << length << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface_name>" << std::endl;
        return 1;
    }

    try {
        // Create network device
        auto device = std::make_shared<RawSocketDevice>(argv[1]);

        // Open the device
        if (device->open() < 0) {
            std::cerr << "Failed to open device" << std::endl;
            return 1;
        }

        std::cout << "Device opened successfully" << std::endl;

        // Receive packets with a 1 second timeout
        device->receive(packet_handler, nullptr, 1000);

        // Close the device
        device->close();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

## Implementation Details

1. **PIMPL Idiom**: Uses the PIMPL (Pointer to Implementation) pattern to hide the libpcap implementation details.
2. **Thread Safety**: The current implementation is not thread-safe; concurrent calls to send/receive are not supported.
3. **Error Handling**: Uses return codes to indicate success or failure, with detailed error messages printed to stderr.
4. **MAC Address Resolution**: Automatically resolves the MAC address of the specified interface during initialization.

## Limitations

1. The implementation requires root/admin privileges to access the raw network interface.
2. It does not handle network interface state changes (e.g., if the interface goes down during operation).
3. No built-in filtering mechanism is provided; all Ethernet frames on the interface are captured.

## Future Improvements

1. Add support for packet filtering.
2. Implement thread safety for concurrent operations.
3. Add support for promiscuous mode.
4. Enhance error reporting with more detailed error codes.
5. Add support for additional network device types (e.g., tap devices).