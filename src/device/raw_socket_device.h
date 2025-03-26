#ifndef RAW_SOCKET_DEVICE_H
#define RAW_SOCKET_DEVICE_H

#include "network_device.h"
#include <pcap.h>
#include <memory>

// Forward declaration for internal implementation details
class PcapContext;

// RawSocketDevice class that uses pcap for packet capture
class RawSocketDevice : public NetworkDevice {
public:
    // Constructor and destructor
    RawSocketDevice(const std::string& interface_name, int mtu = 1500);
    ~RawSocketDevice() override;

    // Implementation of NetworkDevice interface
    int open() override;
    void close() override;
    int send(uint8_t* buffer, int length) override;
    int receive(const PacketCallback& callback, void* arg, int timeout) override;
    bool isOpen() const override;

private:
    // Get MAC address of the interface
    int getMacAddress();

    // PIMPL idiom - hides pcap details
    std::unique_ptr<PcapContext> context_;
};

#endif // RAW_SOCKET_DEVICE_H