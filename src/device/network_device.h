#ifndef NETWORK_DEVICE_H
#define NETWORK_DEVICE_H

#include <cstdint>
#include <string>
#include <memory>
#include <functional>

// NetworkDevice class declaration
class NetworkDevice {
public:
    // Callback type for received packets
    using PacketCallback = std::function<void(uint8_t*, size_t, void*)>;

    // Constructor and destructor
    NetworkDevice(const std::string& interface_name, int mtu = 1500);
    virtual ~NetworkDevice();

    // Delete copy constructor and assignment operator
    NetworkDevice(const NetworkDevice&) = delete;
    NetworkDevice& operator=(const NetworkDevice&) = delete;

    // Interface methods
    virtual int open() = 0;
    virtual void close() = 0;
    virtual int send(uint8_t* buffer, int length) = 0;
    virtual int receive(uint8_t* buffer, int buffer_size,
                       const PacketCallback& callback, void* arg, int timeout) = 0;
    virtual bool isOpen() const = 0;

    // Common getters
    const std::string& getName() const { return name_; }
    int getMtu() const { return mtu_; }
    const uint8_t* getMacAddress() const { return mac_address_; }

protected:
    std::string name_;          // Interface name (e.g., "en0")
    int mtu_;                   // Maximum Transmission Unit
    uint8_t mac_address_[6];    // MAC address of the device
};

#endif // NETWORK_DEVICE_H