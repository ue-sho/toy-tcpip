#include "network_device.h"
#include <cstring>
#include <iostream>

NetworkDevice::NetworkDevice(const std::string& interface_name, int mtu)
    : name_(interface_name),
      mtu_(mtu > 0 ? mtu : 1500),
      mac_address_({0, 0, 0, 0, 0, 0})
{
}

NetworkDevice::~NetworkDevice() {
    // Virtual destructor to ensure proper cleanup in derived classes
}