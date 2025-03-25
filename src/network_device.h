#ifndef NETWORK_DEVICE_H
#define NETWORK_DEVICE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Network device structure
typedef struct {
    char* name;              // Interface name (e.g., "en0")
    int mtu;                 // Maximum Transmission Unit
    uint8_t mac_address[6];  // MAC address of the device
    int fd;                  // Socket file descriptor
    int ifindex;             // Interface index
    void* user_data;         // User data pointer (for pcap context)
} NetworkDevice;

// Function declarations
int network_device_open(NetworkDevice* device);
void network_device_close(NetworkDevice* device);
int network_device_send(NetworkDevice* device, uint8_t* buffer, int length);
int network_device_receive(NetworkDevice* device, uint8_t* buffer, int buffer_size, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout);
bool network_device_is_open(NetworkDevice* device);

#endif // NETWORK_DEVICE_H