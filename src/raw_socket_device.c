#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <errno.h>
#include "network_device.h"

// Initialize a raw socket device
NetworkDevice* create_raw_socket_device(const char* interface_name, int mtu) {
    NetworkDevice* device = (NetworkDevice*)malloc(sizeof(NetworkDevice));
    if (!device) {
        perror("Failed to allocate memory for device");
        return NULL;
    }

    // Initialize the device structure
    device->name = strdup(interface_name);
    device->mtu = mtu > 0 ? mtu : 1500; // Default MTU if not specified
    device->fd = -1;
    device->ifindex = -1;
    memset(device->mac_address, 0, sizeof(device->mac_address));

    return device;
}

// Free network device resources
void destroy_raw_socket_device(NetworkDevice* device) {
    if (device) {
        network_device_close(device);
        if (device->name) {
            free(device->name);
        }
        free(device);
    }
}

// Open the raw socket device
int network_device_open(NetworkDevice* device) {
    if (network_device_is_open(device)) {
        return 0; // Already open
    }

    // Create a raw socket
    device->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (device->fd < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device->name, IFNAMSIZ - 1);

    // Get interface index
    if (ioctl(device->fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(device->fd);
        device->fd = -1;
        return -1;
    }
    device->ifindex = ifr.ifr_ifindex;

    // Get MAC address
    if (ioctl(device->fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(device->fd);
        device->fd = -1;
        return -1;
    }
    memcpy(device->mac_address, ifr.ifr_hwaddr.sa_data, 6);

    // Bind to the interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = device->ifindex;

    if (bind(device->fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Failed to bind to interface");
        close(device->fd);
        device->fd = -1;
        return -1;
    }

    // Enable promiscuous mode
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device->name, IFNAMSIZ - 1);

    if (ioctl(device->fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Failed to get interface flags");
        close(device->fd);
        device->fd = -1;
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(device->fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Failed to set interface to promiscuous mode");
        close(device->fd);
        device->fd = -1;
        return -1;
    }

    printf("Raw socket opened on interface %s (index=%d). MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           device->name, device->ifindex,
           device->mac_address[0], device->mac_address[1], device->mac_address[2],
           device->mac_address[3], device->mac_address[4], device->mac_address[5]);

    return 0;
}

// Close the raw socket device
void network_device_close(NetworkDevice* device) {
    if (device && device->fd >= 0) {
        // Disable promiscuous mode
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device->name, IFNAMSIZ - 1);

        if (ioctl(device->fd, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags &= ~IFF_PROMISC;
            ioctl(device->fd, SIOCSIFFLAGS, &ifr);
        }

        close(device->fd);
        device->fd = -1;
    }
}

// Send data through the raw socket
int network_device_send(NetworkDevice* device, uint8_t* buffer, int length) {
    if (!network_device_is_open(device)) {
        fprintf(stderr, "Device not open\n");
        return -1;
    }

    return send(device->fd, buffer, length, 0);
}

// Receive data from the raw socket
int network_device_receive(NetworkDevice* device, uint8_t* buffer, int buffer_size, void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    if (!network_device_is_open(device)) {
        fprintf(stderr, "Device not open\n");
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = device->fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, timeout);
    switch (ret) {
        case -1:
            if (errno != EINTR) {
                perror("poll");
            }
            return -1;
        case 0: // timeout
            return 0; // No data received
    }

    ssize_t len = recv(device->fd, buffer, buffer_size, 0);
    if (len < 0) {
        perror("recv");
        return -1;
    }

    // Call the callback function with the received data
    callback(buffer, len, arg);
    return len;
}

// Check if the device is open
bool network_device_is_open(NetworkDevice* device) {
    return device && device->fd >= 0;
}