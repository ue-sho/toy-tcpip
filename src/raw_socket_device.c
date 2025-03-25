#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/poll.h>
#include <pcap.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include "network_device.h"

// Helper function to get MAC address on macOS
static int get_mac_address(const char *interface_name, uint8_t *mac_address) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
            if (!strcmp(ifaptr->ifa_name, interface_name) &&
                ifaptr->ifa_addr->sa_family == AF_LINK) {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)ifaptr->ifa_addr);
                memcpy(mac_address, ptr, 6);
                freeifaddrs(ifap);
                return 0;
            }
        }
        freeifaddrs(ifap);
    }
    return -1;
}

// Pcap context to hold pcap-specific data
typedef struct {
    pcap_t *handle;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    void (*callback)(uint8_t *, size_t, void *);
    void *callback_arg;
} PcapContext;

// Initialize a raw socket device using pcap
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

    // Create pcap context
    PcapContext *context = (PcapContext *)malloc(sizeof(PcapContext));
    if (!context) {
        perror("Failed to allocate memory for pcap context");
        free(device->name);
        free(device);
        return NULL;
    }

    memset(context, 0, sizeof(PcapContext));
    device->user_data = context;

    return device;
}

// Free network device resources
void destroy_raw_socket_device(NetworkDevice* device) {
    if (device) {
        network_device_close(device);
        if (device->name) {
            free(device->name);
        }
        if (device->user_data) {
            free(device->user_data);
        }
        free(device);
    }
}

// Callback for pcap_dispatch - will call the user's callback
static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    PcapContext *context = (PcapContext *)user;
    if (context->callback) {
        context->callback((uint8_t *)bytes, h->caplen, context->callback_arg);
    }
}

// Open the raw socket device
int network_device_open(NetworkDevice* device) {
    if (network_device_is_open(device)) {
        return 0; // Already open
    }

    PcapContext *context = (PcapContext *)device->user_data;
    if (!context) {
        fprintf(stderr, "Invalid pcap context\n");
        return -1;
    }

    // Open the device for capturing
    context->handle = pcap_open_live(device->name, device->mtu, 1, 1000, context->errbuf);
    if (context->handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, context->errbuf);
        return -1;
    }

    // Get MAC address
    if (get_mac_address(device->name, device->mac_address) < 0) {
        fprintf(stderr, "Failed to get MAC address for %s\n", device->name);
        pcap_close(context->handle);
        context->handle = NULL;
        return -1;
    }

    // Set non-blocking mode
    if (pcap_setnonblock(context->handle, 1, context->errbuf) != 0) {
        fprintf(stderr, "Failed to set non-blocking mode: %s\n", context->errbuf);
        pcap_close(context->handle);
        context->handle = NULL;
        return -1;
    }

    printf("Device opened on interface %s. MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           device->name,
           device->mac_address[0], device->mac_address[1], device->mac_address[2],
           device->mac_address[3], device->mac_address[4], device->mac_address[5]);

    return 0;
}

// Close the raw socket device
void network_device_close(NetworkDevice* device) {
    PcapContext *context = (PcapContext *)device->user_data;
    if (context && context->handle) {
        pcap_close(context->handle);
        context->handle = NULL;
    }
}

// Send data through the pcap device
int network_device_send(NetworkDevice* device, uint8_t* buffer, int length) {
    PcapContext *context = (PcapContext *)device->user_data;
    if (!context || !context->handle) {
        fprintf(stderr, "Device not open\n");
        return -1;
    }

    return pcap_inject(context->handle, buffer, length);
}

// Receive data from the pcap device
int network_device_receive(NetworkDevice* device, uint8_t* buffer, int buffer_size,
                          void (*callback)(uint8_t *, size_t, void *), void *arg, int timeout) {
    PcapContext *context = (PcapContext *)device->user_data;
    if (!context || !context->handle) {
        fprintf(stderr, "Device not open\n");
        return -1;
    }

    // Store callback information
    context->callback = callback;
    context->callback_arg = arg;

    // Handle timeout
    if (timeout > 0) {
        fd_set readfds;
        struct timeval tv;
        int fd = pcap_get_selectable_fd(context->handle);

        if (fd < 0) {
            fprintf(stderr, "pcap_get_selectable_fd failed\n");
            return -1;
        }

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        int ret = select(fd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) {
            if (ret < 0 && errno != EINTR) {
                perror("select");
            }
            return ret; // Timeout or error
        }
    }

    // Process packets
    int count = pcap_dispatch(context->handle, 1, pcap_callback, (u_char *)context);
    if (count < 0) {
        fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(context->handle));
        return -1;
    }

    return count;
}

// Check if the device is open
bool network_device_is_open(NetworkDevice* device) {
    if (!device || !device->user_data) {
        return false;
    }

    PcapContext *context = (PcapContext *)device->user_data;
    return context->handle != NULL;
}