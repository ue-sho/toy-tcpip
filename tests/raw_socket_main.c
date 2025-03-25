#include <signal.h>
#include <stdio.h>
#include "socket_device.h"

volatile sig_atomic_t terminate;

static void on_signal(int s) { terminate = 1; }

static void rx_handler(uint8_t *frame, size_t len, void *arg) {
  fprintf(stderr, "receive %zu octets\n", len);
}

// External functions defined in raw_socket_device.c
extern NetworkDevice* create_raw_socket_device(const char* interface_name, int mtu);
extern void destroy_raw_socket_device(NetworkDevice* device);

// Volatile flag for termination
volatile sig_atomic_t terminate;

// Signal handler for graceful termination
void signal_handler(int signum) {
    terminate = 1;
}

int main(int argc, char* argv[]) {
    // Create and initialize the device
    NetworkDevice* device = create_raw_socket_device("en0", 1500);
    if (!device) {
        fprintf(stderr, "Failed to create device\n");
        return 1;
    }

    // Set up signal handler for termination
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Open the device
    if (network_device_open(device) < 0) {
        fprintf(stderr, "Failed to open device\n");
        destroy_raw_socket_device(device);
        return 1;
    }

    printf("Device opened, waiting for packets...\n");

    // Receiving data
    while (!terminate) {
        uint8_t frame[1500]; // Adjust size as needed
        int length = network_device_receive(device, frame, sizeof(frame), rx_handler, NULL, 1000);

        if (length > 0) {
            printf("Received %d bytes\n", length);
            // Process the received frame as needed
        }
    }

    // Clean up
    network_device_close(device);
    destroy_raw_socket_device(device);

    printf("Closed\n");
    return 0;
}