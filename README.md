# Toy TCP/IP Stack - C++ Implementation

A simplified TCP/IP networking stack implementation in C++.

## Overview

This project is a C++ implementation of a toy TCP/IP stack that can capture and process network packets using raw sockets.

## Prerequisites

- C++17 compatible compiler
- Linux/macOS (with developer tools installed)
- Root privileges (for raw socket operations)
- libpcap development package

## Building

To build the project:

```bash
make
```

This will create the executables in the `bin` directory.

## Running Tests

Because the application uses raw sockets, it requires root privileges:

```bash
sudo ./bin/ethernet_test <interface_name>
```

Or you can use the make run target:

```bash
make run-ethernet_test
```

## Features

- [x] Raw Device
  - [x] tap device on Linux
  - [x] PF_PACKET socket on Linux
  - [ ] tap device on BSD
  - [ ] BFP on BSD
- [x] Ethernet
- [ ] ARP
- [ ] IP
  - [ ] ip_tx
  - [ ] ip_rx
  - [ ] Fragmentation
  - [ ] Checksum
  - [ ] Routing
  - [ ] Packet Forwarding
  - [ ] Dynamic network device selection by IP Address
- [ ] ICMP
- [ ] DHCP
- [ ] TCP
- [ ] UDP

## Documentation

Detailed documentation for each component is available in the `docs` directory:

- [Raw Socket Implementation](docs/raw_socket.md) - Base network interface implementation
- [Ethernet Layer](docs/ethernet.md) - Ethernet frame handling implementation

## License

This project is open-source.
