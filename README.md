# Toy TCP/IP Stack - C++ Implementation

A simple TCP/IP network stack implementation in C++.

## Overview

This project implements a TCP/IP stack that can capture and process network packets using raw sockets. It includes features such as Ethernet frame transmission/reception, MAC address resolution via ARP, IP packet transmission/reception, and ICMP echo request/reply functionality.

## Prerequisites

- C++17 compatible compiler
- Linux/macOS (with developer tools installed)
- Root privileges (for raw socket operations)
- libpcap development package

### macOS Setup

On macOS, install libpcap using the following command:

```bash
brew install libpcap
```

### Linux Setup

On Linux, install libpcap using the following command:

```bash
sudo apt-get install build-essential cmake libbsd-dev libpcap-dev
```

## Building

To build the project:

```bash
make
```

This will create the executables in the `bin` directory.

To build specific tests:

```bash
make build-ethernet_test
make build-arp_test
make build-ip_test
make build-icmp_test
make build-tcp_test
```

## Running Tests

Because the application uses raw sockets, it requires root privileges:

```bash
# Ethernet test
sudo ./bin/ethernet_test <interface_name>

# ARP test
sudo ./bin/arp_test <interface_name> <local_ip_address> [target_ip_address]

# IP test
sudo ./bin/ip_test <interface_name> <local_ip_address> <target_ip_address>

# ICMP test (ping functionality)
sudo ./bin/icmp_test <interface_name> <local_ip_address> <target_ip_address> [count]

# TCP test
sudo ./bin/tcp_test <interface_name> <local_ip_address> <mode> <remote_ip_address> [port]
```

## Implemented Features

- [x] Raw Socket Device
  - [x] PCAP-based packet capture
  - [x] Promiscuous mode
- [x] Ethernet
  - [x] Frame transmission/reception
  - [x] MTU support
- [x] ARP
  - [x] ARP cache management
  - [x] Automatic retransmission
  - [x] Timeout handling
- [x] IP
  - [x] IP packet transmission/reception
  - [x] Fragmentation
  - [x] Checksum verification
  - [x] Timeout handling
- [x] ICMP (implemented but not working)
  - [x] Echo request/reply
  - [x] Statistics display
- [ ] UDP
- [x] TCP (implemented but not working)
