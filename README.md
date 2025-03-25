# Toy TCP/IP Stack - C Implementation

A simplified TCP/IP networking stack implementation in C.

## Overview

This project is a C implementation of a toy TCP/IP stack that can capture and process network packets using raw sockets.

## Prerequisites

- GCC compiler
- Linux/macOS (with developer tools installed)
- Root privileges (for raw socket operations)

## Building

To build the project:

```bash
make
```

This will create the executable in the `bin` directory.

## Running

Because the application uses raw sockets, it requires root privileges:

```bash
sudo ./bin/toy-tcpip
```

Or you can use the make run target:

```bash
make run
```

## Features

- Raw socket implementation for packet capture
- Interface for network devices
- Support for promiscuous mode
- Signal handling for graceful termination

## License

This project is open-source.
