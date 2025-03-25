#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <string>
#include <array>

// Ethernet MAC address (6 bytes)
using MacAddress = std::array<uint8_t, 6>;

// Special MAC addresses
const MacAddress MAC_BROADCAST = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const MacAddress MAC_ZERO = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Convert MAC address to string
std::string macToString(const MacAddress& mac);

// Convert string to MAC address
MacAddress stringToMac(const std::string& mac_str);

// Type for representing IPv4 addresses
using IPv4Address = uint32_t;

// Special IPv4 addresses
constexpr IPv4Address IP_ZERO = 0x00000000;
constexpr IPv4Address IP_BROADCAST = 0xFFFFFFFF;

// Convert IPv4 address to string representation
std::string ipToString(IPv4Address ip);

// Convert string to IPv4 address
IPv4Address stringToIp(const std::string& ip_str);

bool parseIpAddress(const std::string& ip_str, IPv4Address& ip);

#endif // COMMON_H