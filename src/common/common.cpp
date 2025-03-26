#include "common.h"
#include <sstream>
#include <arpa/inet.h>
#include <iomanip>

std::string macToString(const MacAddress& mac) {
    std::stringstream ss;
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) ss << ':';
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

MacAddress stringToMac(const std::string& mac_str) {
    MacAddress mac = {0};

    // Parse MAC address string
    int values[6];
    int count = std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                           &values[0], &values[1], &values[2],
                           &values[3], &values[4], &values[5]);

    if (count == 6) {
        for (int i = 0; i < 6; ++i) {
            mac[i] = static_cast<uint8_t>(values[i]);
        }
    }

    return mac;
}

std::string ipToString(IPv4Address ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
    return std::string(str);
}

IPv4Address stringToIp(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address format");
    }
    return ntohl(addr.s_addr);
}

bool parseIpAddress(const std::string& ip_str, IPv4Address& ip) {
    struct in_addr addr;
    int result = inet_pton(AF_INET, ip_str.c_str(), &addr);

    if (result <= 0) {
        return false;
    }

    ip = ntohl(addr.s_addr);
    return true;
}
