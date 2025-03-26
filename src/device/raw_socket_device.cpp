#include "raw_socket_device.h"
#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
    #include <net/if.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <net/if_arp.h>
    #include <arpa/inet.h>
#else
    #include <net/if_dl.h>
#endif

// PcapContext class to encapsulate pcap-specific data
class PcapContext {
public:
    pcap_t* handle{nullptr};
    struct bpf_program fp{};
    char errbuf[PCAP_ERRBUF_SIZE]{};
    NetworkDevice::PacketCallback callback;
    void* callback_arg{nullptr};

    ~PcapContext() {
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
    }
};

// Static callback function for pcap_dispatch
static void pcap_callback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    auto* context = reinterpret_cast<PcapContext*>(user);
    if (context && context->callback) {
        context->callback(const_cast<uint8_t*>(bytes), h->caplen, context->callback_arg);
    }
}

// Constructor
RawSocketDevice::RawSocketDevice(const std::string& interface_name, int mtu)
    : NetworkDevice(interface_name, mtu),
      context_(std::make_unique<PcapContext>())
{
}

// Destructor
RawSocketDevice::~RawSocketDevice() {
    close();
}

// Get MAC address of the interface
int RawSocketDevice::getMacAddress() {
#ifdef __linux__
    // Linux specific implementation
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket for MAC address retrieval" << std::endl;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "ioctl failed on interface " << name_ << std::endl;
        ::close(sock);
        return -1;
    }

    // Copy MAC address
    for (int i = 0; i < 6; i++) {
        mac_address_[i] = static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
    }

    ::close(sock);
    return 0;
#else
    // BSD implementation (Mac OS X, FreeBSD, etc.)
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
            if (name_ == ifaptr->ifa_name &&
                ifaptr->ifa_addr->sa_family == AF_LINK) {
                ptr = reinterpret_cast<unsigned char*>(LLADDR(
                    reinterpret_cast<struct sockaddr_dl*>(ifaptr->ifa_addr)));
                for (size_t i = 0; i < 6; i++) {
                    mac_address_[i] = ptr[i];
                }
                freeifaddrs(ifap);
                return 0;
            }
        }
        freeifaddrs(ifap);
    }
    return -1;
#endif
}

// Open the device for packet capture
int RawSocketDevice::open() {
    if (isOpen()) {
        return 0; // Already open
    }

    if (!context_) {
        std::cerr << "Invalid pcap context" << std::endl;
        return -1;
    }

    // Open the device for capturing
    context_->handle = pcap_open_live(name_.c_str(), mtu_, 1, 1000, context_->errbuf);
    if (!context_->handle) {
        std::cerr << "Couldn't open device " << name_ << ": "
                  << context_->errbuf << std::endl;
        return -1;
    }

    // Set filter to capture only IPv4 and ARP packets
    std::string filter_exp = "arp or ip";
    if (pcap_compile(context_->handle, &context_->fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": "
                  << pcap_geterr(context_->handle) << std::endl;
        context_->handle = nullptr;
        return -1;
    }

    if (pcap_setfilter(context_->handle, &context_->fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": "
                  << pcap_geterr(context_->handle) << std::endl;
        pcap_freecode(&context_->fp);
        context_->handle = nullptr;
        return -1;
    }

    // Get link-layer header type
    int datalink = pcap_datalink(context_->handle);
    std::cout << "Device " << name_ << " datalink type: " << datalink << std::endl;

    // Get MAC address
    if (getMacAddress() < 0) {
        std::cerr << "Failed to get MAC address for " << name_ << std::endl;
        pcap_freecode(&context_->fp);
        context_->handle = nullptr;
        return -1;
    }

    // Set non-blocking mode
    if (pcap_setnonblock(context_->handle, 1, context_->errbuf) != 0) {
        std::cerr << "Failed to set non-blocking mode: "
                  << context_->errbuf << std::endl;
        pcap_freecode(&context_->fp);
        context_->handle = nullptr;
        return -1;
    }

    std::cout << "Device opened on interface " << name_ << ". MAC address: "
              << std::hex << static_cast<int>(mac_address_[0]) << ":"
              << static_cast<int>(mac_address_[1]) << ":"
              << static_cast<int>(mac_address_[2]) << ":"
              << static_cast<int>(mac_address_[3]) << ":"
              << static_cast<int>(mac_address_[4]) << ":"
              << static_cast<int>(mac_address_[5]) << std::dec
              << std::endl;

    return 0;
}

// Close the device
void RawSocketDevice::close() {
    if (context_) {
        if (context_->handle) {
            pcap_freecode(&context_->fp);
            context_->handle = nullptr;
        }
    }
}

// Send data through the device
int RawSocketDevice::send(uint8_t* buffer, int length) {
    if (!isOpen()) {
        std::cerr << "Device not open" << std::endl;
        return -1;
    }

    int result = pcap_inject(context_->handle, buffer, length);
    if (result < 0) {
        std::cerr << "Failed to inject packet: "
                  << pcap_geterr(context_->handle) << std::endl;
    }

    return result;
}

// Receive data from the device
int RawSocketDevice::receive(const PacketCallback& callback, void* arg, int timeout) {
    if (!isOpen()) {
        std::cerr << "Device not open" << std::endl;
        return -1;
    }

    // Store callback information
    context_->callback = callback;
    context_->callback_arg = arg;

    // Handle timeout
    if (timeout > 0) {
        fd_set readfds;
        struct timeval tv;
        int fd = pcap_get_selectable_fd(context_->handle);

        if (fd < 0) {
            std::cerr << "pcap_get_selectable_fd failed" << std::endl;
            return -1;
        }

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        int ret = select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if (ret <= 0) {
            if (ret < 0 && errno != EINTR) {
                perror("select");
            }
            return ret; // Timeout or error
        }
    }

    // Process packets
    int count = pcap_dispatch(context_->handle, 1, pcap_callback,
                             reinterpret_cast<u_char*>(context_.get()));
    if (count < 0) {
        std::cerr << "pcap_dispatch error: "
                  << pcap_geterr(context_->handle) << std::endl;
        return -1;
    }

    return count;
}

// Check if the device is open
bool RawSocketDevice::isOpen() const {
    return context_ && context_->handle;
}