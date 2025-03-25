#ifndef TCP_H
#define TCP_H

#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <functional>
#include <chrono>
#include <queue>
#include <list>
#include "../ip/ip.h"
#include "../common/common.h"

// Forward declarations to resolve circular dependencies
class TCP;
class TCPConnection;
class TCPSegment;

// TCP header structure (as per RFC 793)
#pragma pack(push, 1)
struct TCPHeader {
    uint16_t src_port;          // Source port
    uint16_t dst_port;          // Destination port
    uint32_t seq_num;           // Sequence number
    uint32_t ack_num;           // Acknowledgment number
    uint16_t offset_flags;      // Data offset (4 bits) + Reserved (6 bits) + Flags (6 bits)
    uint16_t window;            // Window size
    uint16_t checksum;          // Checksum
    uint16_t urgent_ptr;        // Urgent pointer
    // Options may follow
};
#pragma pack(pop)

// TCP header size constants
constexpr size_t TCP_HEADER_MIN_SIZE = sizeof(TCPHeader);
constexpr size_t TCP_HEADER_MAX_SIZE = TCP_HEADER_MIN_SIZE + 40; // Max 40 bytes of options

// TCP flags
namespace TCPFlags {
    constexpr uint16_t FIN = 0x0001;  // No more data from sender
    constexpr uint16_t SYN = 0x0002;  // Synchronize sequence numbers
    constexpr uint16_t RST = 0x0004;  // Reset the connection
    constexpr uint16_t PSH = 0x0008;  // Push function
    constexpr uint16_t ACK = 0x0010;  // Acknowledgment field is significant
    constexpr uint16_t URG = 0x0020;  // Urgent pointer field is significant
    // RFC 3168 ECN flags
    constexpr uint16_t ECE = 0x0040;  // ECN-Echo
    constexpr uint16_t CWR = 0x0080;  // Congestion Window Reduced
}

// TCP option kinds
namespace TCPOptionKind {
    constexpr uint8_t END_OF_OPTION_LIST = 0;
    constexpr uint8_t NO_OPERATION = 1;
    constexpr uint8_t MAXIMUM_SEGMENT_SIZE = 2;
    constexpr uint8_t WINDOW_SCALE = 3;
    constexpr uint8_t SACK_PERMITTED = 4;
    constexpr uint8_t SACK = 5;
    constexpr uint8_t TIMESTAMP = 8;
}

// TCP default parameters
constexpr uint16_t TCP_DEFAULT_WINDOW = 65535;
constexpr uint16_t TCP_DEFAULT_MSS = 1460;      // Typical MSS for Ethernet (1500 MTU - 40 bytes for IP+TCP headers)
constexpr uint16_t TCP_MIN_PORT = 1024;         // First non-reserved port
constexpr uint16_t TCP_MAX_PORT = 65535;        // Highest possible port number
constexpr uint32_t TCP_INITIAL_RTO = 1000;      // Initial retransmission timeout (ms)
constexpr uint32_t TCP_MAX_RTO = 60000;         // Maximum retransmission timeout (ms)
constexpr uint8_t TCP_MAX_RETRIES = 5;          // Maximum number of retransmission attempts
constexpr std::chrono::seconds TCP_MSL{60};     // Maximum Segment Lifetime (for TIME_WAIT)

// TCP socket states (as per RFC 793)
enum class TCPState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT
};

// String representation of TCP states
const char* tcpStateToString(TCPState state);

// TCP segment class
class TCPSegment {
public:
    // Constructors
    TCPSegment();
    TCPSegment(uint16_t src_port, uint16_t dst_port);

    // Create TCP segment from buffer
    static std::unique_ptr<TCPSegment> fromBuffer(const uint8_t* buffer, size_t length);

    // Header field getters/setters
    uint16_t getSourcePort() const;
    void setSourcePort(uint16_t port);

    uint16_t getDestinationPort() const;
    void setDestinationPort(uint16_t port);

    uint32_t getSequenceNumber() const;
    void setSequenceNumber(uint32_t seq);

    uint32_t getAcknowledgmentNumber() const;
    void setAcknowledgmentNumber(uint32_t ack);

    uint8_t getDataOffset() const; // In 32-bit words
    void setDataOffset(uint8_t offset);

    uint16_t getFlags() const;
    void setFlags(uint16_t flags);
    void setFlag(uint16_t flag); // Set a specific flag
    void clearFlag(uint16_t flag); // Clear a specific flag
    bool hasFlag(uint16_t flag) const; // Check if a specific flag is set

    uint16_t getWindowSize() const;
    void setWindowSize(uint16_t window);

    uint16_t getChecksum() const;
    void setChecksum(uint16_t checksum);

    uint16_t getUrgentPointer() const;
    void setUrgentPointer(uint16_t pointer);

    // Payload handling
    const std::vector<uint8_t>& getPayload() const;
    void setPayload(const uint8_t* data, size_t length);
    void setPayload(const std::vector<uint8_t>& data);

    // Calculate header checksum (including IP pseudo-header)
    uint16_t calculateChecksum(IPv4Address src_ip, IPv4Address dst_ip) const;
    void updateChecksum(IPv4Address src_ip, IPv4Address dst_ip);

    // Serialize segment to buffer
    size_t serialize(uint8_t* buffer, size_t buffer_size) const;

    // Get header size in bytes
    size_t getHeaderSize() const;

    // Get total segment size (header + payload)
    size_t getTotalSize() const;

private:
    TCPHeader header_;
    std::vector<uint8_t> payload_;
};

// TCP connection identification
struct TCPConnectionId {
    IPv4Address local_ip;
    uint16_t local_port;
    IPv4Address remote_ip;
    uint16_t remote_port;

    bool operator==(const TCPConnectionId& other) const {
        return local_ip == other.local_ip &&
               local_port == other.local_port &&
               remote_ip == other.remote_ip &&
               remote_port == other.remote_port;
    }

    // For use as a map key
    bool operator<(const TCPConnectionId& other) const {
        if (local_ip != other.local_ip) return local_ip < other.local_ip;
        if (local_port != other.local_port) return local_port < other.local_port;
        if (remote_ip != other.remote_ip) return remote_ip < other.remote_ip;
        return remote_port < other.remote_port;
    }
};

// TCP buffer entry for ordered reassembly
struct TCPDataEntry {
    uint32_t seq_num;
    std::vector<uint8_t> data;

    TCPDataEntry(uint32_t seq, const uint8_t* buffer, size_t length)
        : seq_num(seq), data(buffer, buffer + length) {}
};

// TCP timer types
enum class TCPTimerType {
    RETRANSMISSION,
    DELAYED_ACK,
    PERSIST,
    KEEPALIVE,
    TIME_WAIT
};

// Callback for data received
using TCPDataReceivedCallback = std::function<void(const uint8_t* data, size_t length)>;

// Callback for connection status changes
using TCPConnectionCallback = std::function<void(bool success)>;

// TCP connection object
class TCPConnection {
public:
    TCPConnection(std::shared_ptr<TCP> tcp, IPv4Address local_ip, uint16_t local_port,
                 IPv4Address remote_ip, uint16_t remote_port);

    // Connect to remote host
    bool connect(TCPConnectionCallback callback);

    // Send data
    bool send(const uint8_t* data, size_t length);

    // Close connection
    bool close();

    // Process an incoming segment
    void processSegment(std::unique_ptr<TCPSegment> segment);

    // Set callback for received data
    void setDataReceivedCallback(TCPDataReceivedCallback callback);

    // Get connection state
    TCPState getState() const;

    // Get connection ID
    TCPConnectionId getConnectionId() const;

private:
    // Handle different TCP states
    void handleClosedState(const TCPSegment& segment);
    void handleListenState(const TCPSegment& segment);
    void handleSynSentState(const TCPSegment& segment);
    void handleSynReceivedState(const TCPSegment& segment);
    void handleEstablishedState(const TCPSegment& segment);
    void handleFinWait1State(const TCPSegment& segment);
    void handleFinWait2State(const TCPSegment& segment);
    void handleCloseWaitState(const TCPSegment& segment);
    void handleClosingState(const TCPSegment& segment);
    void handleLastAckState(const TCPSegment& segment);
    void handleTimeWaitState(const TCPSegment& segment);

    // Send a segment
    bool sendSegment(const TCPSegment& segment);

    // Send a reset segment
    void sendReset();

    // Process received data
    void processReceivedData(const TCPSegment& segment);

    // Timer handling
    void startTimer(TCPTimerType type, std::chrono::milliseconds timeout);
    void stopTimer(TCPTimerType type);
    void handleTimeout(TCPTimerType type);

    // Connection parameters
    std::shared_ptr<TCP> tcp_;
    TCPConnectionId conn_id_;
    TCPState state_;

    // Sequence numbers
    uint32_t snd_una_;          // Send unacknowledged
    uint32_t snd_nxt_;          // Send next
    uint32_t snd_wnd_;          // Send window
    uint32_t rcv_nxt_;          // Receive next
    uint32_t rcv_wnd_;          // Receive window
    uint32_t iss_;              // Initial send sequence number
    uint32_t irs_;              // Initial receive sequence number

    // Retransmission parameters
    uint32_t rto_;              // Retransmission timeout (ms)
    std::chrono::steady_clock::time_point rtt_start_; // RTT measurement start time
    bool rtt_measuring_;        // Whether we're currently measuring RTT
    uint32_t srtt_;             // Smoothed round-trip time (ms)
    uint32_t rttvar_;           // Round-trip time variation (ms)
    uint8_t retries_;           // Number of retransmission attempts

    // Send and receive buffers
    std::vector<uint8_t> send_buffer_;
    std::vector<uint8_t> recv_buffer_;
    std::list<TCPDataEntry> out_of_order_queue_; // Out-of-order segments

    // Timers
    std::map<TCPTimerType, std::chrono::steady_clock::time_point> timers_;

    // User callbacks
    TCPDataReceivedCallback data_received_callback_;
    TCPConnectionCallback connection_callback_;

    // Mutex for thread safety
    mutable std::mutex mutex_;
};

// TCP send options
struct TCPSendOptions {
    bool push;              // Set PSH flag
    bool urgent;            // Set URG flag
    uint16_t urgent_ptr;    // Urgent pointer

    TCPSendOptions() : push(false), urgent(false), urgent_ptr(0) {}
};

// TCP listen options
struct TCPListenOptions {
    uint16_t backlog;       // Maximum connection backlog

    TCPListenOptions() : backlog(5) {}
};

// TCP layer class
class TCP : public std::enable_shared_from_this<TCP> {
public:
    // Constructor
    TCP(std::shared_ptr<IP> ip);

    // Initialize TCP layer
    bool init();

    // Active open: Connect to a remote host
    std::shared_ptr<TCPConnection> connect(IPv4Address remote_ip, uint16_t remote_port,
                                          TCPConnectionCallback callback);

    // Passive open: Listen for incoming connections
    bool listen(uint16_t local_port, TCPConnectionCallback callback,
               const TCPListenOptions& options = TCPListenOptions());

    // Stop listening on a port
    bool stopListening(uint16_t port);

    // Close all connections and stop listening
    void closeAll();

    // Process TCP timers
    void processTimers();

    // Send data through an established connection
    bool send(const TCPConnectionId& conn_id, const uint8_t* data, size_t length,
             const TCPSendOptions& options = TCPSendOptions());

    // Close a specific connection
    bool close(const TCPConnectionId& conn_id);

    // Register data received callback for a connection
    void registerDataReceivedCallback(const TCPConnectionId& conn_id,
                                     TCPDataReceivedCallback callback);

    // Get IP instance
    std::shared_ptr<IP> getIP() const;

private:
    // TCP packet handler (called by IP layer)
    void handleTCPSegment(const uint8_t* data, size_t length,
                         IPv4Address src_ip, IPv4Address dst_ip);

    // Find a connection by its ID
    std::shared_ptr<TCPConnection> findConnection(const TCPConnectionId& conn_id);

    // Create a new connection
    std::shared_ptr<TCPConnection> createConnection(IPv4Address local_ip, uint16_t local_port,
                                                  IPv4Address remote_ip, uint16_t remote_port);

    // Remove a connection
    void removeConnection(const TCPConnectionId& conn_id);

    // Allocate an ephemeral port for client connections
    uint16_t allocateEphemeralPort();

    // Reference to IP layer
    std::shared_ptr<IP> ip_;

    // Connections
    std::map<TCPConnectionId, std::shared_ptr<TCPConnection>> connections_;
    std::map<uint16_t, TCPConnectionCallback> listening_ports_;
    std::mutex connections_mutex_;

    // Next ephemeral port
    uint16_t next_ephemeral_port_;
};

// Calculate TCP checksum (including IP pseudo-header)
uint16_t calculateTCPChecksum(const void* tcp_data, size_t tcp_length,
                             IPv4Address src_ip, IPv4Address dst_ip);

#endif // TCP_H