#include "tcp.h"
#include <cstring>
#include <iostream>
#include <random>
#include <algorithm>
#include <arpa/inet.h>

// String representation of TCP states
const char* tcpStateToString(TCPState state) {
    switch (state) {
        case TCPState::CLOSED:       return "CLOSED";
        case TCPState::LISTEN:       return "LISTEN";
        case TCPState::SYN_SENT:     return "SYN_SENT";
        case TCPState::SYN_RECEIVED: return "SYN_RECEIVED";
        case TCPState::ESTABLISHED:  return "ESTABLISHED";
        case TCPState::FIN_WAIT_1:   return "FIN_WAIT_1";
        case TCPState::FIN_WAIT_2:   return "FIN_WAIT_2";
        case TCPState::CLOSE_WAIT:   return "CLOSE_WAIT";
        case TCPState::CLOSING:      return "CLOSING";
        case TCPState::LAST_ACK:     return "LAST_ACK";
        case TCPState::TIME_WAIT:    return "TIME_WAIT";
        default:                     return "UNKNOWN";
    }
}

// TCP Segment implementation

TCPSegment::TCPSegment() {
    // Initialize header with zeros
    std::memset(&header_, 0, sizeof(header_));

    // Set default data offset (5 32-bit words = 20 bytes, no options)
    setDataOffset(5);

    // Set default window size
    setWindowSize(TCP_DEFAULT_WINDOW);
}

TCPSegment::TCPSegment(uint16_t src_port, uint16_t dst_port) : TCPSegment() {
    setSourcePort(src_port);
    setDestinationPort(dst_port);
}

std::unique_ptr<TCPSegment> TCPSegment::fromBuffer(const uint8_t* buffer, size_t length) {
    if (length < TCP_HEADER_MIN_SIZE) {
        // Buffer too small for TCP header
        return nullptr;
    }

    auto segment = std::make_unique<TCPSegment>();

    // Copy the header
    std::memcpy(&segment->header_, buffer, TCP_HEADER_MIN_SIZE);

    // Convert network byte order to host byte order
    segment->header_.src_port = ntohs(segment->header_.src_port);
    segment->header_.dst_port = ntohs(segment->header_.dst_port);
    segment->header_.seq_num = ntohl(segment->header_.seq_num);
    segment->header_.ack_num = ntohl(segment->header_.ack_num);
    segment->header_.offset_flags = ntohs(segment->header_.offset_flags);
    segment->header_.window = ntohs(segment->header_.window);
    segment->header_.checksum = ntohs(segment->header_.checksum);
    segment->header_.urgent_ptr = ntohs(segment->header_.urgent_ptr);

    // Get data offset in bytes (data offset is in 32-bit words)
    size_t header_size = segment->getHeaderSize();

    // Check if the buffer contains the complete header
    if (length < header_size) {
        return nullptr;
    }

    // Copy payload if present
    if (length > header_size) {
        segment->setPayload(buffer + header_size, length - header_size);
    }

    return segment;
}

uint16_t TCPSegment::getSourcePort() const {
    return header_.src_port;
}

void TCPSegment::setSourcePort(uint16_t port) {
    header_.src_port = port;
}

uint16_t TCPSegment::getDestinationPort() const {
    return header_.dst_port;
}

void TCPSegment::setDestinationPort(uint16_t port) {
    header_.dst_port = port;
}

uint32_t TCPSegment::getSequenceNumber() const {
    return header_.seq_num;
}

void TCPSegment::setSequenceNumber(uint32_t seq) {
    header_.seq_num = seq;
}

uint32_t TCPSegment::getAcknowledgmentNumber() const {
    return header_.ack_num;
}

void TCPSegment::setAcknowledgmentNumber(uint32_t ack) {
    header_.ack_num = ack;
}

uint8_t TCPSegment::getDataOffset() const {
    return (header_.offset_flags >> 12) & 0x0F;
}

void TCPSegment::setDataOffset(uint8_t offset) {
    // Clear the data offset bits and set the new value
    header_.offset_flags &= 0x0FFF;  // Clear top 4 bits
    header_.offset_flags |= (static_cast<uint16_t>(offset) << 12);
}

uint16_t TCPSegment::getFlags() const {
    return header_.offset_flags & 0x003F;  // Bottom 6 bits are flags
}

void TCPSegment::setFlags(uint16_t flags) {
    // Clear the flags bits and set the new value
    header_.offset_flags &= 0xFFC0;  // Clear bottom 6 bits
    header_.offset_flags |= (flags & 0x003F);
}

void TCPSegment::setFlag(uint16_t flag) {
    header_.offset_flags |= (flag & 0x003F);
}

void TCPSegment::clearFlag(uint16_t flag) {
    header_.offset_flags &= ~(flag & 0x003F);
}

bool TCPSegment::hasFlag(uint16_t flag) const {
    return (getFlags() & flag) == flag;
}

uint16_t TCPSegment::getWindowSize() const {
    return header_.window;
}

void TCPSegment::setWindowSize(uint16_t window) {
    header_.window = window;
}

uint16_t TCPSegment::getChecksum() const {
    return header_.checksum;
}

void TCPSegment::setChecksum(uint16_t checksum) {
    header_.checksum = checksum;
}

uint16_t TCPSegment::getUrgentPointer() const {
    return header_.urgent_ptr;
}

void TCPSegment::setUrgentPointer(uint16_t pointer) {
    header_.urgent_ptr = pointer;
}

const std::vector<uint8_t>& TCPSegment::getPayload() const {
    return payload_;
}

void TCPSegment::setPayload(const uint8_t* data, size_t length) {
    payload_.assign(data, data + length);
}

void TCPSegment::setPayload(const std::vector<uint8_t>& data) {
    payload_ = data;
}

uint16_t TCPSegment::calculateChecksum(IPv4Address src_ip, IPv4Address dst_ip) const {
    // Create a buffer for the pseudo-header + TCP segment
    size_t tcp_length = getHeaderSize() + payload_.size();
    size_t total_length = 12 + tcp_length;  // 12 bytes for pseudo-header

    std::vector<uint8_t> buffer(total_length, 0);

    // Fill in the pseudo-header
    // Source IP
    buffer[0] = (src_ip >> 24) & 0xFF;
    buffer[1] = (src_ip >> 16) & 0xFF;
    buffer[2] = (src_ip >> 8) & 0xFF;
    buffer[3] = src_ip & 0xFF;

    // Destination IP
    buffer[4] = (dst_ip >> 24) & 0xFF;
    buffer[5] = (dst_ip >> 16) & 0xFF;
    buffer[6] = (dst_ip >> 8) & 0xFF;
    buffer[7] = dst_ip & 0xFF;

    // Reserved (zeros) + Protocol + TCP Length
    buffer[8] = 0;
    buffer[9] = IPProtocol::TCP;
    buffer[10] = (tcp_length >> 8) & 0xFF;
    buffer[11] = tcp_length & 0xFF;

    // Prepare TCP header with network byte order
    TCPHeader net_header = header_;
    net_header.src_port = htons(net_header.src_port);
    net_header.dst_port = htons(net_header.dst_port);
    net_header.seq_num = htonl(net_header.seq_num);
    net_header.ack_num = htonl(net_header.ack_num);
    net_header.offset_flags = htons(net_header.offset_flags);
    net_header.window = htons(net_header.window);
    net_header.checksum = 0;  // Zero out checksum field
    net_header.urgent_ptr = htons(net_header.urgent_ptr);

    // Copy TCP header to buffer
    std::memcpy(buffer.data() + 12, &net_header, sizeof(net_header));

    // Copy payload to buffer
    if (!payload_.empty()) {
        std::memcpy(buffer.data() + 12 + sizeof(net_header), payload_.data(), payload_.size());
    }

    // Calculate checksum
    return calculateTCPChecksum(buffer.data(), buffer.size(), src_ip, dst_ip);
}

void TCPSegment::updateChecksum(IPv4Address src_ip, IPv4Address dst_ip) {
    setChecksum(calculateChecksum(src_ip, dst_ip));
}

size_t TCPSegment::serialize(uint8_t* buffer, size_t buffer_size) const {
    size_t total_size = getHeaderSize() + payload_.size();
    if (buffer_size < total_size) {
        return 0; // Buffer too small
    }

    // Prepare TCP header with network byte order
    TCPHeader net_header = header_;
    net_header.src_port = htons(net_header.src_port);
    net_header.dst_port = htons(net_header.dst_port);
    net_header.seq_num = htonl(net_header.seq_num);
    net_header.ack_num = htonl(net_header.ack_num);
    net_header.offset_flags = htons(net_header.offset_flags);
    net_header.window = htons(net_header.window);
    net_header.checksum = htons(net_header.checksum);
    net_header.urgent_ptr = htons(net_header.urgent_ptr);

    // Copy TCP header to buffer
    std::memcpy(buffer, &net_header, sizeof(net_header));

    // Copy payload to buffer
    if (!payload_.empty()) {
        std::memcpy(buffer + getHeaderSize(), payload_.data(), payload_.size());
    }

    return total_size;
}

size_t TCPSegment::getHeaderSize() const {
    return getDataOffset() * 4;  // Data offset is in 32-bit (4-byte) words
}

size_t TCPSegment::getTotalSize() const {
    return getHeaderSize() + payload_.size();
}

// Calculate TCP checksum (utility function)
uint16_t calculateTCPChecksum(const void* tcp_data, size_t tcp_length,
                            IPv4Address src_ip, IPv4Address dst_ip) {
    // Use the IP checksum utility for actual calculation
    return calculateIPChecksum(tcp_data, tcp_length);
}

// TCP Connection implementation
TCPConnection::TCPConnection(std::shared_ptr<TCP> tcp, IPv4Address local_ip, uint16_t local_port,
                           IPv4Address remote_ip, uint16_t remote_port)
    : tcp_(tcp),
      state_(TCPState::CLOSED),
      snd_una_(0), snd_nxt_(0), snd_wnd_(TCP_DEFAULT_WINDOW),
      rcv_nxt_(0), rcv_wnd_(TCP_DEFAULT_WINDOW),
      iss_(0), irs_(0),
      rto_(TCP_INITIAL_RTO), rtt_measuring_(false),
      srtt_(0), rttvar_(0), retries_(0) {
    // Set connection ID
    conn_id_.local_ip = local_ip;
    conn_id_.local_port = local_port;
    conn_id_.remote_ip = remote_ip;
    conn_id_.remote_port = remote_port;

    // Generate initial sequence number
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(1, 0xFFFFFFFF);
    iss_ = dist(gen);
    snd_nxt_ = iss_;
}

bool TCPConnection::connect(TCPConnectionCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != TCPState::CLOSED) {
        return false;  // Can only connect from CLOSED state
    }

    // Save callback for later
    connection_callback_ = callback;

    // Create and send SYN segment
    TCPSegment syn_segment(conn_id_.local_port, conn_id_.remote_port);
    syn_segment.setSequenceNumber(iss_);
    syn_segment.setFlag(TCPFlags::SYN);
    syn_segment.setWindowSize(rcv_wnd_);

    // Send the SYN segment
    if (!sendSegment(syn_segment)) {
        return false;
    }

    // Advance sequence number (SYN consumes 1 sequence number)
    snd_nxt_ = iss_ + 1;

    // Start retransmission timer
    startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));

    // Change state to SYN_SENT
    state_ = TCPState::SYN_SENT;
    return true;
}

bool TCPConnection::send(const uint8_t* data, size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != TCPState::ESTABLISHED && state_ != TCPState::CLOSE_WAIT) {
        return false;  // Can only send in ESTABLISHED or CLOSE_WAIT states
    }

    if (length == 0) {
        return true;  // Nothing to send
    }

    // Add data to send buffer
    size_t offset = send_buffer_.size();
    send_buffer_.resize(offset + length);
    std::memcpy(send_buffer_.data() + offset, data, length);

    // Try to send what we can
    size_t window_available = snd_wnd_ - (snd_nxt_ - snd_una_);
    if (window_available > 0 && offset == 0) {
        // We can send data immediately
        size_t send_size = std::min(length, window_available);

        TCPSegment data_segment(conn_id_.local_port, conn_id_.remote_port);
        data_segment.setSequenceNumber(snd_nxt_);
        data_segment.setAcknowledgmentNumber(rcv_nxt_);
        data_segment.setFlag(TCPFlags::ACK);
        data_segment.setWindowSize(rcv_wnd_);
        data_segment.setPayload(data, send_size);

        if (send_size == length) {
            data_segment.setFlag(TCPFlags::PSH);  // Push if sending all available data
        }

        if (!sendSegment(data_segment)) {
            return false;
        }

        // Advance sequence number
        snd_nxt_ += send_size;

        // Update send buffer
        if (send_size < length) {
            // Remove sent data from buffer
            std::memmove(send_buffer_.data(), send_buffer_.data() + send_size,
                       length - send_size);
            send_buffer_.resize(length - send_size);
        } else {
            // All data sent
            send_buffer_.clear();
        }

        // Start retransmission timer if not already running
        startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));
    }

    return true;
}

bool TCPConnection::close() {
    std::lock_guard<std::mutex> lock(mutex_);

    switch (state_) {
        case TCPState::CLOSED:
        case TCPState::LISTEN:
        case TCPState::SYN_SENT:
            // Just close the connection immediately
            state_ = TCPState::CLOSED;
            return true;

        case TCPState::SYN_RECEIVED:
        case TCPState::ESTABLISHED:
            // Send FIN
            {
                TCPSegment fin_segment(conn_id_.local_port, conn_id_.remote_port);
                fin_segment.setSequenceNumber(snd_nxt_);
                fin_segment.setAcknowledgmentNumber(rcv_nxt_);
                fin_segment.setFlag(TCPFlags::FIN | TCPFlags::ACK);
                fin_segment.setWindowSize(rcv_wnd_);

                if (!sendSegment(fin_segment)) {
                    return false;
                }

                // Advance sequence number (FIN consumes 1 sequence number)
                snd_nxt_++;

                // Start retransmission timer
                startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));

                // Change state
                state_ = TCPState::FIN_WAIT_1;
            }
            return true;

        case TCPState::CLOSE_WAIT:
            // Send FIN
            {
                TCPSegment fin_segment(conn_id_.local_port, conn_id_.remote_port);
                fin_segment.setSequenceNumber(snd_nxt_);
                fin_segment.setAcknowledgmentNumber(rcv_nxt_);
                fin_segment.setFlag(TCPFlags::FIN | TCPFlags::ACK);
                fin_segment.setWindowSize(rcv_wnd_);

                if (!sendSegment(fin_segment)) {
                    return false;
                }

                // Advance sequence number (FIN consumes 1 sequence number)
                snd_nxt_++;

                // Start retransmission timer
                startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));

                // Change state
                state_ = TCPState::LAST_ACK;
            }
            return true;

        default:
            // Already closing
            return false;
    }
}

void TCPConnection::processSegment(std::unique_ptr<TCPSegment> segment) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!segment) {
        return;
    }

    // Process segment based on current state
    switch (state_) {
        case TCPState::CLOSED:
            handleClosedState(*segment);
            break;
        case TCPState::LISTEN:
            handleListenState(*segment);
            break;
        case TCPState::SYN_SENT:
            handleSynSentState(*segment);
            break;
        case TCPState::SYN_RECEIVED:
            handleSynReceivedState(*segment);
            break;
        case TCPState::ESTABLISHED:
            handleEstablishedState(*segment);
            break;
        case TCPState::FIN_WAIT_1:
            handleFinWait1State(*segment);
            break;
        case TCPState::FIN_WAIT_2:
            handleFinWait2State(*segment);
            break;
        case TCPState::CLOSE_WAIT:
            handleCloseWaitState(*segment);
            break;
        case TCPState::CLOSING:
            handleClosingState(*segment);
            break;
        case TCPState::LAST_ACK:
            handleLastAckState(*segment);
            break;
        case TCPState::TIME_WAIT:
            handleTimeWaitState(*segment);
            break;
    }
}

void TCPConnection::setDataReceivedCallback(TCPDataReceivedCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    data_received_callback_ = callback;
}

TCPState TCPConnection::getState() const {
    return state_;
}

TCPConnectionId TCPConnection::getConnectionId() const {
    return conn_id_;
}

bool TCPConnection::sendSegment(const TCPSegment& segment) {
    // Serialize the segment
    const size_t max_segment_size = TCP_HEADER_MAX_SIZE + TCP_DEFAULT_MSS;
    std::vector<uint8_t> buffer(max_segment_size);

    TCPSegment segment_copy = segment;
    segment_copy.updateChecksum(conn_id_.local_ip, conn_id_.remote_ip);

    size_t segment_size = segment_copy.serialize(buffer.data(), buffer.size());
    if (segment_size == 0) {
        return false;
    }

    // Send via IP layer
    IPSendOptions options;
    options.ttl = IP_DEFAULT_TTL;

    return tcp_->getIP()->sendPacket(
        conn_id_.remote_ip,
        IPProtocol::TCP,
        buffer.data(),
        segment_size,
        options
    );
}

void TCPConnection::sendReset() {
    TCPSegment rst_segment(conn_id_.local_port, conn_id_.remote_port);
    rst_segment.setSequenceNumber(snd_nxt_);
    rst_segment.setFlag(TCPFlags::RST);

    sendSegment(rst_segment);
}

void TCPConnection::startTimer(TCPTimerType type, std::chrono::milliseconds timeout) {
    auto now = std::chrono::steady_clock::now();
    timers_[type] = now + timeout;
}

void TCPConnection::stopTimer(TCPTimerType type) {
    timers_.erase(type);
}

// Handle SYN_SENT state: waiting for SYN-ACK
void TCPConnection::handleSynSentState(const TCPSegment& segment) {
    // Check for RST
    if (segment.hasFlag(TCPFlags::RST)) {
        // Connection refused
        state_ = TCPState::CLOSED;
        if (connection_callback_) {
            connection_callback_(false);
        }
        return;
    }

    // Check for SYN-ACK
    if (segment.hasFlag(TCPFlags::SYN) && segment.hasFlag(TCPFlags::ACK)) {
        // Validate ACK
        if (segment.getAcknowledgmentNumber() == iss_ + 1) {
            // Valid SYN-ACK, send ACK
            irs_ = segment.getSequenceNumber();
            rcv_nxt_ = irs_ + 1;
            snd_una_ = segment.getAcknowledgmentNumber();

            // Stop retransmission timer
            stopTimer(TCPTimerType::RETRANSMISSION);

            // Send ACK
            TCPSegment ack_segment(conn_id_.local_port, conn_id_.remote_port);
            ack_segment.setSequenceNumber(snd_nxt_);
            ack_segment.setAcknowledgmentNumber(rcv_nxt_);
            ack_segment.setFlag(TCPFlags::ACK);
            ack_segment.setWindowSize(rcv_wnd_);

            if (!sendSegment(ack_segment)) {
                // Failed to send ACK
                state_ = TCPState::CLOSED;
                if (connection_callback_) {
                    connection_callback_(false);
                }
                return;
            }

            // Connection established
            state_ = TCPState::ESTABLISHED;
            if (connection_callback_) {
                connection_callback_(true);
            }
            return;
        }
    }

    // Check for SYN (simultaneous open)
    if (segment.hasFlag(TCPFlags::SYN) && !segment.hasFlag(TCPFlags::ACK)) {
        // Simultaneous connection attempt
        irs_ = segment.getSequenceNumber();
        rcv_nxt_ = irs_ + 1;

        // Send SYN-ACK
        TCPSegment synack_segment(conn_id_.local_port, conn_id_.remote_port);
        synack_segment.setSequenceNumber(iss_);
        synack_segment.setAcknowledgmentNumber(rcv_nxt_);
        synack_segment.setFlag(TCPFlags::SYN | TCPFlags::ACK);
        synack_segment.setWindowSize(rcv_wnd_);

        if (!sendSegment(synack_segment)) {
            // Failed to send SYN-ACK
            state_ = TCPState::CLOSED;
            if (connection_callback_) {
                connection_callback_(false);
            }
            return;
        }

        // Change state
        state_ = TCPState::SYN_RECEIVED;
        return;
    }
}

// TCP状態ハンドラの空実装
void TCPConnection::handleClosedState(const TCPSegment& segment) {
    // CLOSEDステートでは通常RST以外何もしない
    sendReset();
}

void TCPConnection::handleListenState(const TCPSegment& segment) {
    // LISTENステートではSYNを受け取った場合に限り応答する
    if (segment.hasFlag(TCPFlags::SYN)) {
        // SYN-RECEIVEDに遷移して応答する
        irs_ = segment.getSequenceNumber();
        rcv_nxt_ = irs_ + 1;

        // SYN-ACKセグメントを送信
        TCPSegment synack_segment(conn_id_.local_port, conn_id_.remote_port);
        synack_segment.setSequenceNumber(iss_);
        synack_segment.setAcknowledgmentNumber(rcv_nxt_);
        synack_segment.setFlag(TCPFlags::SYN | TCPFlags::ACK);
        synack_segment.setWindowSize(rcv_wnd_);

        if (sendSegment(synack_segment)) {
            // 状態遷移
            state_ = TCPState::SYN_RECEIVED;

            // タイマー開始
            startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));
        }
    }
}

void TCPConnection::handleSynReceivedState(const TCPSegment& segment) {
    // このメソッドはクライアントがSYN-ACKに対してACKを返した場合に実行される
    if (segment.hasFlag(TCPFlags::ACK)) {
        // ACKが正しいか確認
        if (segment.getAcknowledgmentNumber() == iss_ + 1) {
            // ACKは正しい、ESTABLISHEDに遷移
            snd_una_ = segment.getAcknowledgmentNumber();
            state_ = TCPState::ESTABLISHED;

            // 再送タイマーを停止
            stopTimer(TCPTimerType::RETRANSMISSION);

            // コネクション確立コールバックを呼び出す
            if (connection_callback_) {
                connection_callback_(true);
            }
        }
    }
}

void TCPConnection::handleEstablishedState(const TCPSegment& segment) {
    // ESTABLISHEDステートでのセグメント処理

    // ACKフラグがある場合、送信ウィンドウを更新
    if (segment.hasFlag(TCPFlags::ACK)) {
        if (segment.getAcknowledgmentNumber() > snd_una_ &&
            segment.getAcknowledgmentNumber() <= snd_nxt_) {
            // 正しいACK
            snd_una_ = segment.getAcknowledgmentNumber();
            snd_wnd_ = segment.getWindowSize();

            // 再送タイマーを更新
            if (snd_una_ == snd_nxt_) {
                // すべて確認されたら再送タイマーを停止
                stopTimer(TCPTimerType::RETRANSMISSION);
            } else {
                // まだ確認されていないセグメントがある場合は再送タイマーをリセット
                startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));
            }
        }
    }

    // データ到着時の処理
    if (!segment.getPayload().empty()) {
        processReceivedData(segment);
    }

    // FINを受け取った場合
    if (segment.hasFlag(TCPFlags::FIN)) {
        // 受信シーケンス番号を1増やす（FINは1シーケンス消費）
        rcv_nxt_ = segment.getSequenceNumber() + 1;

        // FIN-ACKを送信
        TCPSegment finack_segment(conn_id_.local_port, conn_id_.remote_port);
        finack_segment.setSequenceNumber(snd_nxt_);
        finack_segment.setAcknowledgmentNumber(rcv_nxt_);
        finack_segment.setFlag(TCPFlags::ACK);
        finack_segment.setWindowSize(rcv_wnd_);

        if (sendSegment(finack_segment)) {
            // CLOSE_WAITに遷移
            state_ = TCPState::CLOSE_WAIT;
        }
    }
}

void TCPConnection::handleFinWait1State(const TCPSegment& segment) {
    // FIN_WAIT_1ステートでのセグメント処理

    // ACKを受け取った場合
    if (segment.hasFlag(TCPFlags::ACK)) {
        if (segment.getAcknowledgmentNumber() == snd_nxt_) {
            // 送信したFINに対するACK
            snd_una_ = segment.getAcknowledgmentNumber();

            // 再送タイマーを停止
            stopTimer(TCPTimerType::RETRANSMISSION);

            // FIN_WAIT_2に遷移
            state_ = TCPState::FIN_WAIT_2;
        }
    }

    // FINを受け取った場合
    if (segment.hasFlag(TCPFlags::FIN)) {
        // 受信シーケンス番号を1増やす（FINは1シーケンス消費）
        rcv_nxt_ = segment.getSequenceNumber() + 1;

        // FIN-ACKを送信
        TCPSegment finack_segment(conn_id_.local_port, conn_id_.remote_port);
        finack_segment.setSequenceNumber(snd_nxt_);
        finack_segment.setAcknowledgmentNumber(rcv_nxt_);
        finack_segment.setFlag(TCPFlags::ACK);
        finack_segment.setWindowSize(rcv_wnd_);

        if (sendSegment(finack_segment)) {
            // 相手のFINにACKを返した

            if (segment.hasFlag(TCPFlags::ACK) && segment.getAcknowledgmentNumber() == snd_nxt_) {
                // 自分のFINに対するACKも含まれていた（同時クローズ）
                state_ = TCPState::TIME_WAIT;
                startTimer(TCPTimerType::TIME_WAIT, std::chrono::seconds(2 * TCP_MSL.count()));
            } else {
                // 相手からのFINのみ
                state_ = TCPState::CLOSING;
            }
        }
    }
}

void TCPConnection::handleFinWait2State(const TCPSegment& segment) {
    // FIN_WAIT_2ステートでのセグメント処理

    // FINを受け取った場合
    if (segment.hasFlag(TCPFlags::FIN)) {
        // 受信シーケンス番号を1増やす（FINは1シーケンス消費）
        rcv_nxt_ = segment.getSequenceNumber() + 1;

        // FIN-ACKを送信
        TCPSegment finack_segment(conn_id_.local_port, conn_id_.remote_port);
        finack_segment.setSequenceNumber(snd_nxt_);
        finack_segment.setAcknowledgmentNumber(rcv_nxt_);
        finack_segment.setFlag(TCPFlags::ACK);
        finack_segment.setWindowSize(rcv_wnd_);

        if (sendSegment(finack_segment)) {
            // TIME_WAITに遷移
            state_ = TCPState::TIME_WAIT;
            startTimer(TCPTimerType::TIME_WAIT, std::chrono::seconds(2 * TCP_MSL.count()));
        }
    }
}

void TCPConnection::handleCloseWaitState(const TCPSegment& segment) {
    // CLOSE_WAITステートでのセグメント処理
    // アプリケーションがclose()を呼ぶのを待っている状態
    // ACKを受け取った場合は処理するが、状態遷移はしない

    if (segment.hasFlag(TCPFlags::ACK)) {
        if (segment.getAcknowledgmentNumber() > snd_una_ &&
            segment.getAcknowledgmentNumber() <= snd_nxt_) {
            // 正しいACK
            snd_una_ = segment.getAcknowledgmentNumber();
        }
    }
}

void TCPConnection::handleClosingState(const TCPSegment& segment) {
    // CLOSINGステートでのセグメント処理

    // ACKを受け取った場合
    if (segment.hasFlag(TCPFlags::ACK)) {
        if (segment.getAcknowledgmentNumber() == snd_nxt_) {
            // 送信したFINに対するACK
            snd_una_ = segment.getAcknowledgmentNumber();

            // 再送タイマーを停止
            stopTimer(TCPTimerType::RETRANSMISSION);

            // TIME_WAITに遷移
            state_ = TCPState::TIME_WAIT;
            startTimer(TCPTimerType::TIME_WAIT, std::chrono::seconds(2 * TCP_MSL.count()));
        }
    }
}

void TCPConnection::handleLastAckState(const TCPSegment& segment) {
    // LAST_ACKステートでのセグメント処理

    // ACKを受け取った場合
    if (segment.hasFlag(TCPFlags::ACK)) {
        if (segment.getAcknowledgmentNumber() == snd_nxt_) {
            // 送信したFINに対するACK
            snd_una_ = segment.getAcknowledgmentNumber();

            // 再送タイマーを停止
            stopTimer(TCPTimerType::RETRANSMISSION);

            // CLOSEDに遷移
            state_ = TCPState::CLOSED;
        }
    }
}

void TCPConnection::handleTimeWaitState(const TCPSegment& segment) {
    // TIME_WAITステートでのセグメント処理

    // 主に再送されたFINに対応
    if (segment.hasFlag(TCPFlags::FIN)) {
        // FIN-ACKを再送
        TCPSegment finack_segment(conn_id_.local_port, conn_id_.remote_port);
        finack_segment.setSequenceNumber(snd_nxt_);
        finack_segment.setAcknowledgmentNumber(rcv_nxt_);
        finack_segment.setFlag(TCPFlags::ACK);
        finack_segment.setWindowSize(rcv_wnd_);

        sendSegment(finack_segment);

        // TIME_WAITタイマーをリセット
        startTimer(TCPTimerType::TIME_WAIT, std::chrono::seconds(2 * TCP_MSL.count()));
    }
}

// データ処理
void TCPConnection::processReceivedData(const TCPSegment& segment) {
    // 受信したデータの処理

    // シーケンス番号チェック
    uint32_t seg_seq = segment.getSequenceNumber();
    const std::vector<uint8_t>& payload = segment.getPayload();
    size_t payload_size = payload.size();

    if (payload_size == 0) {
        return;  // データなし
    }

    // 受信ウィンドウ内かチェック
    if (seg_seq < rcv_nxt_ + rcv_wnd_) {
        // 受信バッファに追加（簡易実装）
        if (seg_seq == rcv_nxt_) {
            // 順序通りのデータ

            // データをアプリケーションに通知
            if (data_received_callback_) {
                data_received_callback_(payload.data(), payload_size);
            }

            // 受信シーケンス番号を更新
            rcv_nxt_ += payload_size;

            // ACKを送信
            TCPSegment ack_segment(conn_id_.local_port, conn_id_.remote_port);
            ack_segment.setSequenceNumber(snd_nxt_);
            ack_segment.setAcknowledgmentNumber(rcv_nxt_);
            ack_segment.setFlag(TCPFlags::ACK);
            ack_segment.setWindowSize(rcv_wnd_);

            sendSegment(ack_segment);
        } else {
            // 順不同の到着 - 実際の実装ではここでバッファリングして再順序化する

            // とりあえずACKを送り返す
            TCPSegment ack_segment(conn_id_.local_port, conn_id_.remote_port);
            ack_segment.setSequenceNumber(snd_nxt_);
            ack_segment.setAcknowledgmentNumber(rcv_nxt_);  // まだ順序通りのパケットが来ていないのでrcv_nxt_は更新しない
            ack_segment.setFlag(TCPFlags::ACK);
            ack_segment.setWindowSize(rcv_wnd_);

            sendSegment(ack_segment);
        }
    }
}

// タイムアウト処理
void TCPConnection::handleTimeout(TCPTimerType type) {
    switch (type) {
        case TCPTimerType::RETRANSMISSION:
            // 再送処理
            if (++retries_ > TCP_MAX_RETRIES) {
                // 再送回数超過
                if (state_ == TCPState::SYN_SENT || state_ == TCPState::SYN_RECEIVED) {
                    // 接続失敗
                    state_ = TCPState::CLOSED;
                    if (connection_callback_) {
                        connection_callback_(false);
                    }
                } else {
                    // 接続切断
                    state_ = TCPState::CLOSED;
                }
            } else {
                // 再送
                // 現在の状態に応じた再送処理（簡易実装）
                switch (state_) {
                    case TCPState::SYN_SENT:
                        // SYN再送
                        {
                            TCPSegment syn_segment(conn_id_.local_port, conn_id_.remote_port);
                            syn_segment.setSequenceNumber(iss_);
                            syn_segment.setFlag(TCPFlags::SYN);
                            syn_segment.setWindowSize(rcv_wnd_);

                            if (sendSegment(syn_segment)) {
                                // 再送タイマーを再設定（指数バックオフ）
                                rto_ = std::min(rto_ * 2, TCP_MAX_RTO);
                                startTimer(TCPTimerType::RETRANSMISSION, std::chrono::milliseconds(rto_));
                            }
                        }
                        break;

                    // その他の状態（FIN_WAIT_1, LAST_ACKなど）での再送も必要に応じて実装

                    default:
                        break;
                }
            }
            break;

        case TCPTimerType::TIME_WAIT:
            // TIME_WAIT終了
            state_ = TCPState::CLOSED;
            break;

        default:
            break;
    }
}

// TCP Implementation
TCP::TCP(std::shared_ptr<IP> ip)
    : ip_(ip), next_ephemeral_port_(TCP_MIN_PORT) {
}

bool TCP::init() {
    // Register TCP protocol handler with IP layer
    ip_->registerProtocolHandler(IPProtocol::TCP,
        [this](const uint8_t* data, size_t length, IPv4Address src_ip, IPv4Address dst_ip) {
            handleTCPSegment(data, length, src_ip, dst_ip);
        }
    );

    return true;
}

std::shared_ptr<TCPConnection> TCP::connect(IPv4Address remote_ip, uint16_t remote_port,
                                           TCPConnectionCallback callback) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Allocate local port
    uint16_t local_port = allocateEphemeralPort();
    if (local_port == 0) {
        return nullptr;  // No ports available
    }

    // Get local IP address
    IPv4Address local_ip = ip_->getLocalIP();

    // Create connection object
    auto connection = createConnection(local_ip, local_port, remote_ip, remote_port);
    if (!connection) {
        return nullptr;
    }

    // Start connection process
    if (!connection->connect(callback)) {
        // Failed to initiate connection
        removeConnection(connection->getConnectionId());
        return nullptr;
    }

    return connection;
}

bool TCP::listen(uint16_t local_port, TCPConnectionCallback callback,
                const TCPListenOptions& options) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Check if port is already in use
    if (listening_ports_.find(local_port) != listening_ports_.end()) {
        return false;
    }

    // Register the listening port
    listening_ports_[local_port] = callback;

    return true;
}

bool TCP::stopListening(uint16_t port) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto it = listening_ports_.find(port);
    if (it == listening_ports_.end()) {
        return false;
    }

    listening_ports_.erase(it);
    return true;
}

void TCP::closeAll() {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Close all active connections
    for (auto& pair : connections_) {
        pair.second->close();
    }

    // Clear all connections
    connections_.clear();

    // Clear all listening ports
    listening_ports_.clear();
}

void TCP::processTimers() {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // List of connections to remove
    std::vector<TCPConnectionId> to_remove;

    // Check timers for all connections
    for (auto& pair : connections_) {
        auto& conn_id = pair.first;
        auto& connection = pair.second;

        if (connection->getState() == TCPState::CLOSED) {
            to_remove.push_back(conn_id);
        }
    }

    // Remove closed connections
    for (const auto& conn_id : to_remove) {
        removeConnection(conn_id);
    }
}

bool TCP::send(const TCPConnectionId& conn_id, const uint8_t* data, size_t length,
              const TCPSendOptions& options) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto connection = findConnection(conn_id);
    if (!connection) {
        return false;
    }

    return connection->send(data, length);
}

bool TCP::close(const TCPConnectionId& conn_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto connection = findConnection(conn_id);
    if (!connection) {
        return false;
    }

    return connection->close();
}

void TCP::registerDataReceivedCallback(const TCPConnectionId& conn_id,
                                      TCPDataReceivedCallback callback) {
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto connection = findConnection(conn_id);
    if (connection) {
        connection->setDataReceivedCallback(callback);
    }
}

std::shared_ptr<IP> TCP::getIP() const {
    return ip_;
}

void TCP::handleTCPSegment(const uint8_t* data, size_t length,
                          IPv4Address src_ip, IPv4Address dst_ip) {
    if (length < TCP_HEADER_MIN_SIZE) {
        return;  // Ignore too short segments
    }

    // Parse TCP segment
    auto segment = TCPSegment::fromBuffer(data, length);
    if (!segment) {
        return;  // Failed to parse segment
    }

    // Extract source and destination ports
    uint16_t src_port = segment->getSourcePort();
    uint16_t dst_port = segment->getDestinationPort();

    // Create a connection ID based on the segment
    TCPConnectionId conn_id = {
        dst_ip,          // Local IP
        dst_port,        // Local port
        src_ip,          // Remote IP
        src_port         // Remote port
    };

    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Try to find an existing connection
    auto connection = findConnection(conn_id);

    if (connection) {
        // Pass segment to connection
        connection->processSegment(std::move(segment));
        return;
    }

    // Check if this is a SYN for a listening port
    if (segment->hasFlag(TCPFlags::SYN) && !segment->hasFlag(TCPFlags::ACK)) {
        auto it = listening_ports_.find(dst_port);
        if (it != listening_ports_.end()) {
            // Create a new connection for this incoming request
            connection = createConnection(dst_ip, dst_port, src_ip, src_port);
            if (connection) {
                // Set connection to LISTEN state
                connection->processSegment(std::move(segment));
                return;
            }
        }
    }

    // No matching connection or listener, send RST
    TCPSegment rst_segment(dst_port, src_port);
    rst_segment.setSequenceNumber(0);

    if (segment->hasFlag(TCPFlags::ACK)) {
        rst_segment.setSequenceNumber(segment->getAcknowledgmentNumber());
    } else {
        rst_segment.setFlag(TCPFlags::ACK);
        rst_segment.setAcknowledgmentNumber(segment->getSequenceNumber() +
                                          segment->getPayload().size() +
                                          (segment->hasFlag(TCPFlags::SYN) ? 1 : 0) +
                                          (segment->hasFlag(TCPFlags::FIN) ? 1 : 0));
    }

    rst_segment.setFlag(TCPFlags::RST);
    rst_segment.updateChecksum(dst_ip, src_ip);

    // Serialize and send RST segment
    std::vector<uint8_t> buffer(TCP_HEADER_MAX_SIZE);
    size_t rst_size = rst_segment.serialize(buffer.data(), buffer.size());

    IPSendOptions options;
    ip_->sendPacket(src_ip, IPProtocol::TCP, buffer.data(), rst_size, options);
}

std::shared_ptr<TCPConnection> TCP::findConnection(const TCPConnectionId& conn_id) {
    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<TCPConnection> TCP::createConnection(IPv4Address local_ip, uint16_t local_port,
                                                   IPv4Address remote_ip, uint16_t remote_port) {
    TCPConnectionId conn_id = {local_ip, local_port, remote_ip, remote_port};

    // Check if connection already exists
    if (findConnection(conn_id)) {
        return nullptr;
    }

    // Create new connection
    auto connection = std::make_shared<TCPConnection>(shared_from_this(),
                                                   local_ip, local_port,
                                                   remote_ip, remote_port);

    // Store in connections map
    connections_[conn_id] = connection;

    return connection;
}

void TCP::removeConnection(const TCPConnectionId& conn_id) {
    connections_.erase(conn_id);
}

uint16_t TCP::allocateEphemeralPort() {
    // Find an unused ephemeral port
    uint16_t start_port = next_ephemeral_port_;

    do {
        // Check if port is already in use
        bool port_in_use = false;

        // Check if port is used as listening port
        if (listening_ports_.find(next_ephemeral_port_) != listening_ports_.end()) {
            port_in_use = true;
        }

        // Check if port is used in any connection
        if (!port_in_use) {
            for (const auto& pair : connections_) {
                if (pair.first.local_port == next_ephemeral_port_) {
                    port_in_use = true;
                    break;
                }
            }
        }

        if (!port_in_use) {
            // Found an unused port
            uint16_t allocated_port = next_ephemeral_port_;

            // Increment for next allocation
            next_ephemeral_port_++;
            if (next_ephemeral_port_ >= TCP_MAX_PORT) {
                next_ephemeral_port_ = TCP_MIN_PORT;
            }

            return allocated_port;
        }

        // Try next port
        next_ephemeral_port_++;
        if (next_ephemeral_port_ >= TCP_MAX_PORT) {
            next_ephemeral_port_ = TCP_MIN_PORT;
        }

    } while (next_ephemeral_port_ != start_port);

    // No ports available
    return 0;
}