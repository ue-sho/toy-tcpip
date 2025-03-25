package com.toy.tcpip.tcp

import com.toy.tcpip.util.Constants
import com.toy.tcpip.util.bytesToIpv4
import com.toy.tcpip.util.createNetworkBuffer
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.min

/**
 * Represents a TCP connection
 */
class TcpConnection(
    val localAddress: ByteArray,
    val localPort: Int,
    val remoteAddress: ByteArray,
    val remotePort: Int,
    val mss: Int = Constants.DEFAULT_MSS,
    val windowSize: Int = 65535
) {
    // Connection state
    @Volatile
    var state: Int = Constants.TCP_STATE_CLOSED

    // Sequence and acknowledgment numbers
    var sendUnacknowledged: Long = 0    // SND.UNA - oldest unacknowledged sequence number
    var sendNext: Long = 0              // SND.NXT - next sequence number to send
    var sendWindowSize: Int = 0         // SND.WND - send window size
    var initialSendSequence: Long = 0   // ISS - initial send sequence number
    var receiveNext: Long = 0           // RCV.NXT - next sequence number expected to receive
    var receiveWindowSize: Int = windowSize  // RCV.WND - receive window size
    var initialReceiveSequence: Long = 0 // IRS - initial receive sequence number

    // Retransmission queue (unacknowledged segments)
    val retransmissionQueue = ConcurrentLinkedQueue<RetransmissionItem>()

    // Retransmission timer (when to retransmit the oldest unacknowledged segment)
    var retransmissionTimeout: Long = Constants.TCP_RETRANSMISSION_TIMEOUT
    var retransmissionTimestamp: Long = 0

    // Number of consecutive retransmissions
    var retransmissionCount: Int = 0

    // User timeout (when to abort the connection due to unresponsive peer)
    var userTimeout: Long = Constants.TCP_USER_TIMEOUT
    var userTimeoutTimestamp: Long = 0

    // TIME-WAIT timeout (when to fully close the connection after FIN-ACK)
    var timeWaitTimeout: Long = Constants.TCP_TIME_WAIT_TIMEOUT
    var timeWaitTimestamp: Long = 0

    // Send buffer
    private val sendBuffer = ByteBuffer.allocate(Constants.SO_SNDBUF)
    private val sendBufferLock = ReentrantLock()
    private var sendBufferProcessed = AtomicLong(0)

    // Receive buffer
    private val receiveBuffer = ByteBuffer.allocate(Constants.SO_RCVBUF)
    private val receiveBufferLock = ReentrantLock()

    // Backlog of segments that arrived out of order
    private val outOfOrderSegments = mutableMapOf<Long, ByteBuffer>()
    private val outOfOrderLock = ReentrantLock()

    /**
     * Structure for items in the retransmission queue
     */
    data class RetransmissionItem(
        val segment: TcpSegment,
        val buffer: ByteBuffer,
        var timestamp: Long,
        var retransmitCount: Int = 0
    )

    /**
     * Initialize a new connection with random initial sequence number
     */
    init {
        // Generate random initial sequence number
        initialSendSequence = (System.nanoTime() and 0xFFFFFFFF)
        sendNext = initialSendSequence
        sendUnacknowledged = initialSendSequence
    }

    /**
     * Add data to the send buffer
     *
     * @param data The data to send
     * @return Number of bytes added to the buffer, or -1 if buffer is full
     */
    fun write(data: ByteBuffer): Int {
        val length = data.remaining()
        if (length == 0) {
            return 0
        }

        return sendBufferLock.withLock {
            if (sendBuffer.remaining() < length) {
                // Not enough space
                return@withLock -1
            }

            // Add data to send buffer
            val position = sendBuffer.position()
            sendBuffer.put(data)

            // Return number of bytes written
            sendBuffer.position() - position
        }
    }

    /**
     * Read data from the receive buffer
     *
     * @param buffer The buffer to read into
     * @return Number of bytes read, or -1 if no data is available
     */
    fun read(buffer: ByteBuffer): Int {
        return receiveBufferLock.withLock {
            if (receiveBuffer.position() == 0) {
                // No data available
                return@withLock -1
            }

            // Prepare receive buffer for reading
            receiveBuffer.flip()

            // Calculate how much data we can copy
            val bytesToRead = min(buffer.remaining(), receiveBuffer.remaining())
            if (bytesToRead == 0) {
                // Reset the receive buffer and return 0
                receiveBuffer.compact()
                return@withLock 0
            }

            // Create a temporary buffer with just the data we want to copy
            val tempBuffer = receiveBuffer.duplicate()
            tempBuffer.limit(tempBuffer.position() + bytesToRead)

            // Copy data to the output buffer
            buffer.put(tempBuffer)

            // Advance position in receive buffer
            receiveBuffer.position(receiveBuffer.position() + bytesToRead)

            // Compact the receive buffer (move remaining data to the beginning)
            receiveBuffer.compact()

            // Adjust receive window size
            receiveWindowSize = receiveBuffer.remaining()

            bytesToRead
        }
    }

    /**
     * Add received data to the receive buffer
     *
     * @param data The data to add
     * @param sequenceNumber The starting sequence number of the data
     * @return True if the data was added, false if there's no space
     */
    fun addToReceiveBuffer(data: ByteBuffer, sequenceNumber: Long): Boolean {
        if (data.remaining() == 0) {
            return true
        }

        return receiveBufferLock.withLock {
            if (sequenceNumber != receiveNext) {
                // Out of order segment - store it for later
                outOfOrderLock.withLock {
                    outOfOrderSegments[sequenceNumber] = data.duplicate()
                }
                return@withLock false
            }

            if (receiveBuffer.remaining() < data.remaining()) {
                // Not enough space
                return@withLock false
            }

            // Add data to receive buffer
            receiveBuffer.put(data)

            // Update receive next to account for the data we just added
            receiveNext += data.limit() - data.position()

            // Check if we can now process any out-of-order segments
            processOutOfOrderSegments()

            // Update receive window size
            receiveWindowSize = receiveBuffer.remaining()

            true
        }
    }

    /**
     * Process any out-of-order segments that are now in order
     */
    private fun processOutOfOrderSegments() {
        outOfOrderLock.withLock {
            var processedSegment = true

            // Process segments as long as we find the next one
            while (processedSegment) {
                processedSegment = false

                // Look for a segment that starts at receiveNext
                val segment = outOfOrderSegments[receiveNext]
                if (segment != null) {
                    // Found the next segment
                    if (receiveBuffer.remaining() >= segment.remaining()) {
                        // Add it to the receive buffer
                        receiveBuffer.put(segment)

                        // Update receive next
                        receiveNext += segment.limit() - segment.position()

                        // Remove from out-of-order list
                        outOfOrderSegments.remove(receiveNext)

                        // We processed a segment, so try again
                        processedSegment = true
                    }
                }
            }
        }
    }

    /**
     * Get the next chunk of data to send (up to MSS bytes)
     */
    fun getNextDataToSend(): ByteBuffer? {
        return sendBufferLock.withLock {
            if (sendBuffer.position() == 0) {
                // No data to send
                return@withLock null
            }

            // Prepare send buffer for reading
            sendBuffer.flip()

            // Calculate how much data we can send (limited by MSS and send window)
            val availableWindow = sendWindowSize - (sendNext - sendUnacknowledged).toInt()
            if (availableWindow <= 0) {
                // No window space available
                sendBuffer.compact()
                return@withLock null
            }

            val bytesToSend = min(min(sendBuffer.remaining(), mss), availableWindow)
            if (bytesToSend == 0) {
                // Reset the send buffer and return null
                sendBuffer.compact()
                return@withLock null
            }

            // Create a buffer with just the data we want to send
            val dataToSend = createNetworkBuffer(bytesToSend)
            val tempBuffer = sendBuffer.duplicate()
            tempBuffer.limit(tempBuffer.position() + bytesToSend)
            dataToSend.put(tempBuffer)
            dataToSend.flip()

            // Update processed counter
            sendBufferProcessed.addAndGet(bytesToSend.toLong())

            // Advance position in send buffer
            sendBuffer.position(sendBuffer.position() + bytesToSend)

            // Compact the send buffer (move remaining data to the beginning)
            sendBuffer.compact()

            dataToSend
        }
    }

    /**
     * Add a segment to the retransmission queue
     */
    fun addToRetransmissionQueue(segment: TcpSegment, buffer: ByteBuffer) {
        val now = System.currentTimeMillis()

        // Only add data segments or SYN/FIN to retransmission queue
        if (segment.payload.remaining() > 0 ||
            (segment.flags and (Constants.TCP_FLAG_SYN or Constants.TCP_FLAG_FIN)) != 0) {

            val item = RetransmissionItem(segment, buffer.duplicate(), now)
            retransmissionQueue.add(item)

            // Set retransmission timer if this is the first item
            if (retransmissionQueue.size == 1) {
                retransmissionTimestamp = now
                userTimeoutTimestamp = now
            }
        }
    }

    /**
     * Process acknowledgment for received data
     *
     * @param acknowledgmentNumber The acknowledgment number received
     * @return True if the acknowledgment was valid, false otherwise
     */
    fun processAcknowledgment(acknowledgmentNumber: Long): Boolean {
        if (acknowledgmentNumber <= sendUnacknowledged ||
            acknowledgmentNumber > sendNext) {
            // Invalid ACK (too old or acknowledging data we haven't sent yet)
            return false
        }

        // This is a valid ACK, update sendUnacknowledged
        sendUnacknowledged = acknowledgmentNumber

        // Reset retransmission counter since we got a valid ACK
        retransmissionCount = 0

        // Reset timeout timestamps
        val now = System.currentTimeMillis()
        retransmissionTimestamp = now
        userTimeoutTimestamp = now

        // Remove acknowledged segments from retransmission queue
        var removed = 0
        while (!retransmissionQueue.isEmpty()) {
            val item = retransmissionQueue.peek()
            val endSeq = item.segment.sequenceNumber +
                        (if (item.segment.payload.remaining() > 0) item.segment.payload.remaining().toLong() else 0) +
                        (if ((item.segment.flags and Constants.TCP_FLAG_SYN) != 0) 1 else 0) +
                        (if ((item.segment.flags and Constants.TCP_FLAG_FIN) != 0) 1 else 0)

            if (acknowledgmentNumber >= endSeq) {
                // This segment is fully acknowledged
                retransmissionQueue.poll()
                removed++
            } else {
                // This and remaining segments are not fully acknowledged
                break
            }
        }

        // If we received an ACK, update the retransmission timer
        if (retransmissionQueue.isEmpty()) {
            // No more segments to retransmit
            retransmissionTimestamp = 0
            userTimeoutTimestamp = 0
        } else {
            // Update the timestamp for the next segment
            val nextItem = retransmissionQueue.peek()
            nextItem.timestamp = now
        }

        return true
    }

    /**
     * Check if the connection has timed out waiting for an ACK
     */
    fun hasTimedOut(now: Long): Boolean {
        if (userTimeoutTimestamp == 0L) {
            return false
        }

        return now - userTimeoutTimestamp > userTimeout
    }

    /**
     * Check if it's time to retransmit the oldest unacknowledged segment
     */
    fun isTimeToRetransmit(now: Long): Boolean {
        if (retransmissionTimestamp == 0L || retransmissionQueue.isEmpty()) {
            return false
        }

        return now - retransmissionTimestamp > retransmissionTimeout
    }

    /**
     * Get the next segment to retransmit
     */
    fun getSegmentToRetransmit(): RetransmissionItem? {
        if (retransmissionQueue.isEmpty()) {
            return null
        }

        val item = retransmissionQueue.peek()

        // Update timestamps
        val now = System.currentTimeMillis()
        item.timestamp = now
        retransmissionTimestamp = now

        // Increment retransmission counters
        retransmissionCount++
        item.retransmitCount++

        // If we've retransmitted this segment too many times, the connection is dead
        if (item.retransmitCount > 10) {
            // This would typically lead to a connection reset
            return null
        }

        return item
    }

    /**
     * Reset the connection state
     */
    fun reset() {
        state = Constants.TCP_STATE_CLOSED

        sendBufferLock.withLock {
            sendBuffer.clear()
        }

        receiveBufferLock.withLock {
            receiveBuffer.clear()
        }

        outOfOrderLock.withLock {
            outOfOrderSegments.clear()
        }

        retransmissionQueue.clear()

        initialSendSequence = 0
        initialReceiveSequence = 0
        sendNext = 0
        sendUnacknowledged = 0
        receiveNext = 0

        retransmissionTimestamp = 0
        userTimeoutTimestamp = 0
        timeWaitTimestamp = 0

        retransmissionCount = 0
    }

    override fun toString(): String {
        return "TcpConnection(${bytesToIpv4(localAddress)}:$localPort -> " +
               "${bytesToIpv4(remoteAddress)}:$remotePort, " +
               "state=${stateToString(state)}, " +
               "snd.nxt=$sendNext, " +
               "snd.una=$sendUnacknowledged, " +
               "rcv.nxt=$receiveNext)"
    }

    companion object {
        /**
         * Convert TCP state to string representation
         */
        fun stateToString(state: Int): String {
            return when (state) {
                Constants.TCP_STATE_CLOSED -> "CLOSED"
                Constants.TCP_STATE_LISTEN -> "LISTEN"
                Constants.TCP_STATE_SYN_SENT -> "SYN_SENT"
                Constants.TCP_STATE_SYN_RECEIVED -> "SYN_RECEIVED"
                Constants.TCP_STATE_ESTABLISHED -> "ESTABLISHED"
                Constants.TCP_STATE_FIN_WAIT_1 -> "FIN_WAIT_1"
                Constants.TCP_STATE_FIN_WAIT_2 -> "FIN_WAIT_2"
                Constants.TCP_STATE_CLOSE_WAIT -> "CLOSE_WAIT"
                Constants.TCP_STATE_CLOSING -> "CLOSING"
                Constants.TCP_STATE_LAST_ACK -> "LAST_ACK"
                Constants.TCP_STATE_TIME_WAIT -> "TIME_WAIT"
                else -> "UNKNOWN"
            }
        }

        /**
         * Generate unique connection ID for connection tracking
         */
        fun generateConnectionId(
            localAddress: ByteArray,
            localPort: Int,
            remoteAddress: ByteArray,
            remotePort: Int
        ): String {
            return "${bytesToIpv4(localAddress)}:$localPort-${bytesToIpv4(remoteAddress)}:$remotePort"
        }
    }
}