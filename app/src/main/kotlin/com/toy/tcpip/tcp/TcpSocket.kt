package com.toy.tcpip.tcp

import java.nio.ByteBuffer
import java.util.concurrent.Future

/**
 * Interface for TCP socket operations
 */
interface TcpSocket {
    /**
     * Get the local IP address
     */
    val localAddress: ByteArray

    /**
     * Get the local port
     */
    val localPort: Int

    /**
     * Get the remote IP address (null if not connected)
     */
    val remoteAddress: ByteArray?

    /**
     * Get the remote port (0 if not connected)
     */
    val remotePort: Int

    /**
     * Check if the socket is connected
     */
    fun isConnected(): Boolean

    /**
     * Check if the socket is closed
     */
    fun isClosed(): Boolean

    /**
     * Check if the socket is listening (server socket)
     */
    fun isListening(): Boolean

    /**
     * Bind the socket to a local address and port
     *
     * @param address Local IP address to bind to
     * @param port Local port to bind to
     * @throws IllegalStateException if the socket is already bound
     */
    fun bind(address: ByteArray, port: Int)

    /**
     * Start listening for incoming connections (server socket)
     *
     * @param backlog Maximum number of pending connections
     * @throws IllegalStateException if the socket is not bound or already listening
     */
    fun listen(backlog: Int = 5)

    /**
     * Accept an incoming connection (server socket)
     *
     * @return A new socket for the accepted connection
     * @throws IllegalStateException if the socket is not listening
     */
    fun accept(): TcpSocket

    /**
     * Connect to a remote address and port
     *
     * @param address Remote IP address to connect to
     * @param port Remote port to connect to
     * @throws IllegalStateException if the socket is already connected
     */
    fun connect(address: ByteArray, port: Int)

    /**
     * Close the socket
     */
    fun close()

    /**
     * Send data on the socket
     *
     * @param data Data to send
     * @return Number of bytes sent or -1 on error
     * @throws IllegalStateException if the socket is not connected
     */
    fun send(data: ByteBuffer): Int

    /**
     * Receive data from the socket
     *
     * @param buffer Buffer to receive data into
     * @return Number of bytes received or -1 on error or connection closed
     * @throws IllegalStateException if the socket is not connected
     */
    fun receive(buffer: ByteBuffer): Int

    /**
     * Set the socket option
     *
     * @param option Option name
     * @param value Option value
     */
    fun setOption(option: String, value: Any)

    /**
     * Get the socket option
     *
     * @param option Option name
     * @return Option value
     */
    fun getOption(option: String): Any?

    companion object {
        // Socket options
        const val SO_RCVBUF = "SO_RCVBUF"
        const val SO_SNDBUF = "SO_SNDBUF"
        const val SO_KEEPALIVE = "SO_KEEPALIVE"
        const val SO_REUSEADDR = "SO_REUSEADDR"
        const val SO_LINGER = "SO_LINGER"
        const val TCP_NODELAY = "TCP_NODELAY"

        // Timeout options
        const val SO_TIMEOUT = "SO_TIMEOUT"
        const val CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    }
}

/**
 * Interface for non-blocking TCP socket operations
 */
interface NonBlockingTcpSocket : TcpSocket {
    /**
     * Connect to a remote address and port asynchronously
     *
     * @param address Remote IP address to connect to
     * @param port Remote port to connect to
     * @return A Future that completes when the connection is established
     * @throws IllegalStateException if the socket is already connected
     */
    fun connectAsync(address: ByteArray, port: Int): Future<Boolean>

    /**
     * Accept an incoming connection asynchronously
     *
     * @return A Future that completes with the accepted socket
     * @throws IllegalStateException if the socket is not listening
     */
    fun acceptAsync(): Future<TcpSocket>

    /**
     * Send data on the socket asynchronously
     *
     * @param data Data to send
     * @return A Future that completes with the number of bytes sent
     * @throws IllegalStateException if the socket is not connected
     */
    fun sendAsync(data: ByteBuffer): Future<Int>

    /**
     * Receive data from the socket asynchronously
     *
     * @param buffer Buffer to receive data into
     * @return A Future that completes with the number of bytes received
     * @throws IllegalStateException if the socket is not connected
     */
    fun receiveAsync(buffer: ByteBuffer): Future<Int>

    /**
     * Check if the socket is ready for reading
     */
    fun isReadyForReading(): Boolean

    /**
     * Check if the socket is ready for writing
     */
    fun isReadyForWriting(): Boolean

    /**
     * Register a callback for when the socket is ready for reading
     *
     * @param callback Callback to invoke
     */
    fun onReadable(callback: () -> Unit)

    /**
     * Register a callback for when the socket is ready for writing
     *
     * @param callback Callback to invoke
     */
    fun onWritable(callback: () -> Unit)

    /**
     * Register a callback for when the socket is closed
     *
     * @param callback Callback to invoke
     */
    fun onClose(callback: () -> Unit)
}