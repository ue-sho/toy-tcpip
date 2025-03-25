package com.toy.tcpip

import com.toy.tcpip.device.RawSocketDevice
import java.nio.ByteBuffer
import kotlin.system.exitProcess

@Volatile
private var terminate = false

fun main() {
    val device = RawSocketDevice("en0")
    device.open()

    // Signal handler for termination
    Runtime.getRuntime().addShutdownHook(Thread {
        terminate = true
        device.close()
        println("Device closed")
    })

    // Receiving data
    while (!terminate) {
        val frame = ByteBuffer.allocate(1500) // Adjust size as needed
        val length = device.receive(frame) // Assume receive method exists
        if (length > 0) {
            println("Received ${length} bytes")
            // Process the received frame as needed
        }
    }

    device.close()
    println("Closed")
    exitProcess(0)
}