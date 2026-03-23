package app.CLIKeyGen

import app.CLICore.MQTTInterface
import app.CLICore.Native
import app.CLICore.hexString
import io.github.davidepianca98.MQTTClient
import io.github.davidepianca98.mqtt.MQTTVersion
import io.github.davidepianca98.mqtt.packets.mqttv5.ReasonCode
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import uniffi.dkls.*
import java.io.File
import java.util.*
import kotlin.system.exitProcess

@OptIn(ExperimentalUnsignedTypes::class)
fun main(): kotlin.Unit = runBlocking {
    Native.loadOrThrow()

    println("DKLS CLI DKG Test (Kotlin)")
    println()

    // ---- Inputs ----
    print("Enter device name: ")
    val nameRaw = readlnOrNull()
    val name = nameRaw?.trim().orEmpty().ifBlank { "default-name" }

    print("Enter instance ID (optional, leave empty for new instance): ")
    val instanceIDInputRaw = readlnOrNull()
    val instanceIDInput = instanceIDInputRaw?.trim().orEmpty()

    val instanceID = if (instanceIDInput.isNotEmpty()) {
        try {
            InstanceId.fromBytes(Base64.getDecoder().decode(instanceIDInput))
        } catch (e: Exception) {
            println("Invalid Instance ID. Generating a new one.")
            InstanceId.fromEntropy()
        }
    } else {
        InstanceId.fromEntropy()
    }

    print("Enter threshold (default 2): ")
    val thresholdRaw = readlnOrNull()
    val threshold = thresholdRaw?.trim().orEmpty().ifBlank { "2" }.toUByteOrNull() ?: 2u

    print("Enter output filename (default keyshare_<name>): ")
    val outputFilenameInputRaw = readlnOrNull()
    val outputFilenameInput = outputFilenameInputRaw?.trim().orEmpty()
    val outputFilename = outputFilenameInput.ifBlank { "keyshare_${name}" }

    print("Enter MQTT host (default localhost): ")
    val mqttHostRaw = readlnOrNull()
    val mqttHost = mqttHostRaw?.trim().orEmpty().ifBlank { "localhost" }

    print("Enter MQTT port (default 1883): ")
    val mqttPortRaw = readlnOrNull()
    val mqttPort = mqttPortRaw?.trim().orEmpty().ifBlank { "1883" }.toIntOrNull() ?: 1883

    print("Enter QR Data from another device (optional, leave empty to start a new DKG): ")
    val qrDataInputRaw = readlnOrNull()
    val qrDataInput = qrDataInputRaw?.trim().orEmpty() // keep empty string if user presses Enter

    // ---- DEBUG Validation ----
    /*
    println()
    println("---- Debug: Raw inputs ----")
    println("nameRaw: '${nameRaw}'")
    println("instanceIDInputRaw: '${instanceIDInputRaw}'")
    println("thresholdRaw: '${thresholdRaw}'")
    println("outputFilenameInputRaw: '${outputFilenameInputRaw}'")
    println("mqttHostRaw: '${mqttHostRaw}'")
    println("mqttPortRaw: '${mqttPortRaw}'")
    println("qrDataInputRaw: '${qrDataInputRaw}'")
    println()
    println("---- Debug: Parsed/Defaulted values ----")
    println("name: '$name'")
    println("instanceID: '$instanceID'")
    println("threshold: $threshold")
    println("outputFilename: '$outputFilename'")
    println("mqttHost: '$mqttHost'")
    println("mqttPort: $mqttPort")
    println("qrDataInput (trimmed): '$qrDataInput'")
    println()
     */

    // ---- User parameters ----
    println("Output filename: $outputFilename")
    println("MQTT host: $mqttHost")
    println("MQTT port: $mqttPort")
    println()

    val mqttDispatchScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val client = MQTTClient(
        MQTTVersion.MQTT5,
        mqttHost,
        mqttPort,
        tls = null
    ) { publish ->
        // DEBUG Print
        //println("MQTTClient IN topic='${publish.topicName}' payloadBytes=${publish.payload?.size ?: 0}")
        // publishReceived callback (ALL inbound publishes)
        mqttDispatchScope.launch {
            MQTTInterface.dispatch(publish)
        }
    }

    println("Connecting to MQTT broker...")
    val connectionJob = launch(Dispatchers.IO) {
        client.runSuspend()
    }
    println("Connected!")

    val dkgNode: DkgNode
    val instanceStr: String

    if (qrDataInput.isEmpty()) {
        instanceStr = hexString(instanceID.toBytes())
        println("Starting DKG as starter for Instance: $instanceStr, and threshold: $threshold")
        dkgNode = DkgNode(name, instanceID, threshold)
        try {
            println("My QR: ${Base64.getEncoder().encodeToString(dkgNode.getQrBytes())}")
        } catch (e: Exception) {
            // Should never happen at this point.
            println("Error getting QR data: ${e.message}")
            exitProcess(1)
        }
    } else {
        println("Starting DKG as participant for QR data")
        try {
            val qr = QrData.fromBytes(Base64.getDecoder().decode(qrDataInput))
            instanceStr = hexString(qr.getInstance().toBytes())
            dkgNode = DkgNode.fromQr(name, qr)
        } catch (e: Exception) {
            println("Error parsing QR data: ${e.message}")
            exitProcess(1)
        }
    }

    // Create network interfaces for the message loop
    val setupInterface = MQTTInterface(client, "dkg${instanceStr}setup")
    val dkgInterface = MQTTInterface(client, "dkg${instanceStr}proto")

    // DEBUG
    /*
    println("InstanceStr: $instanceStr")
    println("Setup topic: dkg${instanceStr}setup")
    println("Proto topic: dkg${instanceStr}proto")
     */

    val messageLoopJob = launch {
        try {
            println("Starting message loop...")
            dkgNode.messageLoop(setupInterface, dkgInterface)
        } catch (e: Exception) {
            println("Error in message loop: ${e.message}")
        }
        println("Message loop completed.")
    }

    class SetupChangeListener : DkgSetupChangeListener {
        override fun onSetupChanged(devices: List<DeviceInfo>, myId: UByte) {
            println("--- DKG Setup Update ---")
            println("Devices (${devices.size}):")
            devices.forEachIndexed { i, device ->
                val verified = if (i.toUByte() == myId) {
                    "(You)"
                } else if (device.isVerified()) {
                    "(Verified)"
                } else {
                    "(Not Verified)"
                }
                println("  ${i + 1}. ${device.name()} $verified")
            }
            println("------------------------")
        }
    }

    val inputChannel = Channel<String>()
    val inputJob = launch(Dispatchers.IO) {
        while (isActive) {
            val line = readlnOrNull()
            if (line != null) {
                inputChannel.send(line)
            } else {
                println("Exiting...")
                exitProcess(1)
            }
        }
    }

    class StateChangeListener(
        private val inputChannel: Channel<String>,
        private val dkgNode: DkgNode,
        private val scope: CoroutineScope
    ) : DkgStateChangeListener {
        override fun onStateChanged(oldState: DkgState, newState: DkgState) {
            println("State changed: $oldState -> $newState")
            if (oldState == DkgState.WAIT_FOR_SETUP &&
                (newState == DkgState.WAIT_FOR_SIGS || newState == DkgState.WAIT_FOR_DEVICES || newState == DkgState.READY)) {
                try {
                    println("My QR: ${Base64.getEncoder().encodeToString(dkgNode.getQrBytes())}")
                } catch (e: Exception) {
                    println("Error getting QR data: ${e.message}")
                }
            }
            if (newState == DkgState.RUNNING) {
                scope.launch { inputChannel.close() } // Stop listening for user input to start DKG
            }
            if (newState == DkgState.READY) {
                println("Press Enter to begin Key Gen Process!")
            }
        }
    }

    val stateChangeListener = StateChangeListener(inputChannel, dkgNode, this)
    dkgNode.addStateChangeListener(stateChangeListener)
    dkgNode.addSetupChangeListener(SetupChangeListener())

    launch {
        for (line in inputChannel) {
            println("Input received. Current DKG state: ${dkgNode.getState()}") // Debug
            if (line.isEmpty()) {
                if (dkgNode.getState() == DkgState.READY) {
                    println("Starting DKG...")
                    try {
                        dkgNode.startDkg()
                    } catch (e: Exception) {
                        println("Error starting DKG: ${e.message}")
                    }
                } else {
                    println("Not ready yet.")
                }
            } else {
                // Assume this is QR data
                try {
                    dkgNode.receiveQrBytes(Base64.getDecoder().decode(line))
                } catch (e: Exception) {
                    println("Error in QR data: ${e.message}")
                }
            }
        }
    }

    println("Waiting for DKG to complete...")
    messageLoopJob.join()

    // ---- Save local data ----
    try {
        val localData = dkgNode.getLocalData()

        val outDir = File("keyshares")
        if (!outDir.exists()) outDir.mkdirs()

        val outFile = File(outDir, outputFilename)
        outFile.writeBytes(localData.toBytes())

        println("Device local data written to ${outFile.path}")
    } catch (e: Exception) {
        println("Error saving local data: ${e.message}")
    }

    println("Disconnecting...")
    try {
        client.disconnect(ReasonCode.SUCCESS)
        connectionJob.cancelAndJoin()
        println("Goodbye!")
        exitProcess(0)
    } catch (e: Exception) {
        println("Error while disconnecting: ${e.message}")
        exitProcess(1)
    }
}