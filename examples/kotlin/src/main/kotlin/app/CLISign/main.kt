package app.CLISign

import app.CLICore.MQTTInterface
import app.CLICore.Native
import app.CLICore.hexString
import app.CLICore.hexToBytes
import io.github.davidepianca98.MQTTClient
import io.github.davidepianca98.mqtt.MQTTVersion
import io.github.davidepianca98.mqtt.packets.mqttv5.ReasonCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import uniffi.dkls.*
import java.io.File
import kotlin.system.exitProcess

private fun verifySigHex(signatureHex: String, message: String, vk: NodeVerifyingKey) {
    println("---- VERIFYING SIGNATURE ----")
    println("Message: '$message'")
    println("Signature (hex): ${signatureHex.trim()}")

    val result = runCatching {
        val sigBytes = hexToBytes(signatureHex.trim())
        val sig = Signature.fromBytes(sigBytes)      // can throw on bad length/encoding
        vk.verify(message.toByteArray(Charsets.UTF_8), sig) // can throw if invalid sig
    }

    if (result.isSuccess) {
        println("---- SIGNATURE OK! ----")
    } else {
        println("---- FAIL TO MATCH SIGNATURE ----")
        println("Error: ${result.exceptionOrNull()?.message}")
    }
}

// ---- Listener / callbacks ----
// Kotlin equivalents of Swift's ConsoleListener in main.swift: implements both listener traits.
//
// Minimal structure change: keep the existing flow, but callbacks now drive the process instead
// of calling getNextReq()/doJoinRequest()/doSignBytes() with netIf.
class ConsoleListener(
    private val scope: CoroutineScope,
    private val localData: DeviceLocalData,
    private val devices: List<DeviceInfo>,
    private val skipConfirmation: Boolean,
    private val signNode: SignNode,
) : SignRequestListener, SignResultListener {

    // A very small "queue" for pending requests; the Swift version indexes these for approval.
    private val pending = mutableListOf<SignSetupMessage>()

    override fun receiveSignRequest(req: SignSetupMessage, dev: DeviceInfo?) {
        println("---- NEW SIGN REQUEST ----")

        // Print message (String or Bytes) if present
        val msg = req.getMessage()
        if (msg != null) {
            when (msg) {
                is SignRequestType.String -> {
                    println("Message: ${msg.toString()}")
                }
                is SignRequestType.Bytes -> {
                    val b = msg.toString().toByteArray()
                    println("Bytes (${b.size}): ${hexString(b)}")
                }
            }
        }

        // Print sender information if available
        if (dev != null) {
            println("From: ${dev.name()} VK: ${hexString(dev.vk().toBytes())}")
        } else {
            println("From: Unknown Device (WARNING)")
        }

        // Auto-approve if requested; otherwise, store and let the user approve manually.
        if (skipConfirmation && dev != null) {
            println("Skipping confirmation; approving request...")
            scope.launch {
                runCatching {
                    signNode.acceptRequest(req = req, listener = this@ConsoleListener)
                }.onFailure { e ->
                    println("Error approving request: ${e.message}")
                }
            }
        } else {
            pending.add(req)
            val idx = pending.lastIndex
            println("Request added as index $idx. ID: ${hexString(req.getInstance().toBytes())}")
            println("Type 'a $idx' to approve, 'c $idx' to cancel, 'l' to list.")
        }
    }

    override fun cancelSignRequest(req: SignSetupMessage) {
        println("---- SIGN REQUEST CANCELLED ----")
        pending.removeAll { it.getInstance() == req.getInstance() }
    }

    override fun signDevicesChanged(req: SignSetupMessage, devices: List<DeviceInfo?>) {
        println("---- SIGNING DEVICES CHANGED ----")
        println("Instance ID: ${hexString(req.getInstance().toBytes())}")
        println("Devices:")
        devices.forEach { dev ->
            if (dev != null) println(" - ${dev.name()}")
            else println(" - Unknown Device (WARNING)")
        }
    }

    override fun signDsgStarted(req: SignSetupMessage) {
        println("---- SIGNING DSG STARTED ----")
        println("Instance ID: ${hexString(req.getInstance().toBytes())}")
    }

    override fun signCancelled(req: SignSetupMessage) {
        println("---- SIGNING CANCELLED BY ORIGINATOR ----")
        println("Instance ID: ${hexString(req.getInstance().toBytes())}")
        pending.removeAll { it.getInstance() == req.getInstance() }
    }

    override fun signError(req: SignSetupMessage, error: GeneralException) {
        println("---- SIGNING ERROR ----")
        println("Instance ID: ${hexString(req.getInstance().toBytes())}")
        println("Error: $error")
        pending.removeAll { it.getInstance() == req.getInstance() }
    }

    override fun signResult(req: SignSetupMessage, result: Signature) {
        println("---- SIGNATURE GENERATED ----")
        println("Instance ID: ${hexString(req.getInstance().toBytes())}")
        println("Signature: ${hexString(result.toBytes())}")
        pending.removeAll { it.getInstance() == req.getInstance() }
    }

    fun listPending() {
        if (pending.isEmpty()) {
            println("No pending requests.")
            return
        }
        pending.forEachIndexed { i, req ->
            val display = when (val msg = req.getMessage()) {
                is SignRequestType.String -> msg.toString()
                is SignRequestType.Bytes -> "<binary data>"
                else -> "unknown"
            }
            println("$i: $display ID: ${hexString(req.getInstance().toBytes())}")
        }
    }

    fun getPending(index: Int): SignSetupMessage? =
        pending.getOrNull(index)

    fun removePendingByInstance(instanceBytes: ByteArray) {
        pending.removeAll { it.getInstance().toBytes().contentEquals(instanceBytes) }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
fun main(): kotlin.Unit = runBlocking {
    // ---- Load native dkls ----
    try {
        Native.loadOrThrow()
    } catch (e: UnsatisfiedLinkError) {
        System.err.println("Failed to load native library 'dkls': ${e.message}")
        System.err.println("Tip: run with -Djava.library.path=src/main/resources/native")
        exitProcess(1)
    }

    println("DKLS CLI Signing Test (Kotlin)")
    println()

    // ---- Inputs ----
    print("Enter keyshare filename: ")
    val keyshareFilenameRaw = readlnOrNull()
    val keyshareFilename = keyshareFilenameRaw?.trim().orEmpty()
    if (keyshareFilename.isEmpty()) {
        println("Keyshare filename is required.")
        exitProcess(1)
    }

    print("Enter message to sign (leave empty to listen for requests): ")
    val messageInputRaw = readlnOrNull()
    val messageInput = messageInputRaw?.trim().orEmpty()

    print("Skip confirmation for signing requests? (y/N): ")
    val skipConfirmationRaw = readlnOrNull()
    val skipConfirmation = skipConfirmationRaw?.trim()?.lowercase().orEmpty() == "y"

    print("Enter MQTT host (default localhost): ")
    val mqttHostRaw = readlnOrNull()
    val mqttHost = mqttHostRaw?.trim().orEmpty().ifBlank { "localhost" }

    print("Enter MQTT port (default 1883): ")
    val mqttPortRaw = readlnOrNull()
    val mqttPort = mqttPortRaw?.trim().orEmpty().ifBlank { "1883" }.toIntOrNull() ?: 1883

    // ---- DEBUG Validation ----
    /*
    println()
    println("---- Debug Raw inputs ----")
    println("keyshareFilenameRaw: $keyshareFilenameRaw")
    println("messageInputRaw: $messageInputRaw")
    println("skipConfirmationRaw: $skipConfirmationRaw")
    println("mqttHostRaw: $mqttHostRaw")
    println("mqttPortRaw: $mqttPortRaw")
    println()
    println("---- Debug Parsed/Defaulted values ----")
    println("keyshareFilename: $keyshareFilename")
    println("messageInput (len): ${messageInput.length}")
    println("skipConfirmation: $skipConfirmation")
    println("mqttHost: $mqttHost")
    println("mqttPort: $mqttPort")
    println()
     */

    // ---- User parameters ----
    println("Keyshare filename: $keyshareFilename")
    println("MQTT host: $mqttHost")
    println("MQTT port: $mqttPort")
    println()

    // ---- Load keyshare ----
    val localData: DeviceLocalData = try {
        DeviceLocalData.fromBytes(File(keyshareFilename).readBytes())
    } catch (e: Exception) {
        println("Error reading device data from $keyshareFilename: ${e.message}")
        exitProcess(1)
    }

    val devices = localData.getDeviceList()

    // ---- MQTT client ----
    val mqttDispatchScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    // KMQTT constructor takes (version, address, port, tls) + a single publish callback.
    val client = MQTTClient(
        MQTTVersion.MQTT5,
        mqttHost,
        mqttPort,
        null
    ) { publish ->
        // DEBUG Print
        //println("MQTT IN topic='${publish.topicName}' payloadBytes=${publish.payload?.size ?: 0}")
        // One callback for ALL inbound publishes; dispatch to per-topic MQTTInterface instances.
        mqttDispatchScope.launch {
            MQTTInterface.dispatch(publish)
        }
    }

    println("Connecting to MQTT broker...")
    val connectionJob = launch(Dispatchers.IO) { client.runSuspend() } // This is the "connect" loop in KMQTT.
    delay(1200)
    println("Connected!")
    println()

    val keyIdStr = hexString(localData.keyId())
    val topic = "sign$keyIdStr"
    val netInterface = MQTTInterface(client = client, topic = topic)

    val signNode = SignNode(ctx = localData, netIf = netInterface)

    // ---- SignNode setup + message loop ----
    val listener = ConsoleListener(
        scope = this,
        localData = localData,
        devices = devices,
        skipConfirmation = skipConfirmation,
        signNode = signNode
    )

    signNode.setRequestListener(listener)

    // Run message loop in background
    val messageLoopJob = launch {
        runCatching {
            signNode.messageLoop()
        }.onFailure { e ->
            println("Message loop error: ${e.message}")
        }
    }

    // ---- Requester mode ----
    if (messageInput.isNotEmpty()) {
        println("Requesting signature for message: $messageInput")
        runCatching {
            signNode.requestSignString(message = messageInput, listener = listener)
        }.onFailure { e ->
            println("Error requesting signature: ${e.message}")
        }
    }

    withContext(Dispatchers.IO) {
        while (true) {
            // ---- Simple command loop (approve/list/cancel) ----
            // Keeps your CLI structure lightweight; mirrors Swift's approve-by-index style.
            println("Ready.")
            println("Commands:")
            println("  s <message>              - Request signature for a string message")
            println("  a <index>                - Approve a pending request by index")
            println("  c <index>                - Cancel an outgoing / accepted / pending request by index")
            println("  l                        - List pending requests")
            println("  v <message> <sigHex>     - Verify signature for a string message")
            println("  x                        - Exit")

            val input = readlnOrNull()?.trim().orEmpty()
            if (input.isEmpty()) continue

            val parts = input.split(" ", limit = 2)
            val cmd = parts[0]
            val params = if (parts.size > 1) parts[1].trim() else ""

            when (cmd) {
                "s", "sign" -> {
                    if (params.isEmpty()) {
                        println("Usage: s <message>")
                    } else {
                        println("Requesting signature for: $params")
                        runCatching {
                            signNode.requestSignString(message = params, listener = listener)
                        }.onFailure { e ->
                            println("Error requesting signature: ${e.message}")
                        }
                    }
                }

                "a", "approve" -> {
                    val idx = params.toIntOrNull()
                    if (idx == null) {
                        println("Usage: a <index>")
                        continue
                    }
                    val req = listener.getPending(idx)
                    if (req == null) {
                        println("Invalid request index.")
                        continue
                    }

                    println("Approving request $idx...")
                    runCatching {
                        signNode.acceptRequest(req = req, listener = listener)
                    }.onFailure { e ->
                        println("Error approving request: ${e.message}")
                    }
                }

                "c", "cancel" -> {
                    val idx = params.toIntOrNull()
                    if (idx == null) {
                        println("Usage: c <index>")
                        continue
                    }
                    val req = listener.getPending(idx)
                    if (req == null) {
                        println("Invalid request index.")
                        continue
                    }

                    println("Cancelling request $idx...")
                    runCatching {
                        signNode.cancelRequest(req = req)
                        listener.removePendingByInstance(req.getInstance().toBytes())
                    }.onFailure { e ->
                        println("Error cancelling request: ${e.message}")
                    }
                }

                "l", "list" -> listener.listPending()

                "v", "verify" -> {
                    val parts2 = params.split(" ", limit = 2)
                    if (parts2.size < 2) {
                        println("Usage: v <message> <sigHex>")
                        println("Example: v TimelessDoctor ff47b9...23a4")
                        return@withContext
                    }

                    val msg = parts2[0]
                    val sigHex = parts2[1]

                    val groupVk = localData.groupVk()

                    runCatching {
                        verifySigHex(sigHex, msg, groupVk)
                    }.onFailure { e ->
                        println("Signature INVALID: ${e.message}")
                    }
                }

                "x", "exit", "quit" -> break

                else -> println("Unknown command.")
            }
        }
    }

    // ---- Shutdown ----
    println()
    println("Disconnecting...")
    runCatching { client.disconnect(ReasonCode.SUCCESS) }
    runCatching { connectionJob.cancelAndJoin() }
    runCatching { messageLoopJob.cancelAndJoin() }
    println("Goodbye!")

    exitProcess(0)
}