package app.CLICore

import io.github.davidepianca98.MQTTClient
import io.github.davidepianca98.mqtt.Subscription
import io.github.davidepianca98.mqtt.packets.Qos
import io.github.davidepianca98.mqtt.packets.mqtt.MQTTPublish
import io.github.davidepianca98.mqtt.packets.mqttv5.SubscriptionOptions
import kotlinx.coroutines.channels.Channel
import uniffi.dkls.NetworkInterface
import java.util.concurrent.ConcurrentHashMap

/**
 * Kotlin equivalent of the Swift MQTTTopicInterface.swift:
 * - One instance == one topic
 * - Subscribes in init (QoS 1, MQTT v5 No Local)
 * - receive() suspends until next payload for that topic
 * - send() publishes to that topic (QoS 1, optional retain)
 *
 * IMPORTANT: You must forward inbound publishes to MQTTInterface.dispatch(publish)
 * from the single KMQTT publishReceived callback (because KMQTT delivers all
 * inbound messages through that one callback).
 */
@OptIn(ExperimentalUnsignedTypes::class)
class MQTTInterface(
    private val client: MQTTClient,
    private val topic: String,
    private val retainOnSend: Boolean = false,
    channelCapacity: Int = Channel.BUFFERED
) : NetworkInterface {

    companion object {
        // One global registry so the single MQTTClient callback can find the right interface by topic.
        private val interfacesByTopic = ConcurrentHashMap<String, MQTTInterface>()

        /**
         * Call this from MQTTClient(publishReceived = { publish -> ... }) to deliver messages
         * to the right MQTTInterface instance. This is internal (not public API for users).
         */
        internal suspend fun dispatch(publish: MQTTPublish) {
            interfacesByTopic[publish.topicName]?.handleIncoming(publish)
        }
    }

    private val messageChannel = Channel<ByteArray>(capacity = channelCapacity)

    init {
        // Register first so early retained/fast messages after subscribe don't race.
        // (KMQTT may deliver quickly once subscription is active.)
        interfacesByTopic[topic] = this

        client.subscribe(
            subscriptions = listOf(
                Subscription(
                    topicFilter = topic,
                    options = SubscriptionOptions(
                        qos = Qos.AT_LEAST_ONCE,
                        noLocal = true  // POI...
                    )
                )
            )
        )
    }

    // Private: only the companion dispatch() can reach this.
    private suspend fun handleIncoming(publish: MQTTPublish) {
        if (publish.topicName != topic) return
        val payload = publish.payload ?: return
        // DEBUG
        //println("MQTTInterface IN matched topic='$topic' payloadBytes=${payload.size}")
        // Use send() (not trySend) to avoid silently dropping protocol messages.
        messageChannel.send(payload.toByteArray())
    }

    override suspend fun send(data: ByteArray) {
        // DEBUG
        //println("MQTTInterface OUT topic='$topic' payloadBytes=${data.size}")
        client.publish(
            retain = retainOnSend,
            topic = topic,
            qos = Qos.AT_LEAST_ONCE,
            payload = data.toUByteArray()
        )
    }

    override suspend fun receive(): ByteArray = messageChannel.receive()
}