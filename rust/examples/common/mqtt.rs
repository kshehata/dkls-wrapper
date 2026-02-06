/*****************************************************************************
 * Example MQTT interface.
 *****************************************************************************/

use dkls::error::GeneralError;
use dkls::net::NetworkInterface;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use rumqttc::v5::mqttbytes::v5::Filter;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, EventLoop, MqttOptions};

pub struct MQTTNetworkInterface {
    client: Arc<AsyncClient>,
    topic: String,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl MQTTNetworkInterface {
    fn new(client: Arc<AsyncClient>, topic: String) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            client,
            topic,
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    async fn on_new_packet(&self, p: Vec<u8>) {
        let _ = self.tx.send(p).await;
    }
}

#[async_trait::async_trait]
impl NetworkInterface for MQTTNetworkInterface {
    async fn send(&self, data: Vec<u8>) -> Result<(), GeneralError> {
        self.client
            .publish(&self.topic, QoS::AtLeastOnce, false, data)
            .await
            .map_err(|_e| GeneralError::MessageSendError)?;
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, GeneralError> {
        let mut rx = self.rx.lock().await;
        loop {
            let data = rx.recv().await.ok_or(GeneralError::MessageSendError)?;
            return Ok(data);
        }
    }
}

// Wrapper to help with making interfaces to topics.
pub struct MQTTClientWrapper {
    client: Arc<AsyncClient>,
    eventloop: EventLoop,
    subscribers: RwLock<HashMap<String, Arc<MQTTNetworkInterface>>>,
}

impl MQTTClientWrapper {
    pub fn new(host: &str, port: u16, id_prefix: &str) -> Self {
        let mut mqttoptions = MqttOptions::new(
            format!("{}-{}", id_prefix, uuid::Uuid::new_v4()),
            host,
            port,
        );
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        mqttoptions.set_max_packet_size(Some(20 * 1024 * 1024));

        let (client, eventloop) = AsyncClient::new(mqttoptions, 10);
        Self {
            client: Arc::new(client),
            eventloop,
            subscribers: RwLock::new(HashMap::new()),
        }
    }

    pub async fn subscribe(&self, topic: &str) -> Arc<MQTTNetworkInterface> {
        let mut subscribers = self.subscribers.write().unwrap();
        if subscribers.contains_key(topic) {
            return subscribers.get(topic).unwrap().clone();
        }
        let mut filter = Filter::new(topic.to_string(), QoS::AtLeastOnce);
        filter.nolocal = true;
        self.client.subscribe_many(vec![filter]).await.unwrap();

        let sub = Arc::new(MQTTNetworkInterface::new(
            self.client.clone(),
            topic.to_string(),
        ));
        subscribers.insert(topic.to_string(), sub.clone());
        sub
    }

    pub async fn event_loop(&mut self) {
        loop {
            match self.eventloop.poll().await {
                Ok(notification) => {
                    use rumqttc::v5::mqttbytes::v5::Packet;
                    if let rumqttc::v5::Event::Incoming(Packet::Publish(p)) = notification {
                        let topic = std::str::from_utf8(&p.topic).unwrap_or_default();
                        // Get subscriber from within the lock, cloning Arc.
                        let sub = self
                            .subscribers
                            .read()
                            .unwrap()
                            .get(topic)
                            .map(|s| s.clone());
                        if let Some(sub) = sub {
                            sub.on_new_packet(p.payload.to_vec()).await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("MQTT Error: {:?}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}
