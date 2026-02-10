use clap::Parser;
use dkls::dkg::{DKGNode, DKGSetupChangeListener, DKGState, DKGStateChangeListener, QRData};
use dkls::net::NetworkInterface;
use dkls::types::{DeviceInfo, InstanceId};

use std::sync::Arc;

#[path = "common/mod.rs"]
mod common;
use common::mqtt::MQTTClientWrapper;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of this device.
    name: String,

    /// InstanceID to use in Base45 encoding. If not set, a random InstanceID will be generated.
    #[arg(long, default_value = "")]
    instance_id: String,

    /// Threshold number of devices. Only valid for new instances.
    #[arg(short, long, default_value_t = 2)]
    threshold: u8,

    /// Output filename.
    #[arg(short, long, default_value = "keyshare")]
    output_filename: String,

    /// MQTT host.
    #[arg(long, default_value = "localhost")]
    mqtt_host: String,

    /// MQTT port.
    #[arg(long, default_value_t = 1883)]
    mqtt_port: u16,

    /// QR Data from other party.
    #[arg(short, long, default_value = "")]
    qr_data: String,
}

struct SimpleSetupListener;
impl DKGSetupChangeListener for SimpleSetupListener {
    fn on_setup_changed(&self, parties: Vec<Arc<DeviceInfo>>, my_id: u8) {
        println!("\n--- DKG Setup Update ---");
        println!("Parties ({}):", parties.len());
        for (i, party) in parties.iter().enumerate() {
            let verified = if i == my_id as usize {
                " (this device)"
            } else if party.verified {
                " (Verified)"
            } else {
                ""
            };
            let mark = if i == my_id as usize {
                "•"
            } else if party.verified {
                "✓"
            } else {
                "?"
            };
            println!("  {}. {} {}{}", i + 1, mark, party.friendly_name, verified);
        }
        println!("------------------------\n");
    }
}

struct SimpleStateListener {
    dkg_node: Arc<DKGNode>,
}

impl DKGStateChangeListener for SimpleStateListener {
    fn on_state_changed(&self, old_state: DKGState, new_state: DKGState) {
        println!("State changed: {:?} -> {:?}", old_state, new_state);
        // If we are waiting for parties or setup, print our QR code
        if old_state == DKGState::WaitForSetup
            && (new_state == DKGState::WaitForDevices
                || new_state == DKGState::Ready
                || new_state == DKGState::WaitForSigs)
        {
            if let Ok(qr) = self.dkg_node.get_qr_bytes() {
                println!("My QR: {}", base45::encode(&qr));
            }
        }
    }
}

async fn make_net_if(
    host: &str,
    port: u16,
    instance_str: &str,
) -> (Arc<dyn NetworkInterface>, Arc<dyn NetworkInterface>) {
    let mut mqtt_client = MQTTClientWrapper::new(host, port, "dkg");
    let setup_if = mqtt_client
        .subscribe(&format!("dkg/{}/setup", instance_str))
        .await;
    let dkg_if = mqtt_client
        .subscribe(&format!("dkg/{}/proto", instance_str))
        .await;
    tokio::spawn(async move {
        mqtt_client.event_loop().await;
    });
    (setup_if, dkg_if)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let output_filename = format!("{}_{}", args.output_filename, args.name);

    println!("DKLS CLI DKG Test (Rust)");
    println!("Output filename: {}", output_filename);
    println!("MQTT host: {}", args.mqtt_host);
    println!("MQTT port: {}", args.mqtt_port);
    println!();

    let dkg_node: Arc<DKGNode>;

    let instance_str = if args.qr_data.is_empty() {
        // Initiator
        let instance_id = if args.instance_id.is_empty() {
            InstanceId::from_entropy()
        } else {
            let bytes = base45::decode(&args.instance_id)
                .map_err(|e| format!("Invalid base45 instance ID: {:?}", e))?;
            // InstanceId is [u8; 32]
            let mut arr = [0u8; 32];
            if bytes.len() != 32 {
                panic!("Instance ID must be 32 bytes from base45");
            }
            arr.copy_from_slice(&bytes);
            InstanceId::from(arr)
        };

        // Instance ID to hex string for topic
        let instance_str = hex::encode(instance_id);

        println!(
            "Starting DKG as starter for instance {}, threshold {}",
            instance_str, args.threshold
        );
        dkg_node = Arc::new(DKGNode::new(&args.name, &instance_id, args.threshold));

        println!("My QR: {}", base45::encode(&dkg_node.get_qr_bytes()?));
        instance_str
    } else {
        // Participant
        println!("Starting DKG as participant for QR data");
        let qr_bytes = base45::decode(&args.qr_data)
            .map_err(|e| format!("Invalid base45 QR data: {:?}", e))?;

        // We need to peek at the QR data to get the instance ID used for MQTT topics
        // But `DKGNode::from_qr_bytes` consumes it or parses it.
        // We can parse it manually using `QRData::try_from`.
        let qr_data = QRData::try_from(qr_bytes.as_slice())?;

        dkg_node = Arc::new(DKGNode::try_from_qr_bytes(&args.name, &qr_bytes)?);
        hex::encode(qr_data.instance)
    };

    dkg_node.add_setup_change_listener(Box::new(SimpleSetupListener));
    dkg_node.add_state_change_listener(Box::new(SimpleStateListener {
        dkg_node: dkg_node.clone(),
    }));

    // Input loop for QR scanning (if initiator needs to scan others)
    // We spawn a task for reading stdin
    let dkg_node_clone = dkg_node.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break; // EOF
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                if dkg_node_clone.get_state() == DKGState::Ready {
                    println!("Starting DKG...");
                    if let Err(e) = dkg_node_clone.start_dkg().await {
                        eprintln!("Error starting DKG: {:?}", e);
                    }
                } else {
                    println!("Not ready yet.");
                }
            } else {
                // assume QR data
                if let Ok(data) = base45::decode(trimmed) {
                    if let Err(e) = dkg_node_clone.receive_qr_bytes(&data) {
                        eprintln!("Error in QR data: {:?}", e);
                    }
                } else {
                    eprintln!("Invalid base45");
                }
            }
        }
    });

    let (setup_if, dkg_if) = make_net_if(&args.mqtt_host, args.mqtt_port, &instance_str).await;
    println!("Starting message loop...");
    dkg_node.message_loop(setup_if, dkg_if).await?;
    println!("Message loop completed.");

    let local_data = dkg_node.get_local_data()?;
    let bytes = local_data.to_bytes();
    tokio::fs::write(&output_filename, bytes).await?;
    println!("✓ Device local data written to {}", output_filename);
    std::process::exit(0);
}
