use clap::Parser;
use dkls::sign::SignNode;
use dkls::types::{find_device_by_vk, DeviceLocalData, NodeVerifyingKey, Signature};

use std::io::{self, Write};
use std::sync::Arc;

#[path = "common/mod.rs"]
mod common;
use common::mqtt::MQTTClientWrapper;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Keyshare filename.
    keyshare_filename: String,

    /// Message to sign.
    #[arg(short, long, default_value = "")]
    message: String,

    /// Assume yes for any confirmation prompts.
    #[arg(short = 'y', long)]
    skip_confirmation: bool,

    /// MQTT host.
    #[arg(long, default_value = "localhost")]
    mqtt_host: String,

    /// MQTT port.
    #[arg(long, default_value_t = 1883)]
    mqtt_port: u16,
}

fn verify_sig(sig: &Signature, message: &[u8], vk: &NodeVerifyingKey) {
    println!("✓ Signature generated");
    println!();
    println!("Signature bytes: {} bytes", sig.to_bytes().len());
    println!("{}", hex::encode(sig.to_bytes()));
    println!();

    match vk.verify(message, sig) {
        Ok(_) => println!("✓ Signature verified"),
        Err(e) => println!("Error: Signature verification failed: {:?}", e),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    println!("DKLS CLI Signing Test (Rust)");
    println!();

    let local_data_bytes = tokio::fs::read(&args.keyshare_filename)
        .await
        .map_err(|e| {
            eprintln!("Error reading local data: {}", e);
            e
        })?;

    let local_data = DeviceLocalData::from_bytes(&local_data_bytes).map_err(|e| {
        eprintln!("Error parsing local data: {:?}", e);
        e
    })?;
    let local_data = Arc::new(local_data);

    println!("MQTT host: {}", args.mqtt_host);
    println!("MQTT port: {}", args.mqtt_port);
    println!();

    let mut mqtt_client = MQTTClientWrapper::new(&args.mqtt_host, args.mqtt_port, "sign");
    let net_interface = mqtt_client
        .subscribe(&format!("sign/{}", hex::encode(local_data.key_id())))
        .await;
    tokio::spawn(async move {
        mqtt_client.event_loop().await;
    });

    println!("👂 Listening for messages...");

    let sign_node = SignNode::new(local_data.clone());

    if args.message.is_empty() {
        // Listener Loop
        loop {
            match sign_node.get_next_req(net_interface.clone()).await {
                Ok(req) => {
                    if let Err(e) = req.check_sigs() {
                        eprintln!("Error checking sigs: {:?}", e);
                        continue;
                    }
                    println!("Received signature request:");
                    println!("InstanceID: {:?}", req.instance);

                    println!("Message:");
                    let msg_bytes = req.message();
                    if let Ok(msg_str) = String::from_utf8(msg_bytes.clone()) {
                        println!("{}", msg_str);
                    } else {
                        println!("{:?}", msg_bytes);
                    }

                    if req.party_vk.len() != 1 {
                        eprintln!("ERROR: Request has {} signatures", req.party_vk.len());
                        continue;
                    }

                    let device = find_device_by_vk(&local_data.get_device_list(), &req.party_vk[0]);
                    if let Some(d) = &device {
                        println!("From: {}", d.name());
                    } else {
                        println!("WARNING: Request from unknown device");
                    }

                    if device.is_some() && args.skip_confirmation {
                        println!("Skipping confirmation");
                    } else {
                        print!("Approve? [y/N] ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        if input.trim().to_lowercase() != "y" {
                            continue;
                        }
                    }

                    match sign_node
                        .do_join_request(Arc::new(req), net_interface.clone())
                        .await
                    {
                        Ok(sig) => {
                            verify_sig(&sig, &msg_bytes, &local_data.group_vk());
                            break;
                        }
                        Err(e) => eprintln!("Error: {:?}", e),
                    }
                }
                Err(e) => eprintln!("Error waiting for request: {:?}", e),
            }
        }
    } else {
        // Requester
        println!("Requesting signature for message: {}", args.message);
        let message_bytes = args.message.as_bytes().to_vec();
        match sign_node
            .do_sign_bytes(message_bytes.clone(), net_interface.clone())
            .await
        {
            Ok(sig) => verify_sig(&sig, &message_bytes, &local_data.group_vk()),
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }

    // Disconnect logic is handled by dropping client? rumqttc handles it.
    println!("Goodbye!");

    Ok(())
}
