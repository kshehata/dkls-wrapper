use clap::Parser;
use dkls::sign::{SignMessageType, SignNode, SignRequest, SignRequestListener};
use dkls::types::DeviceLocalData;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

#[path = "common/mod.rs"]
mod common;
use common::mqtt::MQTTClientWrapper;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Keyshare filename.
    keyshare_filename: String,

    /// MQTT host.
    #[arg(long, default_value = "localhost")]
    mqtt_host: String,

    /// MQTT port.
    #[arg(long, default_value_t = 1883)]
    mqtt_port: u16,
}

struct AppState {
    // Store pending requests in a Vec to access by index.
    // Index 0 = Request #1
    pending_requests: Mutex<Vec<Arc<SignRequest>>>,
}

struct ConsoleListener {
    state: Arc<AppState>,
    local_data: Arc<DeviceLocalData>,
    tx: mpsc::Sender<()>, // Signal main loop to print prompt again or something?
                          // Actually just printing to stdout is enough.
}

use dkls::types::find_device_by_vk;

impl SignRequestListener for ConsoleListener {
    fn receive_sign_request(&self, req: Arc<SignRequest>) {
        println!("\n*** NEW SIGN REQUEST ***");
        let index = {
            let mut lock = self.state.pending_requests.lock().unwrap();
            lock.push(req.clone());
            lock.len() - 1
        };

        if let Some(msg) = req.get_message() {
            match msg {
                SignMessageType::String(s) => println!("Message: {}", s),
                SignMessageType::Bytes(b) => println!("Bytes: {:?}", b),
            }
        }

        // Print sender information if available
        let party_vks = req.party_vk();
        if !party_vks.is_empty() {
            let vk = &party_vks[0];
            let name = find_device_by_vk(&self.local_data.devices, vk)
                .map(|d| d.name())
                .unwrap_or_else(|| "Unknown Device".to_string());
            println!("From: {} (VK: {})", name, hex::encode(vk.to_bytes()));
        }

        println!(
            "Request Added as #{}. ID: {}",
            index,
            hex::encode(req.instance)
        );
        println!("Type 'a {}' to approve.", index);
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();

        // Notify main loop? Not strictly needed for cli.
        let _ = self.tx.try_send(());
    }
}

use dkls::error::GeneralError;
use dkls::sign::SignResultListener;
use dkls::types::Signature;

impl SignResultListener for ConsoleListener {
    fn sign_result(&self, req: Arc<SignRequest>, result: Arc<Signature>) {
        println!("\n*** SIGNATURE GENERATED ***");
        println!("Instance ID: {}", hex::encode(req.instance));
        println!("Signature: {}", hex::encode(result.to_bytes()));
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let _ = self.tx.try_send(());
    }

    fn sign_error(&self, req: Arc<SignRequest>, error: GeneralError) {
        println!("\n*** SIGNING ERROR ***");
        println!("Instance ID: {}", hex::encode(req.instance));
        println!("Error: {:?}", error);
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let _ = self.tx.try_send(());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    println!("DKLS CLI Signing Tool");
    println!("Loading keyshare from {}...", args.keyshare_filename);

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
    println!("Loaded ID: {}", hex::encode(local_data.key_id()));

    // Setup MQTT
    let mut mqtt_client = MQTTClientWrapper::new(&args.mqtt_host, args.mqtt_port, "sign");
    // Connect to specific topic for this device
    let topic = format!("sign/{}", hex::encode(local_data.key_id()));
    println!("Subscribing to {}", topic);
    let net_interface = mqtt_client.subscribe(&topic).await;

    // Run MQTT loop
    tokio::spawn(async move {
        mqtt_client.event_loop().await;
    });

    // Create SignNode
    let sign_node = Arc::new(SignNode::new(local_data.clone(), net_interface));

    // Setup state and listener
    let state = Arc::new(AppState {
        pending_requests: Mutex::new(Vec::new()),
    });

    let (tx, mut rx) = mpsc::channel(1);
    let listener = ConsoleListener {
        state: state.clone(),
        local_data: local_data.clone(),
        tx: tx.clone(),
    };
    sign_node.set_listener(Box::new(listener));

    // Create another listener for results (using same state/tx)
    let result_listener = ConsoleListener {
        state: state.clone(),
        local_data: local_data.clone(),
        tx: tx.clone(),
    };
    sign_node.set_result_listener(Box::new(result_listener));

    // Run SignNode message loop
    let node_clone = sign_node.clone();
    tokio::spawn(async move {
        if let Err(e) = node_clone.message_loop().await {
            eprintln!("Message loop error: {:?}", e);
        }
    });

    println!("Ready.");
    println!("Commands:");
    println!("  s, sign <message>    - Request signature for a string message");
    println!("  a, approve <index>   - Approve a pending request by index");
    println!("  l, list              - List pending requests");
    println!("  x, exit              - Exit");

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    print!("> ");
    use std::io::Write;
    std::io::stdout().flush().unwrap();

    loop {
        tokio::select! {
            _ = rx.recv() => {
                // Just woke up from listener notification, prompt is already printed by listener
            }
            res = reader.read_line(&mut line) => {
                if res? == 0 {
                    break; // EOF
                }

                let input = line.trim();
                if input.is_empty() {
                    line.clear();
                    print!("> ");
                    std::io::stdout().flush().unwrap();
                    continue;
                }

                let parts: Vec<&str> = input.split_whitespace().collect();
                let params = if parts.len() > 1 {
                    input[parts[0].len()..].trim().to_string()
                } else {
                    String::new()
                };

                match parts[0] {
                    "s" | "sign" => {
                        if params.is_empty() {
                            println!("Usage: s <message>");
                        } else {
                            println!("Requesting signature for: '{}'", params);
                            if let Err(e) = sign_node.request_sign_string(params).await {
                                eprintln!("Error requesting signature: {:?}", e);
                            } else {
                                println!("Request sent. Waiting for approval...");
                            }
                        }
                    }
                    "a" | "approve" => {
                        if let Ok(idx) = params.parse::<usize>() {
                            let req = {
                                let mut lock = state.pending_requests.lock().unwrap();
                                if idx < lock.len() {
                                    Some(lock.remove(idx))
                                } else {
                                    None
                                }
                            };

                            if let Some(req) = req {
                                println!("Approving request #{}...", idx);
                                if let Err(e) = sign_node.accept_request(req).await {
                                    eprintln!("Error approving: {:?}", e);
                                    // Put it back? Or just assume failures means retry?
                                    // For now, if accept fails, it's gone from list.
                                } else {
                                    println!("Approval sent.");
                                }
                            } else {
                                println!("Invalid request index.");
                            }
                        } else {
                            println!("Usage: a <index>");
                        }
                    }
                    "l" | "list" => {
                        let lock = state.pending_requests.lock().unwrap();
                        if lock.is_empty() {
                            println!("No pending requests.");
                        } else {
                            for (i, req) in lock.iter().enumerate() {
                                print!("[{}] ", i);
                                if let Some(SignMessageType::String(msg)) = req.get_message() {
                                    print!("{}", msg);
                                } else {
                                    print!("<binary data>");
                                }
                                println!(" (ID: {})", hex::encode(req.instance));
                            }
                        }
                    }
                    "x" | "exit" | "quit" => break,
                    _ => println!("Unknown command."),
                }

                line.clear();
                print!("> ");
                std::io::stdout().flush().unwrap();
            }
        }
    }

    Ok(())
}
