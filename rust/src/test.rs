use sl_dkls23::keygen;
use sl_dkls23::setup::{
    keygen::SetupMessage, keygen::SetupMessage as KeygenSetupMessage, NoSigningKey, NoVerifyingKey,
};

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::sync::Arc;

use crate::types::*;

//helper function to create the setup messages per party
fn setup_keygen(t: usize, n: usize, ranks: Option<&[u8]>) -> Vec<KeygenSetupMessage> {
    use std::time::Duration;

    use sl_mpc_mate::message::InstanceId;

    let ranks = if let Some(ranks) = ranks {
        assert_eq!(ranks.len(), n);
        ranks.to_vec()
    } else {
        vec![0u8; n]
    };

    // fetch some randomness in order to uniquely identify that protocol execution with an instance id
    let mut rnd = ChaCha20Rng::from_entropy();
    let instance = rnd.gen();

    // a secret signing key for each party in order to send signed messages over the network.
    // For local tests that is disabled with an empty key
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey).take(n).collect();

    // Compute the corresponding verification key of each party
    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(party_id, _)| NoVerifyingKey::new(party_id))
        .collect();

    // A vector of signing keys for each party. For local tests, using empty NoSigningKey
    // Each party gets a NoSigningKey which disables message signing for local testing purposes
    // The vector contains n copies of NoSigningKey, where n is the number of parties
    party_sk
        .into_iter()
        .enumerate()
        .map(|(party_id, sk)| {
            // Create setup messages for each party in the signing protocol.
            // Each setup message contains:
            // - A unique instance ID to identify this protocol run
            // - The party's signing key (using NoSigningKey mock implementation)
            // - The party's index
            // - The verifying keys of all parties
            // - The party's ranks
            // - Time-to-live duration
            SetupMessage::new(
                InstanceId::new(instance),
                sk,
                party_id,
                party_vk.clone(),
                &ranks,
                t,
            )
            .with_ttl(Duration::from_secs(1000)) // for dkls-metrics benchmarks
        })
        .collect::<Vec<_>>()
}

//helper function to generate the keyshares for the sign protocol
pub async fn gen_keyshares_async(t: usize, n: usize) -> Vec<Keyshare> {
    // Create a new message relay coordinator for inter-party communication
    // This provides the infrastructure for parties to exchange messages during the protocol
    let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

    // Create a JoinSet to manage multiple concurrent party tasks, one for each node in the protocol
    let mut parties = tokio::task::JoinSet::new();

    // Spawn tasks for each party using the setup parameters
    for setup in setup_keygen(t, n, None) {
        parties.spawn({
            // Create a new relay connection for this party
            let relay = coord.connect();
            // Initialize random number generator
            let mut rng = ChaCha20Rng::from_entropy();
            // Run the keygen protocol for this party
            keygen::run(setup, rng.gen(), relay)
        });
    }

    let mut shares = vec![];

    // Wait for all party tasks to complete and collect results
    while let Some(fini) = parties.join_next().await {
        // Handle any errors that occurred during task execution
        if let Err(ref err) = fini {
            println!("error {err:?}");
        } else {
            match fini.unwrap() {
                Err(err) => panic!("err {:?}", err),
                Ok(share) => shares.push(Arc::new(share)),
            }
        }
    }

    shares.sort_by_key(|share| share.party_id);

    shares.into_iter().map(|share| Keyshare(share)).collect()
}

#[uniffi::export]
pub fn gen_keyshares(t: u8, n: u8) -> Vec<Arc<Keyshare>> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let shares = rt.block_on(gen_keyshares_async(t as usize, n as usize));
    shares.into_iter().map(|share| Arc::new(share)).collect()
}

#[uniffi::export]
pub fn gen_random_keys(n: u8) -> Vec<Arc<NodeSecretKey>> {
    (0..n)
        .map(|_| Arc::new(NodeSecretKey::from_entropy()))
        .collect()
}

pub fn gen_random_keypairs(n: u8) -> (Vec<Arc<NodeSecretKey>>, Vec<NodeVerifyingKey>) {
    let sks = gen_random_keys(n);
    let vks = sks
        .iter()
        .map(|sk| NodeVerifyingKey::from_sk(&sk))
        .collect();
    (sks, vks)
}
