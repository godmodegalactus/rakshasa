use std::sync::mpsc::{Receiver, Sender, channel};

use crate::identity::signature::Signature;

pub struct PoHResult {
    pub hash: [u8; 32],
    pub signatures: Vec<Signature>,
}

pub const NUM_SIGNATURES_PER_HASH: usize = 16;

/// this is the main loop of the PoH service
/// it will calculate sha256 hashes in loop
pub fn start_sha256_service(starting_hash: [u8; 32], signature_channel: Receiver<Vec<Signature>>, result_channel: Sender<PoHResult>) {
    let mut current_hash = starting_hash;
    let mut remaining_signatures = vec![];
    loop {
        let signatures = {
            let mut signatures = remaining_signatures.drain(..).collect::<Vec<Signature>>();
            while signatures.len() < NUM_SIGNATURES_PER_HASH {
                match signature_channel.try_recv() {
                    Ok(mut more_signatures) => {
                        signatures.append(&mut more_signatures);
                        if signatures.len() >= NUM_SIGNATURES_PER_HASH {
                            if signatures.len() > NUM_SIGNATURES_PER_HASH {
                                remaining_signatures = signatures.split_off(NUM_SIGNATURES_PER_HASH);
                            }
                            break signatures;
                        }
                    }
                    Err(_) => {
                        // we will just continue with the signatures we have

                        break signatures;
                    }
                }
            }
        };
        let new_hash  = calculate_sha256_hash(&current_hash, &signatures);
        let result = PoHResult {
            hash: new_hash,
            signatures,
        };
        if let Err(e) = result_channel.send(result) {
            log::error!("PoH result_channel.send() failed: {:?}", e);
            break;
        }
    }
}

pub fn test_fn () {
    println!("do nothing");
}

pub fn calculate_sha256_hash(input: &[u8;32], signatures: &[Signature]) -> [u8; 32] {
    let mut hasher = sha256::Sha256::new();
    hasher.input(input);
    for signature in signatures {
        hasher.input(&signature.0);
    }
    let result = hasher.result();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::identity::signature::gen_signature;
    use core::hash;
    use std::sync::mpsc::channel;

    #[test]
    fn test_calculate_sha256_hash() {
        let input = [0u8; 32];
        let signature = gen_signature();
        let hash = calculate_sha256_hash(&input, &[signature]);
        assert_ne!(hash, input);

        let hash2 = calculate_sha256_hash(&input, &[signature]);
        assert_eq!(hash2, hash);

        let hash3 = calculate_sha256_hash(&input, &[]);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_start_sha256_service() {
        let (signature_sender, signature_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        let starting_hash = [0u8; 32];
        let signature = gen_signature();
        signature_sender.send(vec![signature]).unwrap();
        start_sha256_service(starting_hash, signature_receiver, result_sender);
        let result = result_receiver.recv().unwrap();
        assert_ne!(result.hash, starting_hash);
        assert_eq!(result.signatures.len(), 1);
    }
}