use std::sync::mpsc::{Receiver, Sender};

use crate::identity::signature::Signature;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct PoHResult {
    pub hash: [u8; 32],
    pub signatures: Vec<Signature>,
}

pub const NUM_SIGNATURES_PER_HASH: usize = 16;

/// this is the main loop of the PoH service
/// it will calculate sha256 hashes in loop
pub fn start_sha256_service(
    starting_hash: [u8; 32],
    signature_channel: Receiver<Vec<Signature>>,
    result_channel: Sender<PoHResult>,
) {
    let mut current_hash = starting_hash;
    let mut remaining_signatures = vec![];
    loop {
        let signatures = {
            let mut signatures = std::mem::take(&mut remaining_signatures);
            while signatures.len() < NUM_SIGNATURES_PER_HASH {
                match signature_channel.try_recv() {
                    Ok(mut more_signatures) => {
                        signatures.append(&mut more_signatures);
                        if signatures.len() >= NUM_SIGNATURES_PER_HASH {
                            if signatures.len() > NUM_SIGNATURES_PER_HASH {
                                remaining_signatures =
                                    signatures.split_off(NUM_SIGNATURES_PER_HASH);
                            }
                            break;
                        }
                    }
                    Err(_) => {
                        // we will just continue with the signatures we have
                        break;
                    }
                }
            }
            signatures
        };
        let new_hash = calculate_sha256_hash(&current_hash, &signatures);
        let result = PoHResult {
            hash: new_hash,
            signatures,
        };
        if let Err(e) = result_channel.send(result) {
            log::error!("PoH result_channel.send() failed: {:?}", e);
            break;
        }
        current_hash = new_hash;
    }
}

pub fn calculate_sha256_hash(input: &[u8; 32], signatures: &[Signature]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    for signature in signatures {
        hasher.update(signature.0);
    }
    let hash: [u8; 32] = hasher.finalize().into();
    hash
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::identity::signature::gen_signature;
    use core::panic;
    use std::{sync::mpsc::channel, time::Instant};

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

        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver, result_sender)
        });

        let signature = gen_signature();
        signature_sender.send(vec![signature]).unwrap();
        let mut current_hash = [0u8; 32];
        while let Ok(result) = result_receiver.recv() {
            if result.signatures.len() == 0 {
                let calculated_hash = calculate_sha256_hash(&current_hash, &[]);
                assert_eq!(result.hash, calculated_hash);
                current_hash = calculated_hash;
            } else {
                assert_eq!(result.signatures.len(), 1);
                assert_eq!(result.signatures[0], signature);

                let calculated_hash = calculate_sha256_hash(&current_hash, &[signature]);
                assert_eq!(result.hash, calculated_hash);
                break;
            }
        }
    }

    #[test]
    fn test_two_services_with_no_transactions_gives_same_hash_sequence() {
        let (_signature_sender, signature_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        let starting_hash = [8u8; 32];

        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver, result_sender)
        });

        let (_signature_sender_2, signature_receiver_2) = channel();
        let (result_sender_2, result_receiver_2) = channel();
        let starting_hash = [8u8; 32];
        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver_2, result_sender_2)
        });

        let sequence_1 = {
            let mut seq = vec![];
            seq.reserve(1_000_000);

            for _ in 0..1_000_000 {
                let result = result_receiver.recv().unwrap();
                seq.push(result);
            }
            seq
        };

        let sequence_2 = {
            let mut seq = vec![];
            seq.reserve(1_000_000);

            for _ in 0..1_000_000 {
                let result = result_receiver_2.recv().unwrap();
                seq.push(result);
            }
            seq
        };
        assert_eq!(sequence_1, sequence_2)
    }

    #[test]
    fn test_two_services_with_no_transactions_but_different_starting_hash_gives_different_hash_sequence(
    ) {
        let (_signature_sender, signature_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        let starting_hash = [8u8; 32];

        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver, result_sender)
        });

        let (_signature_sender_2, signature_receiver_2) = channel();
        let (result_sender_2, result_receiver_2) = channel();
        let starting_hash = [9u8; 32];
        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver_2, result_sender_2)
        });

        let sequence_1 = {
            let mut seq = vec![];
            seq.reserve(1_000_000);

            for _ in 0..1_000_000 {
                let result = result_receiver.recv().unwrap();
                seq.push(result);
            }
            seq
        };

        let sequence_2 = {
            let mut seq = vec![];
            seq.reserve(1_000_000);

            for _ in 0..1_000_000 {
                let result = result_receiver_2.recv().unwrap();
                seq.push(result);
            }
            seq
        };
        for i in 0..1_000_000 {
            assert_ne!(sequence_1[i], sequence_2[i]);
        }
    }

    #[test]
    pub fn bench_sha_loop_no_transactions() {
        let (_signature_sender, signature_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        let starting_hash = [0u8; 32];
        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver, result_sender)
        });
        let nb_hashes = 10_000_000;
        while let Ok(_result) = result_receiver.try_recv() {
            // do nothing
        }
        let start = Instant::now();
        for _ in 0..nb_hashes {
            if let Err(e) = result_receiver.recv() {
                panic!("result_receiver.recv() failed: {:?}", e);
            }
        }
        let elapsed = start.elapsed();
        println!(
            "with no signatures does: {:?} sha hashes/second",
            nb_hashes / elapsed.as_secs()
        );
    }

    #[test]
    pub fn bench_sha_loop_full_transactions() {
        let (signature_sender, signature_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        let starting_hash = [0u8; 32];
        let nb_hashes = 1_000_000 as u64;

        // populate the channel with signatures
        for _ in 0..nb_hashes * (NUM_SIGNATURES_PER_HASH as u64) + 10 {
            let signature = gen_signature();
            signature_sender.send(vec![signature]).unwrap();
        }

        std::thread::spawn(move || {
            start_sha256_service(starting_hash, signature_receiver, result_sender)
        });
        while let Ok(_result) = result_receiver.try_recv() {
            // do nothing
        }
        let start = Instant::now();
        for _ in 0..nb_hashes {
            match result_receiver.recv() {
                Ok(result) => {
                    assert_eq!(result.signatures.len(), NUM_SIGNATURES_PER_HASH);
                }
                Err(e) => {
                    panic!("result_receiver.recv() failed: {:?}", e);
                }
            }
        }
        let elapsed = start.elapsed();
        println!(
            "with {} signatures does: {:?} sha hashes/second",
            NUM_SIGNATURES_PER_HASH,
            nb_hashes / elapsed.as_secs()
        );
    }
}
