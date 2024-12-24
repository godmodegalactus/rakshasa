use std::sync::mpsc::channel;

use poh::sha::start_sha256_service;

pub mod identity;
pub mod poh;

pub fn test_fn () {
    let starting_hash = [0;32];
    let (sx1, rx1) = channel();
    let (sx2, rx2) = channel();
    start_sha256_service(starting_hash, rx1, sx2);
}