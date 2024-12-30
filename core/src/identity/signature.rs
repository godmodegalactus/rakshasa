use rand::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Signature(pub [u8; 64]);

pub fn gen_signature() -> Signature {
    let mut rng = rand::thread_rng();
    let mut signature = [0u8; 64];
    rng.fill_bytes(&mut signature);
    Signature(signature)
}
