use k256::{elliptic_curve::rand_core, schnorr::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey
}, FieldBytes};
use rand_core::OsRng;

pub struct SIG;

impl SIG {
    pub fn k_gen() -> (SigningKey, FieldBytes) {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        return (sk, pk);
    }

    pub fn sign(sk: &SigningKey, m: &str) -> k256::schnorr::Signature {
        return sk.sign(m.as_bytes());
    }

    pub fn verify(pk: &FieldBytes, m: &str, s: &k256::schnorr::Signature) -> bool {
        match VerifyingKey::from_bytes(&pk) {
            Ok(verifying_key) => match verifying_key.verify(m.as_bytes(), &s) {
                Ok(_) => true,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}