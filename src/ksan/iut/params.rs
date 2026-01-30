use delegatable_credentials::mercurial_sig::{PreparedPublicKey, SecretKey, Signature as EQS_Signature};
use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
use num_bigint::BigInt;
use kzen_paillier::RawCiphertext;
use crate::blocks::eqs::BG;
use crate::blocks::vrs::{VRSSignature, VRSProof};

#[derive(Clone, Debug)]
pub struct SecParams{
    pub bits_vrs: usize,
    pub bits_pke: usize,
    pub n: u32,
    pub dst: String
}

#[derive(Clone, Debug)]
pub struct PublicParams{
    pub secp: SecParams,
    pub bg: BG,
    pub p: BigInt,
    pub q: BigInt,
    pub g: BigInt
}

#[derive(Clone, Debug)]
pub struct SignerPublicKey{
    pub pk_eqs: PreparedPublicKey<Bls12_381>,
    pub pkp: BigInt
}

#[derive(Clone, Debug)]
pub struct SignerSecretKey{
    pub sk_eqs: SecretKey<Bls12_381>,
    pub skp: BigInt
}

#[derive(Clone, Debug)]
pub struct SanitizerPublicKey{
    pub pke: kzen_paillier::EncryptionKey,
    pub pkp: BigInt
}

#[derive(Clone, Debug)]
pub struct SanitizerSecretKey{
    pub ske: kzen_paillier::DecryptionKey,
    pub skp: BigInt
}

#[derive(Clone, Debug)]
pub struct Mod {
    pub i: usize,
    pub m: String
}

#[derive(Clone, Debug)]
pub struct SignatureSS<'d>{
    pub s_x_eqs: EQS_Signature<Bls12_381>,
    pub s_y_eqs: EQS_Signature<Bls12_381>,
    pub s_bls: Vec<G2Projective>,
    pub pk1_bls: Vec<G1Projective>,
    pub pk2_bls: Vec<G1Projective>,
    pub secrets: Vec<Vec<RawCiphertext<'d>>>
}

#[derive(Clone, Debug)]
pub struct Signature<'d>{
    pub s_ss: SignatureSS<'d>,
    pub s_vrs: VRSSignature
}

#[derive(Clone, Debug)]
pub struct Proof{
    pub pr: VRSProof
}