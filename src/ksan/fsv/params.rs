use num_bigint::BigInt;
use kzen_paillier::RawCiphertext;
use crate::blocks::vrs::VRSSignature;

#[derive(Clone, Debug)]
pub struct SecParams{
    pub bits_chash_vrs: usize,
    pub bits_pke: usize
}

#[derive(Clone, Debug)]
pub struct PublicParams{
    pub secp: SecParams,
    pub p: BigInt,
    pub q: BigInt,
    pub g: BigInt
}

#[derive(Clone, Debug)]
pub struct SignerPublicKey{
    pub pk: k256::FieldBytes
}

#[derive(Clone)]
pub struct SignerSecretKey{
    pub sk: k256::schnorr::SigningKey
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
pub struct Proof{
    pub ps: Option<k256::schnorr::Signature>,
    pub pz: Option<VRSSignature>
}

#[derive(Clone, Debug)]
pub struct CHashPubValues {
    pub h: BigInt,
    pub r: BigInt,
    pub pkch: BigInt
}

#[derive(Clone, Debug)]
pub struct Mod {
    pub i: usize,
    pub m: String
}

#[derive(Clone, Debug)]
pub struct Signature<'d>{
    pub s: k256::schnorr::Signature,
    pub hashes: Vec<CHashPubValues>,
    pub secrets: Vec<Vec<RawCiphertext<'d>>>,
    pub pub_adm: Vec<bool>,
    pub n: usize,
    pub proofs: Vec<Proof>
}