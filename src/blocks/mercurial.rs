use mercurial_signature::{Curve, CurveBls12_381, PublicParams, change_representation, SecretKey, PublicKey, Signature};
use num_bigint::{BigInt, BigUint};
use rand::rngs::ThreadRng;

type G1 = <CurveBls12_381 as Curve>::G1;
type Fr = <CurveBls12_381 as Curve>::Fr;

#[derive(Clone)]
pub struct BG {
    pub rng: ThreadRng,
    pub pp: PublicParams,
    pub n: u32
}

pub struct Mercurial;

impl Mercurial {
    pub fn setup(n: u32, _dst: &String) -> BG {
        let mut rng = rand::thread_rng();
        let pp = PublicParams::new(&mut rng);
        return BG{
            rng: rng,
            pp: pp,
            n: n
        };
    }

    pub fn k_gen(bg: &mut BG) -> (SecretKey, PublicKey) {
        let (pk, sk) = bg.pp.key_gen(&mut bg.rng, bg.n);
        return (sk, pk);
    }

    pub fn sign(bg: &mut BG, sk: &mut SecretKey, m: &Vec<G1>) -> Signature{
        let sig = sk.sign(&mut bg.rng, &bg.pp, &m);
        return sig;
    }

    pub fn verify(bg: &mut BG, pk: &PublicKey, m: &Vec<G1>, s: &Signature) -> bool {
        return pk.verify(&bg.pp, &m, &s);
    }

    pub fn chg_rep(bg: &mut BG, _pk: &PublicKey, m: &mut Vec<G1>, s: &mut Signature, r: &BigInt) -> (Signature, Vec<G1>) {
        let r_ = Fr::from(BigUint::from_bytes_be(&r.to_bytes_be().1));
        change_representation(&mut bg.rng, m, s, r_);
        return (s.clone(), m.clone());
    }
}