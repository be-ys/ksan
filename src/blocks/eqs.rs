use delegatable_credentials::mercurial_sig::*;
use num_bigint::{BigUint, BigInt};
use delegatable_credentials::util::generator_pair;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct BG {
    pub rng: StdRng,
    pub p1: G1Affine,
    pub p2: G2Affine,
    pub n: u32,
    //Domain Separation Tag
    pub dst: String
}

pub struct EQS;

impl EQS {
    pub fn setup(n: u32, dst: &String) -> BG {
        let mut rng = StdRng::seed_from_u64(OsRng.next_u64());
        let (p1, p2) = generator_pair::<Bls12_381, StdRng>(&mut rng);
        let bg = BG {
            rng: rng,
            p1: p1,
            p2: p2,
            n: n,
            dst: dst.clone()
        }; 
        return bg;
    }

    pub fn k_gen(bg: &mut BG) -> (SecretKey<Bls12_381>, PreparedPublicKey<Bls12_381>) {
        let sk = SecretKey::new(&mut bg.rng, bg.n).unwrap();
        let pk = PublicKey::<Bls12_381>::new(&sk, &bg.p2);
        let prep_pk = PreparedPublicKey::from(pk.clone());
        return (sk, prep_pk);
    }

    pub fn sign(bg: &mut BG, sk: &SecretKey<Bls12_381>, m: &Vec<G1Affine>) -> Signature<Bls12_381> {
        return Signature::new(&mut bg.rng, &m, &sk, &bg.p1, &bg.p2).unwrap();
    }

    pub fn verify(bg: &mut BG, pk: &PreparedPublicKey<Bls12_381>, m: &Vec<G1Affine>, s: &Signature<Bls12_381>) -> bool {
        return s.verify(&m, pk.clone(), &bg.p1, bg.p2.clone()).is_ok();
    }

    pub fn chg_rep(bg: &mut BG, _pk: &PreparedPublicKey<Bls12_381>, 
                    m: &Vec<G1Affine>, s: &Signature<Bls12_381>, r: &BigInt
    ) -> (Signature<Bls12_381>, Vec<G1Affine>) {
        let r_ = Fr::from(BigUint::from_bytes_be(&r.to_bytes_be().1));
        let (sp, mp) = s.change_rep(&mut bg.rng, &r_, &m);
        return (sp, mp);
    }
}