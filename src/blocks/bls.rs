use ark_bls12_381::{Fr, G1Projective, G2Projective, Bls12_381, g2::Config as G2Config};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::{MapToCurveBasedHasher}, 
        HashToCurve
    }, 
    pairing::Pairing,
    AffineRepr,
    short_weierstrass::Projective,
    CurveGroup
};
use ark_ff::{UniformRand, field_hashers::DefaultFieldHasher};
use num_bigint::{BigUint, BigInt};
use super::eqs::BG;
use sha2::Sha256;

pub struct BLS;

impl BLS {
    pub fn k_gen(bg: &mut BG) -> (Fr, Fr, G1Projective, G1Projective) {
        let sk1 = Fr::rand(&mut bg.rng);
        let sk2 = Fr::rand(&mut bg.rng);
        let pk1 = bg.p1 * sk1;
        let pk2 = pk1 * sk2;
        return (sk1, sk2, pk1, pk2);
    }

    pub fn sign(bg: &mut BG, sk2: &Fr, m: &String) -> G2Projective {
        let h = Self::hash_g2(bg, &m);
        return h * sk2;
    }

    pub fn verify(bg: &mut BG, pk1: &G1Projective, pk2: &G1Projective, m: &String, s: &G2Projective) -> bool {
        if pk2.into_affine() == bg.p1 {
            return false;
        }
        let h = Self::hash_g2(bg, &m);
        return Bls12_381::pairing(pk1, s) == Bls12_381::pairing(pk2, h);
    }

    pub fn _randomize_g1(s: &G1Projective, r: &BigInt) -> G1Projective {
        let r_ = Fr::from(BigUint::from_bytes_be(&r.to_bytes_be().1));
        return *s * r_;
    }

    pub fn randomize_g2(s: &G2Projective, r: &BigInt) -> G2Projective {
        let r_ = Fr::from(BigUint::from_bytes_be(&r.to_bytes_be().1));
        return *s * r_;
    }

    fn hash_g2(bg: &mut BG, m: &String) -> G2Projective {
        let mtc = MapToCurveBasedHasher::<
            Projective<G2Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G2Config>
        >::new(&bg.dst.as_bytes())
        .unwrap();
        let h = mtc.hash(m.as_bytes());
        return h.unwrap().mul_by_cofactor_to_group();
    }
}