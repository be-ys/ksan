use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use kzen_paillier::RawCiphertext;
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::UniformRand;
use num_bigint::{BigInt, BigUint};
use curv::arithmetic::traits::Converter;

use crate::ksan::iut::params::*;
use crate::blocks::pke::*;
use crate::blocks::eqs::*;
use crate::blocks::vrs::*;
use crate::blocks::bls::*;
use crate::ksan::hash::encode;

pub struct KSan;

impl KSan {
    pub fn setup(secp: &SecParams) -> Result<PublicParams, String> {
        let bg = EQS::setup(secp.n + 1, &secp.dst);
        let min = BigInt::from(2).pow(256);
        let mut p: BigInt;
        let mut q: BigInt;
        let mut g: BigInt;
        loop {
            (p, q, g) = VRS::setup(secp.bits_vrs);
            if p > min {
                break;
            }
        }
        let pp = PublicParams {
            secp: secp.clone(),
            bg: bg,
            p: p.clone(),
            q: q.clone(),
            g: g.clone()
        };
        return Ok(pp);
    }

    pub fn kgen_s(pp: &mut PublicParams) -> Result<(SignerSecretKey, SignerPublicKey), String> {
        let (sk_eqs, pk_eqs) = EQS::k_gen(&mut pp.bg);
        let (skp, pkp) = VRS::kgen(&pp.p, &pp.q, &pp.g);
        let sk_s = SignerSecretKey {
            sk_eqs: sk_eqs,
            skp: skp
        };
        let pk_s = SignerPublicKey {
            pk_eqs: pk_eqs,
            pkp: pkp
        };
        return Ok((sk_s, pk_s));
    }

    pub fn kgen_z(pp: &mut PublicParams) -> Result<(SanitizerSecretKey, SanitizerPublicKey), String> {
        //let (pke, ske) = PKE::k_gen(&pp.kp);
        let (ske, pke) = PKE::k_gen(pp.secp.bits_pke);
        let (skp, pkp) = VRS::kgen(&pp.p, &pp.q, &pp.g);
        let sk_z = SanitizerSecretKey {
            ske: ske,
            skp: skp
        };
        let pk_z = SanitizerPublicKey {
            pke: pke,
            pkp: pkp
        };
        return Ok((sk_z, pk_z));
    }

    pub fn sign<'d>(
            pp: &mut PublicParams, sk_s: &SignerSecretKey, pk_s: &SignerPublicKey,
            san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, adm: &Vec<Vec<bool>>
        ) -> Result<Signature<'d>, String> {
        let k = san_pks.len();
        let n = pp.bg.n as usize;
        if m.len() != n - 1 {
            return Err("m must have n-1 elements".to_string());
        }
        let zero = BigInt::from(0);
        let mut secrets: Vec<Vec<RawCiphertext<'d>>> = vec![Vec::with_capacity(n); k];
        let mut m_ = m.clone();
        m_.push(Self::pkz_to_string(&san_pks));
        let mut adm_ = adm.clone();
        for i in 0..k {
            adm_[i].push(false);
        }
        let mut sk1_bls: Vec<Fr> = Vec::with_capacity(n);
        let mut sk2_bls: Vec<Fr> = Vec::with_capacity(n);
        let mut pk1_bls: Vec<G1Projective> = Vec::with_capacity(n);
        let mut pk2_bls: Vec<G1Projective> = Vec::with_capacity(n);
        let mut s_bls: Vec<G2Projective> = Vec::with_capacity(n);
        for j in 0..n {
            let (sk1, sk2, pk1, pk2) = BLS::k_gen(&mut pp.bg);
            sk1_bls.push(sk1);
            sk2_bls.push(sk2);
            pk1_bls.push(pk1);
            pk2_bls.push(pk2);
            let mj = j.to_string() + m_[j].as_str();
            let s = BLS::sign(&mut pp.bg, &sk2, &mj);
            s_bls.push(s);
            for i in 0..k {
                if adm_[i][j] {
                    secrets[i].push(PKE::encrypt(&san_pks[i].pke, &BigInt::from(sk2.to_string().parse::<BigInt>().unwrap())));
                } else {
                    secrets[i].push(PKE::encrypt(&san_pks[i].pke, &zero));
                }
            }
        }
        let s_x_eqs = EQS::sign(&mut pp.bg, &sk_s.sk_eqs, 
            &pk1_bls.iter().map(|x| x.into_affine()).collect());
        let s_y_eqs = EQS::sign(&mut pp.bg, &sk_s.sk_eqs, 
            &pk2_bls.iter().map(|x| x.into_affine()).collect());
        let s_ss = SignatureSS {
            s_x_eqs: s_x_eqs,
            s_y_eqs: s_y_eqs,
            s_bls: s_bls,
            pk1_bls: pk1_bls,
            pk2_bls: pk2_bls,
            secrets: secrets
        };
        let t = Self::generate_t(&pk_s, &m_, &s_ss);
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        let s_vrs = VRS::sign(&pp.p, &pp.q, &pp.g, &sk_s.skp, &ring, &t);
        let sig = Signature {
            s_ss: s_ss,
            s_vrs: s_vrs
        };
        return Ok(sig);
    }

    pub fn sanitize<'d>(
        pp: &mut PublicParams, sk_z: &SanitizerSecretKey, pk_s: &SignerPublicKey, pk_z: &SanitizerPublicKey,
        san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, modif: &Vec<Mod>, sig: &Signature
    ) -> Result<Signature<'d>, String> {
        let k = san_pks.len();
        let n = pp.bg.n as usize;
        let zero = BigInt::from(0);
        let mut m_ = m.clone();
        m_.push(Self::pkz_to_string(&san_pks));
        let mut mp: Vec<String> = Vec::with_capacity(n);
        for j in 0..n {
            mp.push(m_[j].clone());
        }
        for modif in modif.iter() {
            mp[modif.i] = modif.m.clone();
        }
        let mut ip: usize = 0;
        for i in 0..k {
            if san_pks[i].pkp == pk_z.pkp {
                ip = i;
                break;
            }
        }
        let r = Fr::rand(&mut pp.bg.rng).to_string().parse::<BigInt>().unwrap();
        let s = Fr::rand(&mut pp.bg.rng).to_string().parse::<BigInt>().unwrap();
        let (s_x_eqs, pk1_bls) = EQS::chg_rep(
            &mut pp.bg, &pk_s.pk_eqs, &sig.s_ss.pk1_bls.iter().map(|x| x.into_affine()).collect(), 
            &sig.s_ss.s_x_eqs, &r
        );
        let pk1_bls_p = pk1_bls.iter().map(|x| x.into_group()).collect();
        let (s_y_eqs, pk2_bls) = EQS::chg_rep(
                    &mut pp.bg, &pk_s.pk_eqs, &sig.s_ss.pk2_bls.iter().map(|y| y.into_affine()).collect(), 
                    &sig.s_ss.s_y_eqs, &(r * s.clone())
                );
        let pk2_bls_p = pk2_bls.iter().map(|y| y.into_group()).collect();
        let mut s_bls_v: Vec<G2Projective> = Vec::with_capacity(n);
        let mut secrets: Vec<Vec<RawCiphertext<'d>>> = vec![Vec::with_capacity(n); k];
        for j in 0..n {
            if mp[j] != m_[j] {
                let y = PKE::decrypt(&sk_z.ske, &sig.s_ss.secrets[ip][j]);
                if y == zero {
                    return Err("The modification is not admissible for the chosen sanitizer".to_string());
                }
                let mpj = j.to_string() + mp[j].as_str();
                s_bls_v.push(BLS::sign(&mut pp.bg, &Fr::from(BigUint::from_bytes_be(&(y * s.clone()).to_bytes_be().1)), &mpj));
            } else {
                s_bls_v.push(BLS::randomize_g2(&sig.s_ss.s_bls[j], &s));
            }
            for i in 0..k {
                secrets[i].push(PKE::multiply(&san_pks[i].pke, &sig.s_ss.secrets[i][j], &s));
            }
        }
        let s_ss = SignatureSS {
            s_x_eqs: s_x_eqs,
            s_y_eqs: s_y_eqs,
            s_bls: s_bls_v,
            pk1_bls: pk1_bls_p,
            pk2_bls: pk2_bls_p,
            secrets: secrets
        };
        let t = Self::generate_t(&pk_s, &mp, &s_ss);
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        let s_vrs = VRS::sign(&pp.p, &pp.q, &pp.g, &sk_z.skp, &ring, &t);
        let sig = Signature {
            s_ss: s_ss,
            s_vrs: s_vrs
        };
        return Ok(sig);
    }

    pub fn verify(
        pp: &mut PublicParams, pk_s: &SignerPublicKey,
        san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, sig: &Signature
    ) -> Result<bool, String> {
        let n = pp.bg.n as usize;
        if m.len() != n - 1 {
            return Ok(false);
        }
        let mut m_ = m.clone();
        m_.push(Self::pkz_to_string(&san_pks));
        let t = Self::generate_t(&pk_s, &m_, &sig.s_ss);
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        if !VRS::verify(&pp.p, &pp.q, &pp.g, &ring, &t, &sig.s_vrs) {
            return Ok(false);
        }
        if !EQS::verify(
            &mut pp.bg, &pk_s.pk_eqs, &sig.s_ss.pk1_bls.iter().map(|x| x.into_affine()).collect(), 
            &sig.s_ss.s_x_eqs
        ) {
            return Ok(false);
        }
        if !EQS::verify(
            &mut pp.bg, &pk_s.pk_eqs, &sig.s_ss.pk2_bls.iter().map(|y| y.into_affine()).collect(), 
            &sig.s_ss.s_y_eqs
        ) {
            return Ok(false);
        }
        for j in 0..n {
            let mj = j.to_string() + m_[j].as_str();
            if !BLS::verify(&mut pp.bg, &sig.s_ss.pk1_bls[j], &sig.s_ss.pk2_bls[j], &mj, &sig.s_ss.s_bls[j]) {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    pub fn prove(
        pp: &mut PublicParams, sk_s: &SignerSecretKey, pk_s: &SignerPublicKey,
        san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, sig: &Signature, _j: Option<&usize>
    ) -> Result<Proof, String> {
        let mut m_ = m.clone();
        m_.push(Self::pkz_to_string(&san_pks));
        let t = Self::generate_t(&pk_s, &m_, &sig.s_ss);
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        let pr = VRS::prove(&pp.p, &pp.q, &pp.g, &ring, &t, &sig.s_vrs, &pk_s.pkp, &sk_s.skp);
        return Ok(Proof {
            pr: pr
        });
    }

    pub fn judge(
        pp: &mut PublicParams, pk_s: &SignerPublicKey, san_pks: &Vec<SanitizerPublicKey>,
        m: &Vec<String>, sig: &Signature, p: &Proof, _j: Option<&usize>
    ) -> Result<char, String> {
        let mut m_ = m.clone();
        m_.push(Self::pkz_to_string(&san_pks));
        let t = Self::generate_t(&pk_s, &m_, &sig.s_ss);
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        let b = VRS::judge(&pp.p, &pp.q, &pp.g, &ring, &t, &sig.s_vrs, &pk_s.pkp, &p.pr);
        if b.is_err() {
            return Ok('E');
        }
        let b = b.unwrap();
        if b {
            return Ok('S');
        }
        return Ok('Z');
    }

    fn generate_t(pk_s: &SignerPublicKey, m: &Vec<String>, s_ss: &SignatureSS) -> String {
        let mut t = String::new();
        t.push_str(pk_s.pkp.to_str_radix(36).as_str());
        for j in 0..m.len() {
            t.push_str(m[j].as_str());
        }
        let mut bytes = Vec::new();
        for p in pk_s.pk_eqs.0.iter() {
            p.serialize_compressed(&mut bytes).unwrap();
        }
        s_ss.s_x_eqs.Z.serialize_compressed(&mut bytes).unwrap();
        s_ss.s_x_eqs.Y.serialize_compressed(&mut bytes).unwrap();
        s_ss.s_x_eqs.Y_tilde.serialize_compressed(&mut bytes).unwrap();
        s_ss.s_y_eqs.Z.serialize_compressed(&mut bytes).unwrap();
        s_ss.s_y_eqs.Y.serialize_compressed(&mut bytes).unwrap();
        s_ss.s_y_eqs.Y_tilde.serialize_compressed(&mut bytes).unwrap();
        for j in 0..s_ss.pk1_bls.len() {
            s_ss.pk1_bls[j].serialize_compressed(&mut bytes).unwrap();
            s_ss.pk2_bls[j].serialize_compressed(&mut bytes).unwrap();
            s_ss.s_bls[j].serialize_compressed(&mut bytes).unwrap();
            for i in 0..s_ss.secrets.len() {
                t.push_str(s_ss.secrets[i][j].0.as_ref().to_str_radix(36).as_str());
            }
        }
        t.push_str(encode(bytes.as_slice()).as_str());
        return t;
    }

    fn pkz_to_string(san_pks: &Vec<SanitizerPublicKey>) -> String {
        let mut s: String = String::new();
        for p in san_pks.iter() {
            s.push_str(p.pkp.to_str_radix(36).as_str());
            s.push_str(p.pke.n.to_str_radix(36).as_str());
            s.push_str(p.pke.nn.to_str_radix(36).as_str());
        }
        return s;
    }
}