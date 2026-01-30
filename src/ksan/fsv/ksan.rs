use kzen_paillier::RawCiphertext;
use num_bigint::BigInt;
use curv::arithmetic::traits::Converter;

use crate::ksan::fsv::params::*;
use crate::blocks::pke::*;
use crate::blocks::sig::*;
use crate::blocks::chash::*;
use crate::blocks::vrs::*;
use crate::ksan::hash::hash;
use crate::ksan::hash::encode;

pub struct KSan;

impl KSan {
    pub fn setup(secp: &SecParams) -> Result<PublicParams, String> {
        let min = BigInt::from(2).pow(256);
        let mut p: BigInt;
        let mut q: BigInt;
        let mut g: BigInt;
        loop {
            (p, q, g) = CHash::setup(secp.bits_chash_vrs);
            if q > min {
                break;
            }
        }
        let pp = PublicParams {
            secp: secp.clone(),
            p: p,
            q: q,
            g: g
        };
        return Ok(pp);
    }

    pub fn kgen_s(_pp: &PublicParams) -> Result<(SignerSecretKey, SignerPublicKey), String> {
        let (sk, pk) = SIG::k_gen();
        let sk_s = SignerSecretKey {
            sk: sk
        };
        let pk_s = SignerPublicKey {
            pk: pk
        };
        return Ok((sk_s, pk_s));
    }

    pub fn kgen_z(pp: &PublicParams) -> Result<(SanitizerSecretKey, SanitizerPublicKey), String> {
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
            pp: &PublicParams, sk_s: &SignerSecretKey, pk_s: &SignerPublicKey,
            san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, adm: &Vec<Vec<bool>>
        ) -> Result<Signature<'d>, String> {
        let k = san_pks.len();
        let n = m.len();
        let mut hashes: Vec<CHashPubValues> = Vec::with_capacity(n);
        let zero = BigInt::from(0);
        let mut secrets: Vec<Vec<RawCiphertext<'d>>> = vec![Vec::with_capacity(n); k];
        let mut proofs: Vec<Proof> = Vec::with_capacity(n);
        let mut pub_adm: Vec<bool> = Vec::with_capacity(n);
        for j in 0..n {
            let (skch, pkch) = CHash::k_gen(&pp.p, &pp.q, &pp.g);
            let mj = j.to_string() + m[j].as_str();
            let (h, r) = CHash::hash(&pp.p, &pp.q, &pp.g, &pkch, 
                &hash(&mj));
            hashes.push(CHashPubValues { h: h, r: r, pkch: pkch });
            let mut pa = false;
            for i in 0..k {
                if adm[i][j] {
                    secrets[i].push(PKE::encrypt(&san_pks[i].pke, &skch));
                    pa = true;
                } else {
                    secrets[i].push(PKE::encrypt(&san_pks[i].pke, &zero));
                }
            }
            pub_adm.push(pa);
        }
        let ms = Self::generate_ms(&hashes, &secrets, &pub_adm, &pk_s, &san_pks);
        let s = SIG::sign(&sk_s.sk, &ms);
        for j in 0..n {
            let mut t = "".to_string();
            t = t + j.to_string().as_str() + m[j].as_str();
            t = t + encode(&s.to_bytes()).as_str();
            proofs.push(Proof {ps: Some(SIG::sign(&sk_s.sk, &t)), pz: None});
        }
        let sig = Signature {
            s: s,
            hashes: hashes,
            secrets: secrets,
            pub_adm: pub_adm,
            n: n,
            proofs: proofs
        };
        return Ok(sig);
    }

    pub fn sanitize<'d>(
        pp: &PublicParams, sk_z: &SanitizerSecretKey, _pk_s: &SignerPublicKey, pk_z: &SanitizerPublicKey,
        san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, modif: &Vec<Mod>, sig: &Signature<'d>
    ) -> Result<Signature<'d>, String> {
        let k = san_pks.len();
        let n = sig.n;
        let zero = BigInt::from(0);
        let mut hashes_p: Vec<CHashPubValues> = Vec::with_capacity(n);
        let mut proofs_p: Vec<Proof> = Vec::with_capacity(n);
        let mut mp: Vec<String> = Vec::with_capacity(n);
        let ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        for j in 0..n {
            mp.push(m[j].clone());
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
        for j in 0..n {
            if mp[j] != m[j] {
                let skch = PKE::decrypt(&sk_z.ske, &sig.secrets[ip][j]);
                if skch == zero {
                    return Err("The modification is not admissible for the chosen sanitizer".to_string());
                }
                let mj = j.to_string() + m[j].as_str();
                let mpj = j.to_string() + mp[j].as_str();
                let rp = CHash::adapt(&pp.p, &pp.q, &pp.g, &skch, 
                    &hash(&mj), &sig.hashes[j].r, &hash(&mpj));
                let mut t = "".to_string();
                t = t + j.to_string().as_str() + mp[j].as_str();
                t = t + encode(&sig.s.to_bytes()).as_str();
                let pz = VRS::sign(&pp.p, &pp.q, &pp.g, &sk_z.skp, &ring, &t);
                proofs_p.push(Proof { ps: None, pz: Some(pz) });
                hashes_p.push(CHashPubValues { h: sig.hashes[j].h.clone(), r: rp.clone(), pkch: sig.hashes[j].pkch.clone() });
            } else {
                proofs_p.push(sig.proofs[j].clone());
                hashes_p.push(CHashPubValues { h: sig.hashes[j].h.clone(), r: sig.hashes[j].r.clone(), 
                    pkch: sig.hashes[j].pkch.clone() });
            }
        }
        let sigp = Signature {
            s: sig.s,
            hashes: hashes_p,
            secrets: sig.secrets.clone(),
            pub_adm: sig.pub_adm.clone(),
            n: sig.n,
            proofs: proofs_p
        };
        return Ok(sigp);
    }

    pub fn verify(
        pp: &PublicParams, pk_s: &SignerPublicKey,
        san_pks: &Vec<SanitizerPublicKey>, m: &Vec<String>, sig: &Signature
    ) -> Result<bool, String> {
        let n = m.len();
        let ms = Self::generate_ms(&sig.hashes, &sig.secrets, &sig.pub_adm, &pk_s, &san_pks);
        if !SIG::verify(&pk_s.pk, &ms, &sig.s) {
            return Ok(false);
        }
        let ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        for j in 0..n {
            let mj = j.to_string() + m[j].as_str();
            if !CHash::check(&pp.p, &pp.q, &pp.g, &sig.hashes[j].pkch, &hash(&mj), 
                &sig.hashes[j].r, &sig.hashes[j].h) {
                return Ok(false);
            }
            let mut t = "".to_string();
            t = t + j.to_string().as_str() + m[j].as_str();
            t = t + encode(&sig.s.to_bytes()).as_str();
            if sig.pub_adm[j] {
                if sig.proofs[j].pz.is_none() || 
                    !VRS::verify(&pp.p, &pp.q, &pp.g, &ring, &t, sig.proofs[j].pz.as_ref().unwrap()) {
                    return Ok(false);
                }
            } else {
                if sig.proofs[j].ps.is_none() || 
                    !SIG::verify(&pk_s.pk, &t, sig.proofs[j].ps.as_ref().unwrap()) {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }

    pub fn judge(
        _pp: &PublicParams, _pk_s: &SignerPublicKey, _san_pks: &Vec<SanitizerPublicKey>,
        _m: &Vec<String>, sig: &Signature, _p: Option<&Proof>, j: Option<&usize>
    ) -> Result<char, String> {
        if j == None {
            for pa in sig.pub_adm.iter() {
                if *pa {
                    return Ok('Z');
                }
            }
            return Ok('S');
        } else {
            if sig.pub_adm[*j.unwrap()] {
                return Ok('Z');
            }
            return Ok('S');
        }
    }

    fn generate_ms<'d>(
        hashes: &Vec<CHashPubValues>, secrets: &Vec<Vec<RawCiphertext<'d>>>, pub_adm: &Vec<bool>,
        pk_s: &SignerPublicKey, san_pks: &Vec<SanitizerPublicKey>
    ) -> String {
        let k = san_pks.len();
        let n = hashes.len();
        let mut ms = String::new();
        for j in 0..n {
            ms.push_str(hashes[j].h.to_str_radix(36).as_str());
            ms.push_str(hashes[j].pkch.to_str_radix(36).as_str());
            ms.push_str(if pub_adm[j] { "1" } else { "0" });
            for i in 0..k {
                ms.push_str(san_pks[i].pkp.to_str_radix(36).as_str());
                ms.push_str(san_pks[i].pke.n.to_str_radix(36).as_str());
                ms.push_str(san_pks[i].pke.nn.to_str_radix(36).as_str());
                ms.push_str(secrets[i][j].0.as_ref().to_str_radix(36).as_str());
            }
        }
        ms.push_str(encode(&pk_s.pk).as_str());
        ms.push_str(n.to_string().as_str());
        return ms;
    }
}