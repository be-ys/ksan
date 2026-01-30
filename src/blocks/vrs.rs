use ark_std::iterable::Iterable;
use num_bigint::{BigInt, RandBigInt, Sign};
use glass_pumpkin::safe_prime;
use rand::thread_rng;

use crate::ksan::hash::hash;

#[derive(Clone, Debug)]
pub struct LogEqElement{
    pub h: BigInt,
    pub z: BigInt,
    pub g: BigInt,
    pub y: BigInt
}

#[derive(Clone, Debug)]
pub struct LogEqProof{
    pub r: BigInt,
    pub s: BigInt,
    pub c: BigInt,
    pub l: BigInt
}

#[derive(Clone, Debug)]
pub struct VRSSignature{
    pub r: BigInt,
    pub z: BigInt,
    pub p: Vec<LogEqProof>
}

#[derive(Clone, Debug)]
pub struct VRSProof{
    pub z: BigInt,
    pub p: Vec<LogEqProof>
}

pub struct VRS;

impl VRS {
    pub fn setup(bits: usize) -> (BigInt, BigInt, BigInt) {
        let p_uint = safe_prime::new(bits).unwrap();
        let q_uint = (&p_uint-1u8) / 2u8;
        let p = BigInt::from_bytes_be(Sign::Plus, &p_uint.to_bytes_be());
        let q = BigInt::from_bytes_be(Sign::Plus, &q_uint.to_bytes_be());
        let mut rng = thread_rng();
        let min = BigInt::from(2);
        let one = BigInt::from(1);
        let max = p.clone() - &min;
        loop {
            let h = rng.gen_bigint_range(&min, &max);
            let g = h.modpow(&min, &p);
            if g != one && g != (&p - &one) && g.modpow(&q, &p) == one {
                return (p, q, g);
            }
        }
    }

    pub fn kgen(_p: &BigInt, q: &BigInt, g: &BigInt) -> (BigInt, BigInt) {
        let mut rng = thread_rng();
        let min = BigInt::from(1);
        let sk = rng.gen_bigint_range(&min, &q);
        let pk = g.modpow(&sk, &q);
        return (sk, pk);
    }

    pub fn sign(p: &BigInt, q: &BigInt, g: &BigInt, sk: &BigInt, ring: &Vec<BigInt>, m: &String) -> VRSSignature {
        let mut rng = thread_rng();
        let min = BigInt::from(1);
        let r = rng.gen_bigint_range(&min, &q);
        let h = Self::vrs_hash(&p, &q, &(m.clone() + r.to_str_radix(36).as_str()));
        let z = h.modpow(&sk, &q);
        let pk = g.modpow(&sk, &q);
        let mut j = 0;
        for i in 0..ring.len() {
            if ring[i] == pk {
                j = i;
                break;
            }
        }
        let p = Self::le_prove(&q, &ring.iter().map(|x| LogEqElement{
            h: h.clone(),
            z: z.clone(),
            g: g.clone(),
            y: x.clone()
        }).collect(), &sk, j);
        return VRSSignature{r: r, z: z, p: p};
    }

    pub fn verify(p: &BigInt, q: &BigInt, g: &BigInt, ring: &Vec<BigInt>, m: &String, s: &VRSSignature) -> bool {
        let h = Self::vrs_hash(&p, &q, &(m.clone() + s.r.to_str_radix(36).as_str()));
        return Self::le_verif(&q, &ring.iter().map(|x| LogEqElement{
            h: h.clone(),
            z: s.z.clone(),
            g: g.clone(),
            y: x.clone()
        }).collect(), &s.p);
    }

    pub fn prove(p: &BigInt, q: &BigInt, g: &BigInt, _ring: &Vec<BigInt>, m: &String, s: &VRSSignature, pk: &BigInt, sk: &BigInt) -> VRSProof {
        let h = Self::vrs_hash(&p, &q, &(m.clone() + s.r.to_str_radix(36).as_str()));
        let z = h.modpow(&sk, &q);
        let p = Self::le_prove(&q, &vec![LogEqElement{
            h: h.clone(),
            z: z.clone(),
            g: g.clone(),
            y: pk.clone()
        }], &sk, 0);
        return VRSProof{z: z, p: p};
    }

    pub fn judge(p: &BigInt, q: &BigInt, g: &BigInt, _ring: &Vec<BigInt>, m: &String, s: &VRSSignature, pk: &BigInt, pr: &VRSProof) -> Result<bool, String> {
        let h = Self::vrs_hash(&p, &q, &(m.clone() + s.r.to_str_radix(36).as_str()));
        let b = Self::le_verif(&q, &vec![LogEqElement{
            h: h.clone(),
            z: pr.z.clone(),
            g: g.clone(),
            y: pk.clone()
        }], &pr.p);
        if !b {
            return Err("Verification failed".to_string());
        }
        if pr.z != s.z {
            return Ok(false);
        }
        return Ok(true);
    }

    fn le_prove(q: &BigInt, d: &Vec<LogEqElement>, x: &BigInt, j: usize) -> Vec<LogEqProof> {
        let mut rng = thread_rng();
        let min = BigInt::from(1);
        let mut pr: Vec<LogEqProof> = Vec::with_capacity(d.len());
        let mut cp = BigInt::from(1);
        let rand = rng.gen_bigint_range(&min, &q);
        for (i, v) in d.iter().enumerate() {
            if j == i {
                let r = v.g.modpow(&rand, &q);
                let s = v.h.modpow(&rand, &q);
                pr.push(LogEqProof{
                    r: r,
                    s: s,
                    c: BigInt::from(0),
                    l: BigInt::from(0)
                });
            } else {
                let c = rng.gen_bigint_range(&min, &q);
                let l = rng.gen_bigint_range(&min, &q);
                let r = (v.g.modpow(&l, &q) * v.y.modpow(&c, &q).modinv(&q).unwrap()) % q;
                let s = (v.h.modpow(&l, &q) * v.z.modpow(&c, &q).modinv(&q).unwrap()) % q;
                pr.push(LogEqProof{
                    r: r,
                    s: s,
                    c: c.clone(),
                    l: l
                });
                cp = (cp * c) % q;
            }
        }
        let c = Self::le_hash(&q, &pr);
        pr[j].c = (c * cp.modinv(&q).unwrap()) % q;
        pr[j].l = rand.clone() + (pr[j].c.clone() * x);
        return pr;
    }

    fn le_verif(q: &BigInt, d: &Vec<LogEqElement>, pr: &Vec<LogEqProof>) -> bool {
        let mut cp = BigInt::from(1);
        for i in 0..pr.len() {
            if  (
                    d[i].g.modpow(&pr[i].l, &q) != 
                    ((pr[i].r.clone() * d[i].y.modpow(&pr[i].c, &q)) % q)
                ) || (
                    d[i].h.modpow(&pr[i].l, &q) != 
                    ((pr[i].s.clone() * d[i].z.modpow(&pr[i].c, &q)) % q)
                ) 
            {
                return false;
            }
            cp = (cp * pr[i].c.clone()) % q;
        }
        let c = Self::le_hash(&q, &pr);
        if cp != c {
            return false;
        }
        return true;
    }

    fn le_hash(_p: &BigInt, pr: &Vec<LogEqProof>) -> BigInt {
        let mut m = String::new();
        for v in pr {
            m.push_str(&v.r.to_string());
            m.push_str(&v.s.to_string());
        }
        let h = hash(&m);
        return h;
    }

    fn vrs_hash(p: &BigInt, q: &BigInt, m: &String) -> BigInt {
        let mut c = 0u64;
        let one = BigInt::from(1);
        loop {
            let m_ = c.to_string() + m.as_str();
            let h = hash(&m_);
            if h.modpow(&q, &p) == one {
                return h;
            }
            c += 1;
        }
    }
}