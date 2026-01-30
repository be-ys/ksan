use num_bigint::{BigInt, RandBigInt, Sign};
use glass_pumpkin::safe_prime;
use rand::thread_rng;

pub struct CHash;

impl CHash {
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

    pub fn k_gen(p: &BigInt, q: &BigInt, g: &BigInt) -> (BigInt, BigInt) {
        let mut rng = thread_rng();
        let min = BigInt::from(1);
        let sk = rng.gen_bigint_range(&min, &q);
        let pk = g.modpow(&sk, &p);
        return (sk, pk);
    }

    pub fn hash(p: &BigInt, q: &BigInt, g: &BigInt, pk: &BigInt, m: &BigInt) -> (BigInt, BigInt) {
        let mut rng = thread_rng();
        let min = BigInt::from(1);
        let r = rng.gen_bigint_range(&min, &q);
        let h = (g.modpow( &m, &p) * pk.modpow( &r, &p)) % p;
        return (h, r);
    }

    pub fn check(p: &BigInt, _q: &BigInt, g: &BigInt, pk: &BigInt, m: &BigInt, r: &BigInt, h: &BigInt) -> bool {
        let hp = (g.modpow( &m, &p) * pk.modpow( &r, &p)) % p;
        return hp == *h;
    }

    pub fn adapt(_p: &BigInt, q: &BigInt, _g: &BigInt, sk: &BigInt, m: &BigInt, r: &BigInt, mp: &BigInt) -> BigInt {
        let lhs = (((m - mp + q) % q) + ((sk * r) % q)) % q;
        let sk_inv = &sk.modinv(&q).unwrap();
        let rp = (lhs * sk_inv) % q;
        return rp;
    }
}