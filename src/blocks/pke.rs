use curv::arithmetic::Converter;
use kzen_paillier::*;
use num_bigint::BigInt as nBigInt;

pub struct PKE;

impl PKE {
    pub fn k_gen(bits: usize) -> (DecryptionKey, EncryptionKey) {
        let (pk, sk) = Paillier::keypair_safe_primes_with_modulus_size(bits).keys();
        return (sk, pk);
    }

    pub fn encrypt<'m, 'd>(pk: &EncryptionKey, m: &nBigInt) -> RawCiphertext<'d> {
        let m_ = BigInt::from_bytes(m.to_bytes_be().1.as_slice());
        let c= Paillier::encrypt(pk, RawPlaintext::from(m_));
        return c;
    }

    pub fn decrypt(sk: &DecryptionKey, c: &RawCiphertext) -> nBigInt {
        let m = Paillier::decrypt(sk, c);
        return nBigInt::from_bytes_be(num_bigint::Sign::Plus, m.0.into_owned().to_bytes().as_slice());
    }

    pub fn multiply<'c, 'm, 'd>(pk: &EncryptionKey, c: &RawCiphertext, s: &nBigInt) -> RawCiphertext<'d> {
        let s_ = BigInt::from_bytes(s.to_bytes_be().1.as_slice());
        let cp = Paillier::mul(pk, c.clone(), RawPlaintext::from(s_));
        return cp;
    }
}