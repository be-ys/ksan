#[cfg(test)]
mod tests {
    use crate::blocks::{mercurial::Mercurial, pke::PKE};
    use crate::blocks::sig::SIG;
    use crate::blocks::chash::CHash;
    use crate::blocks::eqs::EQS;
    use crate::blocks::bls::BLS;
    use crate::blocks::vrs::VRS;
    use rand::{Rng, thread_rng};
    use num_bigint::{BigInt, BigUint};
    use ark_bls12_381::Fr;

    #[test]
    fn test_pke() {
        let (sk, pk) = PKE::k_gen(2056);

        //Generate a random number to encrypt
        let mut rng = thread_rng();
        let bytes: [u8; 8] = rng.gen();
        let bytes1: [u8; 8] = rng.gen();
        let bytes2: [u8; 8] = rng.gen();
        let bytes3: [u8; 8] = rng.gen();
        let mut bytes_f = bytes.to_vec();
        bytes_f.extend_from_slice(&bytes1);
        bytes_f.extend_from_slice(&bytes2);
        bytes_f.extend_from_slice(&bytes3);
        let r = BigInt::from(BigUint::from_bytes_be(&bytes_f.as_slice()));

        //Check that encryption works
        let c = PKE::encrypt(&pk, &r);
        let m = PKE::decrypt(&sk, &c);
        assert_eq!(m, r, "Decrypted failed");

        //Check that homomorphic scalar multiplication works
        let cp = PKE::multiply(&pk, &c, &BigInt::from(2));
        let mp = PKE::decrypt(&sk, &cp);
        assert_eq!(mp, r.clone() * 2, "Decrypted of multiplied ciphertext failed");
    }

    #[test]
    fn test_sig() {
        let (sk, pk) = SIG::k_gen();

        let m = "message 1234";
        let s: k256::schnorr::Signature = SIG::sign(&sk, &m);

        //Check that the verify algorithm returns true for a valid signature
        let b = SIG::verify(&pk, &m, &s);
        assert!(b, "Valid signature verification failed");

        //Check that the verify algorithm returns false for an invalid signature
        let b = SIG::verify(&pk, "other message", &s);
        assert!(!b, "Invalid signature verification failed");
    }

    #[test]
    fn test_chash() {
        let (p, q, g) = CHash::setup(2048);
        let (sk, pk) = CHash::k_gen(&p, &q, &g);
        
        let m = BigInt::from(10u32);
        let (h, r) = CHash::hash(&p, &q, &g, &pk, &m);
        
        //Check that the check algorithm returns true for a valid hash
        let b = CHash::check(&p, &q, &g, &pk, &m, &r, &h);
        assert!(b, "Valid hash check failed");

        //Check that the check algorithm returns false for an invalid hash
        let b = CHash::check(&p, &q, &g, &pk, &BigInt::from(20u32), &r, &h);
        assert!(!b, "Invalid hash check failed");

        //Check that the check algorithm returns true for a valid adapted hash
        let mp = BigInt::from(55u32);
        let rp = CHash::adapt(&p, &q, &g, &sk, &m, &r, &mp);
        let b = CHash::check(&p, &q, &g, &pk, &mp, &rp, &h);
        assert!(b, "Hash check after Adapt failed");
    }

    #[test]
    fn test_eqs() {
        let mut bg = EQS::setup(3, &"k-SAN test".to_string());
        let (sk, pk) = EQS::k_gen(&mut bg);

        let m = vec![bg.p1.clone(), bg.p1.clone(), bg.p1.clone()];
        let s = EQS::sign(&mut bg, &sk, &m);

        //Check that the verify algorithm returns true for a valid signature
        let b = EQS::verify(&mut bg, &pk, &m, &s);
        assert!(b, "Valid signature verification failed");

        //Check that the verify algorithm returns true for a valid signature after changing its representation
        let r = BigInt::from(50);
        let (sp, mp) = EQS::chg_rep(&mut bg, &pk, &m, &s, &r);
        let b = EQS::verify(&mut bg, &pk, &mp, &sp);
        assert!(b, "Valid signature verification after ChgRep failed");

        //Check that the verify algorithm returns false for an invalid signature
        let b = EQS::verify(&mut bg, &pk, &mp, &s);
        assert!(!b, "Invalid signature verification failed");
    }

    #[test]
    fn test_bls() {
        let mut bg= EQS::setup(3, &"k-SAN test".to_string());
        let (_sk1, sk2, pk1, pk2) = BLS::k_gen(&mut bg);

        let m = "message 1234".to_string();
        let s = BLS::sign(&mut bg, &sk2, &m);

        //Check that the verify algorithm returns true for a valid signature
        let b = BLS::verify(&mut bg, &pk1, &pk2, &m, &s);
        assert!(b, "Valid signature verification failed");

        //Check that the verify algorithm returns false for an invalid signature
        let b = BLS::verify(&mut bg, &pk1, &pk2, &"othermessage".to_string(), &s);
        assert!(!b, "Invalid signature verification failed");
        
        //Check that the verify algorithm returns true for a valid signature after randomization
        let r1 = BigInt::from(50);
        let r2 = BigInt::from(100);
        let r3 = r1.clone() * r2.clone();
        let pk1r = BLS::_randomize_g1(&pk1, &r1);
        let pk2r = BLS::_randomize_g1(&pk2, &r3);
        let sr = BLS::randomize_g2(&s, &r2);
        let b = BLS::verify(&mut bg, &pk1r, &pk2r, &m, &sr);
        assert!(b, "Verification after randomization failed");

        //Check that the verify algorithm returns true for a new valid signature generated after keys randomization
        let ns = BLS::sign(&mut bg, &Fr::from(BigUint::from_bytes_be(&(BigInt::from(sk2.to_string().parse::<BigInt>().unwrap()) * r2.clone()).to_bytes_be().1)), &m);
        let b = BLS::verify(&mut bg, &pk1r, &pk2r, &m, &ns);
        assert!(b, "New signature verification after keys randomization failed");
    }

    #[test]
    fn test_vrs() {
        let (p, q, g) = VRS::setup(2048);
        let (_sk1, pk1) = VRS::kgen(&p, &q, &g);
        let (sk2, pk2) = VRS::kgen(&p, &q, &g);
        let (sk3, pk3) = VRS::kgen(&p, &q, &g);
        let ring = vec![pk1.clone(), pk2.clone(), pk3.clone()];

        let m = "message 1234".to_string();
        let s = VRS::sign(&p, &q, &g, &sk3, &ring, &m);

        //Check that the verify algorithm returns true for a valid signature
        let b = VRS::verify(&p, &q, &g, &ring, &m, &s);
        assert!(b, "Valid signature verification failed");

        //Check that the verify algorithm returns false for an invalid signature
        let b = VRS::verify(&p, &q, &g, &ring, &"other message".to_string(), &s);
        assert!(!b, "Invalid signature verification failed");

        //Check that the judge algorithm returns true for a proof generated by the original signer of the message
        let pr = VRS::prove(&p, &q, &g, &ring, &m, &s, &pk3, &sk3);
        let b = VRS::judge(&p, &q, &g, &ring, &m, &s, &pk3, &pr).unwrap();
        assert!(b, "Judge the original signer failed");

        //Check that the judge algorithm returns false for a proof generated by a signer other than the original
        //signer of the message
        let pr = VRS::prove(&p, &q, &g, &ring, &m, &s, &pk2, &sk2);
        let b = VRS::judge(&p, &q, &g, &ring, &m, &s, &pk2, &pr).unwrap();
        assert!(!b, "Judge not the original signer failed");
    }

    #[test]
    fn test_mercurial() {
        let mut bg = Mercurial::setup(3, &"k-SAN test".to_string());
        let (mut sk, pk) = Mercurial::k_gen(&mut bg);

        let mut m = vec![bg.pp.p1.clone(), bg.pp.p1.clone(), bg.pp.p1.clone()];
        let s = Mercurial::sign(&mut bg, &mut sk, &m);
        let mut s1 = s.clone();

        //Check that the verify algorithm returns true for a valid signature
        let b = Mercurial::verify(&mut bg, &pk, &m, &s);
        assert!(b, "Valid signature verification failed");

        //Check that the verify algorithm returns true for a valid signature after changing its representation
        let r = BigInt::from(50);
        let (sp, mp) = Mercurial::chg_rep(&mut bg, &pk, &mut m, &mut s1, &r);
        let b = Mercurial::verify(&mut bg, &pk, &mp, &sp);
        assert!(b, "Valid signature verification after ChgRep failed");

        //Check that the verify algorithm returns false for an invalid signature
        let b = Mercurial::verify(&mut bg, &pk, &mp, &s);
        assert!(!b, "Invalid signature verification failed");
    }
}