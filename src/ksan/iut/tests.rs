#[cfg(test)]
mod tests {
    use crate::blocks::bls::BLS;
    use crate::blocks::eqs::EQS;
    use crate::ksan::iut::ksan::KSan;
    use crate::ksan::iut::params::{SecParams, Mod, Proof};
    use ark_ec::CurveGroup;
    use num_bigint::BigInt;

    #[test]
    fn test_iut_ksan() {
        let secp = SecParams { bits_vrs: 2048, bits_pke: 2056, n: 3, dst: "k-SAN test".to_string() };
        let mut pp = KSan::setup(&secp).unwrap();
        let (sk_s, pk_s) = KSan::kgen_s(&mut pp).unwrap();
        let (sk_z1, pk_z1) = KSan::kgen_z(&mut pp).unwrap();
        let (sk_z2, pk_z2) = KSan::kgen_z(&mut pp).unwrap();
        let (_sk_z3, pk_z3) = KSan::kgen_z(&mut pp).unwrap();

        let mut m = vec!["not_adm".to_string(), "adm1".to_string(), "adm2+3".to_string()];
        let mut adm = vec![vec![false; 3]; 3];
        adm[0][1] = true;
        adm[1][2] = true;
        adm[2][2] = true;
        let san_pks = vec![pk_z1.clone(), pk_z2.clone(), pk_z3.clone()];
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        ring.push(pk_s.pkp.clone());
        let sig = KSan::sign(&mut pp, &sk_s, &pk_s, &san_pks, &m, &adm).unwrap();

        //Test verification of a non-sanitized signature
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig).unwrap();
        assert!(b, "Verification should succeed for non-sanitized signatures");

        //Test judge on a non-sanitized signature
        let pr: Proof = KSan::prove(&mut pp, &sk_s, &pk_s, &san_pks, &m, &sig, None).unwrap();
        let d = KSan::judge(&mut pp, &pk_s, &san_pks, &m, &sig, &pr, None).unwrap();
        assert_eq!(d, 'S', "Judge should return 'S' for a non-sanitized signature");

        //Test verification of a partially sanitized signature
        let modif = vec![Mod { i: 1, m: "modadm1".to_string() }];
        let sigp1 = KSan::sanitize(&mut pp, &sk_z1, &pk_s, &pk_z1, 
            &san_pks, &m, &modif, &sig).unwrap();
        m[1] = "modadm1".to_string();
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sigp1).unwrap();
        assert!(b, "Verification should succeed for partially sanitized signatures");

        //Test verification of a fully sanitized signature
        let modif = vec![Mod { i: 2, m: "modadm2+3".to_string() }];
        let sigp2 = KSan::sanitize(&mut pp, &sk_z2, &pk_s, &pk_z2, 
            &san_pks, &m, &modif, &sigp1).unwrap();
        m[2] = "modadm2+3".to_string();
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sigp2).unwrap();
        assert!(b, "Verification should succeed for fully sanitized signatures");

        //Test judge on a sanitized signature
        let pr: Proof = KSan::prove(&mut pp, &sk_s, &pk_s, &san_pks, &m, &sigp2, None).unwrap();
        let d = KSan::judge(&mut pp, &pk_s, &san_pks, &m, &sigp2, &pr, None).unwrap();
        assert_eq!(d, 'Z', "Judge should return 'Z' for a sanitized signature");

        //Test modification of a message block
        m[2] = "testverfalse".to_string();
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a message block");
        m[2] = "modadm2+3".to_string();

        //Test modification of the signer public key
        let (_sk_s1, pk_s1) = KSan::kgen_s(&mut pp).unwrap();
        let b = KSan::verify(&mut pp, &pk_s1, &san_pks, &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies the signer public key");

        //Test modification of a sanitizer public key
        let (_sk_z4, pk_z4) = KSan::kgen_z(&mut pp).unwrap();
        let b = KSan::verify(&mut pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone(), pk_z4.clone()], &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a sanitizer public key");

        //Test modification of a BLS (inner) signature to another one that is correct over the same message but with a different keys
        let mut sig_false = sigp2.clone();
        let mj = "0".to_string() + m[0].as_str();
        let (_sk1, sk2, pk1, pk2) = BLS::k_gen(&mut pp.bg);
        let s_bls = BLS::sign(&mut pp.bg, &sk2, &mj);
        sig_false.s_ss.pk1_bls[0] = pk1;
        sig_false.s_ss.pk2_bls[0] = pk2;
        sig_false.s_ss.s_bls[0] = s_bls;
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a BLS (inner) signature");
        
        //Test modification of the EQS (outer) signatures to ones that are correct over the same pk1_bls and pk2_bls
        let mut sig_false = sigp2.clone(); 
        let s_x_eqs = EQS::sign(&mut pp.bg, &sk_s.sk_eqs, &sigp2.s_ss.pk1_bls.iter().map(|x| x.into_affine()).collect());
        let s_y_eqs = EQS::sign(&mut pp.bg, &sk_s.sk_eqs, &sigp2.s_ss.pk2_bls.iter().map(|y| y.into_affine()).collect());
        sig_false.s_ss.s_x_eqs = s_x_eqs;
        sig_false.s_ss.s_y_eqs = s_y_eqs;
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies an EQS (outer) signature");

        //Test modification of the ciphertexts matrix
        let mut sig_false = sigp2.clone();
        sig_false.s_ss.secrets[0][0] = sig_false.s_ss.secrets[0][1].clone();
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies the ciphertexts matrix");
        
        //Test adding a block to the message
        let mut sig_false = sigp2.clone(); 
        m.push(m[0].clone());
        sig_false.s_ss.pk1_bls.push(sigp2.s_ss.pk1_bls[0].clone());
        sig_false.s_ss.pk2_bls.push(sigp2.s_ss.pk2_bls[0].clone());
        sig_false.s_ss.s_bls.push(sigp2.s_ss.s_bls[0].clone());
        sig_false.s_ss.secrets[0].push(sigp2.s_ss.secrets[0][1].clone());
        sig_false.s_ss.secrets[1].push(sigp2.s_ss.secrets[1][1].clone());
        sig_false.s_ss.secrets[2].push(sigp2.s_ss.secrets[2][1].clone());
        pp.bg.n = 4;
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary adds a block to the message");
        m.pop();
        pp.bg.n = 3;

        //Test removing a block from the message
        let mut sig_false = sigp2.clone(); 
        m.pop();
        sig_false.s_ss.pk1_bls.pop();
        sig_false.s_ss.pk2_bls.pop();
        sig_false.s_ss.s_bls.pop();
        sig_false.s_ss.secrets[0].pop();
        sig_false.s_ss.secrets[1].pop();
        sig_false.s_ss.secrets[2].pop();
        pp.bg.n = 2;
        let b = KSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary removes a block from the message");
        m.push("modadm2+3".to_string());
        pp.bg.n = 3;

        //Test adding a sanitizer public key
        let mut sig_false = sigp2.clone();
        sig_false.s_ss.secrets.push(sigp2.s_ss.secrets[2].clone());
        let b = KSan::verify(&mut pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone(), pk_z3.clone(), pk_z4.clone()], &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary adds a sanitizer public key");

        //Test removing a sanitizer public key
        let mut sig_false = sigp2.clone();
        sig_false.s_ss.secrets.pop();
        let b = KSan::verify(&mut pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone()], &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary removes a sanitizer public key");
    }
}