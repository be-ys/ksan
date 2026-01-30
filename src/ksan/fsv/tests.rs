#[cfg(test)]
mod tests {
    use crate::blocks::chash::CHash;
    use crate::blocks::sig::SIG;
    use crate::ksan::fsv::ksan::KSan;
    use crate::ksan::fsv::params::{SecParams, Mod, Proof};
    use crate::blocks::vrs::VRS;
    use crate::ksan::hash::{encode, hash};
    use num_bigint::BigInt;

    #[test]
    fn test_fsv_ksan() {
        let secp = SecParams { bits_chash_vrs: 2048, bits_pke: 2056 };
        let pp = KSan::setup(&secp).unwrap();
        let (sk_s, pk_s) = KSan::kgen_s(&pp).unwrap();
        let (sk_z1, pk_z1) = KSan::kgen_z(&pp).unwrap();
        let (sk_z2, pk_z2) = KSan::kgen_z(&pp).unwrap();
        let (_sk_z3, pk_z3) = KSan::kgen_z(&pp).unwrap();

        let mut m = vec!["not_adm".to_string(), "adm1".to_string(), "adm2+3".to_string()];
        let mut adm = vec![vec![false; 3]; 3];
        adm[0][1] = true;
        adm[1][2] = true;
        adm[2][2] = true;
        let san_pks = vec![pk_z1.clone(), pk_z2.clone(), pk_z3.clone()];
        let mut ring: Vec<BigInt> = san_pks.iter().map(|x| x.pkp.clone()).collect();
        let sig = KSan::sign(&pp, &sk_s, &pk_s, &san_pks, &m, &adm).unwrap();

        //Test verification of a non-sanitized signature
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig).unwrap();
        assert!(!b, "Verification should fail for non-sanitized signatures");

        //Test verification of a partially sanitized signature
        let modif = vec![Mod { i: 1, m: "modadm1".to_string() }];
        let sigp1 = KSan::sanitize(&pp, &sk_z1, &pk_s, &pk_z1, 
            &san_pks, &m, &modif, &sig).unwrap();
        m[1] = "modadm1".to_string();
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sigp1).unwrap();
        assert!(!b, "Verification should fail for partially sanitized signatures");

        //Test verification of a fully sanitized signature
        let modif = vec![Mod { i: 2, m: "modadm2+3".to_string() }];
        let sigp2 = KSan::sanitize(&pp, &sk_z2, &pk_s, &pk_z2, 
            &san_pks, &m, &modif, &sigp1).unwrap();
        m[2] = "modadm2+3".to_string();
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sigp2).unwrap();
        assert!(b, "Verification should succeed for fully sanitized signatures");

        //Test global judge on a sanitized signature
        let d = KSan::judge(&pp, &pk_s, &san_pks, &m, &sigp2, None, None).unwrap();
        assert_eq!(d, 'Z', "Global judge should return 'Z' for sanitized signatures");

        //Test judge on an inadmissible block
        let d = KSan::judge(&pp, &pk_s, &san_pks, &m, &sigp2, None, Some(&0usize)).unwrap();
        assert_eq!(d, 'S', "Judge should return 'S' for inadmissible blocks");

        //Test judge on an admissible block
        let d = KSan::judge(&pp, &pk_s, &san_pks, &m, &sigp2, None, Some(&1usize)).unwrap();
        assert_eq!(d, 'Z', "Judge should return 'S' for admissible blocks");

        //Test modification of a message block
        m[2] = "testverfalse+3".to_string();
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a message block");
        m[2] = "modadm2+3".to_string();

        //Test modification of the signer public key
        let (sk_s1, pk_s1) = KSan::kgen_s(&pp).unwrap();
        let b = KSan::verify(&pp, &pk_s1, &san_pks, &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies the signer public key");

        //Test modification of a sanitizer public key
        let (sk_z4, pk_z4) = KSan::kgen_z(&pp).unwrap();
        let b = KSan::verify(&pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone(), pk_z4.clone()], &m, &sigp2).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a sanitizer public key");

        //Test modification of a signing proof to another proof that is correct over the same message but with a different signer
        let mut sig_false = sigp2.clone();
        let mut t = "".to_string();
        t = t + "0" + m[0].as_str();
        t = t + encode(&sig.s.to_bytes()).as_str(); 
        let temp = SIG::sign(&sk_s1.sk, &t);
        sig_false.proofs[0] = Proof{ ps: Some(temp), pz: None };
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a signing proof");

        //Test modification of a sanitization proof to another proof that is correct over the same message but with a different sanitizer not in the original ring
        let mut sig_false = sigp2.clone(); 
        let mut t = "".to_string();
        t = t + "0" + m[0].as_str();
        t = t + encode(&sig.s.to_bytes()).as_str();
        ring.push(pk_z4.pkp.clone());
        let temp = VRS::sign(&pp.p, &pp.q, &pp.g, &sk_z4.skp, &ring, &t);
        ring.pop();
        sig_false.proofs[1] = Proof {
            ps: None,
            pz: Some(temp)
        };
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a sanitization proof");

        //Test modification of the public admissibility matrix and doing any other necessary changes
        let mut sig_false = sigp2.clone(); 
        sig_false.pub_adm[0] = true;
        let mut t = "".to_string();
        t = t + "0" + m[0].as_str();
        t = t + encode(&sig.s.to_bytes()).as_str();
        let proof = VRS::sign(&pp.p, &pp.q, &pp.g, &sk_z1.skp, &ring, &t);
        sig_false.proofs[0] = Proof {
            ps: None,
            pz: Some(proof)
        };
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies the public admissibility matrix");

        //Test modification of the ciphertexts matrix
        let mut sig_false = sigp2.clone();
        sig_false.secrets[0][0] = sig_false.secrets[0][1].clone();
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies the ciphertexts matrix");

        //Test modification of a chameleon hash that is correct over the same message
        let mut sig_false = sigp2.clone();
        let mj: String = "0".to_string() + m[0].as_str();
        let (h, r) = CHash::hash(&pp.p, &pp.q, &pp.g, &sig.hashes[0].pkch, &hash(&mj));
        sig_false.hashes[0].h = h.clone();
        sig_false.hashes[0].r = r.clone();
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary modifies a chameleon hash");

        //Test adding a block to the message
        let mut sig_false = sigp2.clone();
        sig_false.hashes.push(sigp2.hashes[0].clone());
        sig_false.secrets[0].push(sigp2.secrets[0][1].clone());
        sig_false.secrets[1].push(sigp2.secrets[1][1].clone());
        sig_false.secrets[2].push(sigp2.secrets[2][1].clone());
        sig_false.proofs.push(sigp2.proofs[0].clone());
        sig_false.pub_adm.push(sigp2.pub_adm[0].clone());
        m.push(m[0].clone());
        sig_false.n = 4;
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary adds a block to the message");
        m.pop();

        //Test removing a block from the message
        let mut sig_false = sigp2.clone();
        sig_false.hashes.pop();
        sig_false.secrets[0].pop();
        sig_false.secrets[1].pop();
        sig_false.secrets[2].pop();
        sig_false.proofs.pop();
        sig_false.pub_adm.pop();
        m.pop();
        sig_false.n = 2;
        let b = KSan::verify(&pp, &pk_s, &san_pks, &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary removes a block from the message");
        m.push("modadm2+3".to_string());

        //Test adding a sanitizer public key
        let mut sig_false = sigp2.clone();
        sig_false.secrets.push(sigp2.secrets[2].clone());
        let b = KSan::verify(&pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone(), pk_z3.clone(), pk_z4.clone()], &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary adds a sanitizer public key");

        //Test removing a sanitizer public key
        let mut sig_false = sigp2.clone();
        sig_false.secrets.pop();
        let b = KSan::verify(&pp, &pk_s, &vec![pk_z1.clone(), pk_z2.clone()], &m, &sig_false).unwrap();
        assert!(!b, "Verification should fail if an adversary removes a sanitizer public key");
    }
}