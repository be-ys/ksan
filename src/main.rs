mod blocks;
mod ksan;

use crate::blocks::mercurial::Mercurial;
use crate::ksan::fsv::ksan::KSan as FSVKSan;
use crate::ksan::fsv::params::{
    SecParams as FSVSecParams,
    PublicParams as FSVPublicParams,
    Mod as FSVMod,
    SanitizerPublicKey as FSVSanitizerPublicKey,
    SanitizerSecretKey as FSVSanitizerSecretKey
};

use crate::ksan::iut::ksan::KSan as IUTKSan;
use crate::ksan::iut::params::{
    SecParams as IUTSecParams,
    PublicParams as IUTPublicParams,
    Mod as IUTMod,
    SanitizerPublicKey as IUTSanitizerPublicKey,
    SanitizerSecretKey as IUTSanitizerSecretKey
};

use blocks::chash::*;
use blocks::eqs::*;
use blocks::sig::*;
use blocks::pke::*;

use num_bigint::{BigInt, BigUint};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ff::UniformRand;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use std::time::Instant;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;
use std::env;

use mercurial_signature::{Curve, CurveBls12_381};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut num_exec = 2000;

    let mut call_perf = false;
    let mut call_perf_sec = false;
    let mut call_op_time = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--num-exec" => {
                if i + 1 < args.len() {
                    num_exec = args[i + 1].parse().unwrap_or(num_exec);
                    i += 1;
                }
            }
            "--perf" => {
                call_perf = true;
            }
            "--perf-sec" => {
                call_perf_sec = true;
            }
            "--op-time" => {
                call_op_time = true;
            }
            _ => {}
        }
        i += 1;
    }

    println!("Number of executions: {}", num_exec);
    println!("perf: {}, perf-sec: {}, op-time: {}", call_perf, call_perf_sec, call_op_time);

    if call_op_time {
        get_op_time(num_exec);
    }
    if call_perf {
        test_perf(num_exec);
    }
    if call_perf_sec {
        test_perf_sec(num_exec);
    }
}

fn get_op_time(num_exec: usize) {
    let mut bg = EQS::setup(3, &"k-SAN test".to_string());
    let mut g1_exec_time:Vec<f64> = Vec::new();
    let mut g2_exec_time:Vec<f64> = Vec::new();
    let mut pair_exec_time:Vec<f64> = Vec::new();
    let mut p_exec_time:Vec<f64> = Vec::new();
    let mut n_exec_time:Vec<f64> = Vec::new();
    let mut n2_exec_time:Vec<f64> = Vec::new();
    let mut g11_exec_time:Vec<f64> = Vec::new();
    let mut enc_exec_time:Vec<f64> = Vec::new();
    let mut dec_exec_time:Vec<f64> = Vec::new();
    let mut mul_exec_time:Vec<f64> = Vec::new();
    let (p, q, g) = CHash::setup(512);
    let n = p.clone() * q;
    let n2 = n.clone().pow(2);
    let (sk, _pk) = SIG::k_gen();
    let (ske, pke) = PKE::k_gen(520);
    let mut rng = thread_rng();
    for i in 0..num_exec {
        let r = Fr::rand(&mut bg.rng);
        let start = Instant::now();
        let g1 = bg.p1 * r;
        let duration = start.elapsed();
        g1_exec_time.push(duration.as_micros() as f64);

        let r = Fr::rand(&mut bg.rng);
        let start = Instant::now();
        let g2 = bg.p2 * r;
        let duration = start.elapsed();
        g2_exec_time.push(duration.as_micros() as f64);

        let start = Instant::now();
        let _pair = Bls12_381::pairing(g1, g2);
        let duration = start.elapsed();
        pair_exec_time.push(duration.as_micros() as f64);
        let bytes: [u8; 8] = rng.gen();
        let bytes1: [u8; 8] = rng.gen();
        let bytes2: [u8; 8] = rng.gen();
        let bytes3: [u8; 8] = rng.gen();
        let mut bytes_f = bytes.to_vec();
        bytes_f.extend_from_slice(&bytes1);
        bytes_f.extend_from_slice(&bytes2);
        bytes_f.extend_from_slice(&bytes3);
        let e = BigInt::from(BigUint::from_bytes_be(&bytes_f.as_slice()));
        let ee = g.modpow(&e, &n);
        let start = Instant::now();
        let _n = ee.modpow(&e, &n);
        let duration = start.elapsed();
        n_exec_time.push(duration.as_micros() as f64);

        let start = Instant::now();
        let _n2 = ee.modpow(&e, &n2);
        let duration = start.elapsed();
        n2_exec_time.push(duration.as_micros() as f64);

        let start = Instant::now();
        let _pr = g.modpow(&e, &p);
        let duration = start.elapsed();
        p_exec_time.push(duration.as_micros() as f64);

        let msg = generate_random_string(50);
        let start = Instant::now();
        let _s = SIG::sign(&sk, &msg);
        let duration = start.elapsed();
        g11_exec_time.push(duration.as_micros() as f64);

        let bytes: [u8; 32] = rng.gen();
        let r = BigInt::from(BigUint::from_bytes_be(&bytes));
        let start = Instant::now();
        let c = PKE::encrypt(&pke, &r);
        let duration = start.elapsed();
        enc_exec_time.push(duration.as_micros() as f64);

        let start = Instant::now();
        let _d = PKE::decrypt(&ske, &c);
        let duration = start.elapsed();
        dec_exec_time.push(duration.as_micros() as f64);

        let bytes: [u8; 32] = rng.gen();
        let r1 = BigInt::from(BigUint::from_bytes_be(&bytes));
        let start = Instant::now();
        let _c1 = PKE::multiply(&pke, &c, &r1);
        let duration = start.elapsed();
        mul_exec_time.push(duration.as_micros() as f64);

        println!("num_exec: {}", i);
    }


    let a_p = average(p_exec_time) as f64;
    let a_g1 = average(g1_exec_time) as f64;
    let a_g2 = average(g2_exec_time) as f64;
    let a_pair = average(pair_exec_time) as f64;
    let a_n = average(n_exec_time) as f64;
    let a_n2 = average(n2_exec_time) as f64;
    let a_g11 = average(g11_exec_time) as f64;
    let a_enc = average(enc_exec_time) as f64;
    let a_dec = average(dec_exec_time) as f64;
    let a_mul = average(mul_exec_time) as f64;
    // println!("P: {}. Scaled exec_time: G1: {}, G2: {}, Pair: {}, P: {}, N: {}, N2: {}, G1 secp256k1: {}, ENC: {}, DEC: {}, MUL: {}",
    //         a_p,
    //         (a_g1 / a_p).round(),
    //         (a_g2 / a_p).round(),
    //         (a_pair / a_p).round(),
    //         (a_p / a_p).round(),
    //         (a_n / a_p).round(),
    //         (a_n2 / a_p).round(),
    //         (a_g11 / a_p).round(),
    //         (a_enc / a_p).round(),
    //         (a_dec / a_p).round(),
    //         (a_mul / a_p).round());

    println!("P: {}. Scaled exec_time: G1: {}, G2: {}, Pair: {}, P: {}, N: {}, N2: {}, G1 secp256k1: {}, ENC: {}, DEC: {}, MUL: {}",
            a_p,
            a_g1.round(),
            a_g2.round(),
            a_pair.round(),
            a_p.round(),
            a_n.round(),
            a_n2.round(),
            a_g11.round(),
            a_enc.round(),
            a_dec.round(),
            a_mul.round());
    
    test_perf_mercurial(num_exec, a_p);
    
    test_perf_eqs(num_exec, a_p);
    
}

fn test_perf_eqs(num_exec: usize, _a_p: f64) {
    let mut pair_cost = 0.0;
    let mut last_verify = 0.0;
    let mut last_n = 0.0;

    for i in 0..5 {
        let mut s_exec_time:Vec<f64> = Vec::new();
        let mut v_exec_time:Vec<f64> = Vec::new();
        let mut c_exec_time:Vec<f64> = Vec::new();
        let n = 3 + i * 3;
        let mut bg = EQS::setup(n, &"k-SAN test".to_string());
        let (sk, pk) = EQS::k_gen(&mut bg);
        let mut m: Vec<G1Affine> = Vec::new();
        for _j in 0..n {
            let g1 = Fr::rand(&mut bg.rng);
            m.push((bg.p1 * g1).into_affine());
        }

        for _i in 0..num_exec {
            let start = Instant::now();
            let s = EQS::sign(&mut bg, &sk, &m);
            let duration = start.elapsed();
            s_exec_time.push(duration.as_micros() as f64);

            let start = Instant::now();
            let _b = EQS::verify(&mut bg, &pk, &m, &s);
            let duration = start.elapsed();
            v_exec_time.push(duration.as_micros() as f64);

            let r = BigInt::from(50);
            let start = Instant::now();
            let (_sp, _mp) = EQS::chg_rep(&mut bg, &pk, &m, &s, &r);
            let duration = start.elapsed();
            c_exec_time.push(duration.as_micros() as f64);
        }

        let x = average(v_exec_time) as f64;
        println!("n: {}, S: {}, V: {}, C: {}",
            n,
            average(s_exec_time),
            x,
            average(c_exec_time));
        
        if last_verify != 0.0 {
            pair_cost += (x - last_verify) / 3.0;
        }
        last_verify = x;
        last_n = n as f64;
    }
    pair_cost = (pair_cost / 5.0).round();
    let verify_constant = last_verify - (last_n * pair_cost);
    // println!("Verify cost: {}*n + {}", (pair_cost / a_p).round(), (verify_constant / a_p).round());
    println!("Verify cost: {}*n + {}", pair_cost.round(), verify_constant.round());
}

fn test_perf_mercurial(num_exec: usize, _a_p: f64) {
    let mut pair_cost = 0.0;
    let mut last_verify = 0.0;
    let mut last_n = 0.0;

    for i in 0..5 {
        let mut s_exec_time:Vec<f64> = Vec::new();
        let mut v_exec_time:Vec<f64> = Vec::new();
        let mut c_exec_time:Vec<f64> = Vec::new();
        let n = 3 + i * 3;
        let mut bg = Mercurial::setup(n, &"k-SAN test".to_string());
        let (mut sk, pk) = Mercurial::k_gen(&mut bg);
        let mut m: Vec<<CurveBls12_381 as Curve>::G1> = Vec::new();
        for _j in 0..n {
            let g1 = <CurveBls12_381 as Curve>::Fr::rand(&mut bg.rng);
            m.push(bg.pp.p1 * g1);
        }

        for _i in 0..num_exec {
            let start = Instant::now();
            let mut s = Mercurial::sign(&mut bg, &mut sk, &m);
            let duration = start.elapsed();
            s_exec_time.push(duration.as_micros() as f64);

            let start = Instant::now();
            let _b = Mercurial::verify(&mut bg, &pk, &m, &s);
            let duration = start.elapsed();
            v_exec_time.push(duration.as_micros() as f64);

            let r = BigInt::from(50);
            let start = Instant::now();
            let (mut _sp, mut _mp) = Mercurial::chg_rep(&mut bg, &pk, &mut m, &mut s, &r);
            let duration = start.elapsed();
            c_exec_time.push(duration.as_micros() as f64);
        }

        let x = average(v_exec_time) as f64;
        println!("n: {}, S: {}, V: {}, C: {}",
            n,
            average(s_exec_time),
            x,
            average(c_exec_time));
        
        if last_verify != 0.0 {
            pair_cost += (x - last_verify) / 3.0;
        }
        last_verify = x;
        last_n = n as f64;
    }
    pair_cost = (pair_cost / 5.0).round();
    let verify_constant = last_verify - (last_n * pair_cost);
    //println!("Verify cost: {}*n + {}", (pair_cost / a_p).round(), (verify_constant / a_p).round());
    println!("Verify cost: {}*n + {}", pair_cost.round(), verify_constant.round());
}

fn test_perf(num_exec: usize) {
    let sizes = [3, 6, 9, 12, 15];

    let data_dir = Path::new("data");
    create_dir_all(data_dir).unwrap();
    let out_file_path = data_dir.join("perf.txt");
    let mut out_file = File::create(out_file_path).unwrap();

    let mut fsv_sig_times_n = String::new();
    let mut fsv_san_times_n = String::new();
    let mut fsv_ver_times_n = String::new();
    let mut fsv_jdg_times_n = String::new();

    let mut fsv_sig_times_k = String::new();
    let mut fsv_san_times_k = String::new();
    let mut fsv_ver_times_k = String::new();
    let mut fsv_jdg_times_k = String::new();

    let mut iut_sig_times_n = String::new();
    let mut iut_san_times_n = String::new();
    let mut iut_ver_times_n = String::new();
    let mut iut_prf_times_n = String::new();
    let mut iut_jdg_times_n = String::new();

    let mut iut_sig_times_k = String::new();
    let mut iut_san_times_k = String::new();
    let mut iut_ver_times_k = String::new();
    let mut iut_prf_times_k = String::new();
    let mut iut_jdg_times_k = String::new();

    let secp = FSVSecParams { bits_chash_vrs: 512, bits_pke: 520 };
    let mut pp = FSVKSan::setup(&secp).unwrap();

    // FSV
    for s in sizes {
        let (sig_time, san_time, ver_time, jdg_time) = measure_ksan_fsv_efficiency(s, 9, num_exec, &mut pp, 3);
        fsv_sig_times_n.push_str(format!("({}, {})", s, sig_time).as_str());
        fsv_san_times_n.push_str(format!("({}, {})", s, san_time).as_str());
        fsv_ver_times_n.push_str(format!("({}, {})", s, ver_time).as_str());
        fsv_jdg_times_n.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("FSV-N - s: {}", s);
        let (sig_time, san_time, ver_time, jdg_time) = measure_ksan_fsv_efficiency(9, s, num_exec, &mut pp, 3);
        fsv_sig_times_k.push_str(format!("({}, {})", s, sig_time).as_str());
        fsv_san_times_k.push_str(format!("({}, {})", s, san_time).as_str());
        fsv_ver_times_k.push_str(format!("({}, {})", s, ver_time).as_str());
        fsv_jdg_times_k.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("FSV-K - s: {}", s);
    }

    let mut secp = IUTSecParams { bits_vrs: 512, bits_pke: 520, n: 1 as u32, dst: "k-SAN test".to_string() };
    let mut pp = IUTKSan::setup(&secp).unwrap();

    // IUT
    for s in sizes {
        secp.n = s as u32;
        let new_bg = EQS::setup(secp.n + 1, &secp.dst);
        pp.bg = new_bg;
        let (sig_time, san_time, ver_time, prf_time, jdg_time) = measure_ksan_iut_efficiency(s, 9, num_exec, &mut pp, 3);
        iut_sig_times_n.push_str(format!("({}, {})", s, sig_time).as_str());
        iut_san_times_n.push_str(format!("({}, {})", s, san_time).as_str());
        iut_ver_times_n.push_str(format!("({}, {})", s, ver_time).as_str());
        iut_prf_times_n.push_str(format!("({}, {})", s, prf_time).as_str());
        iut_jdg_times_n.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("IUT-N - s: {}", s);
        secp.n = 9 as u32;
        let new_bg = EQS::setup(secp.n + 1, &secp.dst);
        pp.bg = new_bg;
        let (sig_time, san_time, ver_time, prf_time, jdg_time) = measure_ksan_iut_efficiency(9, s, num_exec, &mut pp, 3);
        iut_sig_times_k.push_str(format!("({}, {})", s, sig_time).as_str());
        iut_san_times_k.push_str(format!("({}, {})", s, san_time).as_str());
        iut_ver_times_k.push_str(format!("({}, {})", s, ver_time).as_str());
        iut_prf_times_k.push_str(format!("({}, {})", s, prf_time).as_str());
        iut_jdg_times_k.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("IUT-K - s: {}", s);
    }

    writeln!(out_file, "FSV_N:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_sig_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_san_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_ver_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_jdg_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

    writeln!(out_file, "\n\nFSV_K:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_sig_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_san_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_ver_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_jdg_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

    writeln!(out_file, "\n\nIUT_N:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_sig_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_san_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_ver_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=orange,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_prf_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Prove}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_jdg_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

    writeln!(out_file, "\n\nIUT_K:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_sig_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_san_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_ver_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=orange,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_prf_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Prove}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_jdg_times_k).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

}

fn test_perf_sec(num_exec: usize) {
    let sizes = [5, 7, 9, 11, 13, 15];

    let data_dir = Path::new("data");
    create_dir_all(data_dir).unwrap();
    let out_file_path = data_dir.join("perf_sec.txt");
    let mut out_file = File::create(out_file_path).unwrap();

    let mut fsv_sig_times_n = String::new();
    let mut fsv_san_times_n = String::new();
    let mut fsv_ver_times_n = String::new();
    let mut fsv_jdg_times_n = String::new();

    let mut iut_sig_times_n = String::new();
    let mut iut_san_times_n = String::new();
    let mut iut_ver_times_n = String::new();
    let mut iut_prf_times_n = String::new();
    let mut iut_jdg_times_n = String::new();

    let secp = FSVSecParams { bits_chash_vrs: 2048, bits_pke: 2056 };
    let mut pp = FSVKSan::setup(&secp).unwrap();

    // FSV
    for s in sizes {
        let (sig_time, san_time, ver_time, jdg_time) = measure_ksan_fsv_efficiency(s, 5, num_exec, &mut pp, 5);
        fsv_sig_times_n.push_str(format!("({}, {})", s, sig_time).as_str());
        fsv_san_times_n.push_str(format!("({}, {})", s, san_time).as_str());
        fsv_ver_times_n.push_str(format!("({}, {})", s, ver_time).as_str());
        fsv_jdg_times_n.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("FSV-N - s: {}", s);
    }

    let mut secp = IUTSecParams { bits_vrs: 2048, bits_pke: 2056, n: 1 as u32, dst: "k-SAN test".to_string() };
    let mut pp = IUTKSan::setup(&secp).unwrap();

    // IUT
    for s in sizes {
        secp.n = s as u32;
        let new_bg = EQS::setup(secp.n + 1, &secp.dst);
        pp.bg = new_bg;
        let (sig_time, san_time, ver_time, prf_time, jdg_time) = measure_ksan_iut_efficiency(s, 5, num_exec, &mut pp, 5);
        iut_sig_times_n.push_str(format!("({}, {})", s, sig_time).as_str());
        iut_san_times_n.push_str(format!("({}, {})", s, san_time).as_str());
        iut_ver_times_n.push_str(format!("({}, {})", s, ver_time).as_str());
        iut_prf_times_n.push_str(format!("({}, {})", s, prf_time).as_str());
        iut_jdg_times_n.push_str(format!("({}, {})", s, jdg_time).as_str());
        println!("IUT-N - s: {}", s);
    }

    writeln!(out_file, "FSV_N:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_sig_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_san_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_ver_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=o]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", fsv_jdg_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

    writeln!(out_file, "\n\nIUT_N:").unwrap();
    writeln!(out_file, "\\addplot[color=blue,mark=triangle*, dashed, mark options={{solid}}]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_sig_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sign}}").unwrap();
    writeln!(out_file, "\\addplot[color=red,mark=triangle*, dashed, mark options={{solid}}]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_san_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Sanitize}}").unwrap();
    writeln!(out_file, "\\addplot[color=green!50!black,mark=triangle*, dashed, mark options={{solid}}]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_ver_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Verify}}").unwrap();
    writeln!(out_file, "\\addplot[color=orange,mark=triangle*, dashed, mark options={{solid}}]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_prf_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Prove}}").unwrap();
    writeln!(out_file, "\\addplot[color=purple,mark=triangle*, dashed, mark options={{solid}}]").unwrap();
    writeln!(out_file, "coordinates {{{}}};", iut_jdg_times_n).unwrap();
    writeln!(out_file, "%\\addlegendentry{{Judge}}").unwrap();

}

fn generate_random_string(length: usize) -> String {
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    return rand_string;
}

fn measure_ksan_iut_efficiency(n: usize, k: usize, num_exec: usize, mut pp: &mut IUTPublicParams, num_adm: usize) -> (u64, u64, u64, u64, u64) {
    //Setup
    let (sk_s, pk_s) = IUTKSan::kgen_s(&mut pp).unwrap();
    let mut m: Vec<String> = Vec::with_capacity(n);
    for _j in 0..n {
        m.push(generate_random_string(10));
    }
    let mut adm = vec![vec![false; n]; k];
    let mut secrets: Vec<IUTSanitizerSecretKey> = Vec::with_capacity(k);
    let mut san_pks: Vec<IUTSanitizerPublicKey> = Vec::with_capacity(k);
    for i in 0..k {
        for j in 0..num_adm {
            adm[i][j] = true;
        }
        let (sk_z, pk_z) = IUTKSan::kgen_z(&mut pp).unwrap();
        secrets.push(sk_z);
        san_pks.push(pk_z);
    }

    let mut sig_time: Vec<f64> = Vec::new();
    let mut san_time: Vec<f64> = Vec::new();
    let mut ver_time: Vec<f64> = Vec::new();
    let mut prf_time: Vec<f64> = Vec::new();
    let mut jdg_time: Vec<f64> = Vec::new();

    for _x in 0..num_exec {
        //Sign
        let start = Instant::now();
        let mut sig = IUTKSan::sign(&mut pp, &sk_s, &pk_s, &san_pks, &m, &adm).unwrap();
        let duration = start.elapsed();
        sig_time.push(duration.as_millis() as f64);

        //Sanitize
        let ns = generate_random_string(10);
        let modif = vec![IUTMod { i: 0, m: ns.clone() }];
        let start = Instant::now();
        sig = IUTKSan::sanitize(&mut pp, &secrets[0], &pk_s, &san_pks[0], 
            &san_pks, &m, &modif, &sig).unwrap();
        let duration = start.elapsed();
        san_time.push(duration.as_millis() as f64);
        m[0] = ns.clone();

        //Verify
        let start = Instant::now();
        let b = IUTKSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig).unwrap();
        let duration = start.elapsed();
        ver_time.push(duration.as_millis() as f64);
        assert!(b, "Verify failed");

        //Prove
        let start = Instant::now();
        let pr: ksan::iut::params::Proof = IUTKSan::prove(&mut pp, &sk_s, &pk_s, &san_pks, &m, &sig, None).unwrap();
        let duration = start.elapsed();
        prf_time.push(duration.as_millis() as f64);

        //Judge
        let start = Instant::now();
        let d = IUTKSan::judge(&mut pp, &pk_s, &san_pks, &m, &sig, &pr, None).unwrap();
        let duration = start.elapsed();
        jdg_time.push(duration.as_millis() as f64);
        assert!(d == 'Z', "Judge failed");
    }
    return (average(sig_time), 
            average(san_time), 
            average(ver_time), 
            average(prf_time), 
            average(jdg_time));
}

fn measure_ksan_fsv_efficiency(n: usize, k: usize, num_exec: usize, mut pp: &mut FSVPublicParams, num_adm: usize) -> (u64, u64, u64, u64) {
    //Setup
    let (sk_s, pk_s) = FSVKSan::kgen_s(&mut pp).unwrap();
    let mut m: Vec<String> = Vec::with_capacity(n);
    for _j in 0..n {
        m.push(generate_random_string(10));
    }
    let mut adm = vec![vec![false; n]; k];
    let mut secrets: Vec<FSVSanitizerSecretKey> = Vec::with_capacity(k);
    let mut san_pks: Vec<FSVSanitizerPublicKey> = Vec::with_capacity(k);
    for i in 0..k {
        for j in 0..num_adm {
            adm[i][j] = true;
        }
        let (sk_z, pk_z) = FSVKSan::kgen_z(&mut pp).unwrap();
        secrets.push(sk_z);
        san_pks.push(pk_z);
    }

    let mut sig_time: Vec<f64> = Vec::new();
    let mut san_time: Vec<f64> = Vec::new();
    let mut ver_time: Vec<f64> = Vec::new();
    let mut jdg_time: Vec<f64> = Vec::new();

    for _x in 0..num_exec {
        //Sign
        let start = Instant::now();
        let mut sig = FSVKSan::sign(&mut pp, &sk_s, &pk_s, &san_pks, &m, &adm).unwrap();
        let duration = start.elapsed();
        sig_time.push(duration.as_millis() as f64);

        //Sanitize\
        for j in 0..num_adm {
            let ns = generate_random_string(10);
            let modif = vec![FSVMod { i: j, m: ns.clone() }];
            let start = Instant::now();
            sig = FSVKSan::sanitize(&mut pp, &secrets[0], &pk_s, &san_pks[0], 
                &san_pks, &m, &modif, &sig).unwrap();
            let duration = start.elapsed();
            if j == 0 {
                san_time.push(duration.as_millis() as f64);
            }
            m[j] = ns.clone();
        }

        //Verify
        let start = Instant::now();
        let b = FSVKSan::verify(&mut pp, &pk_s, &san_pks, &m, &sig).unwrap();
        let duration = start.elapsed();
        ver_time.push(duration.as_millis() as f64);
        assert!(b, "Verify failed");

        //Judge
        let start = Instant::now();
        let d = FSVKSan::judge(&mut pp, &pk_s, &san_pks, &m, &sig, None, None).unwrap();
        let duration = start.elapsed();
        jdg_time.push(duration.as_millis() as f64);
        assert!(d == 'Z', "Judge failed");
    }
    return (average(sig_time), 
            average(san_time), 
            average(ver_time), 
            average(jdg_time));
}

fn _median(mut numbers: Vec<f64>) -> u64 {
    let len = numbers.len();
    
    numbers.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mid = len / 2;
    let mut res: u64;
    if len % 2 == 0 {
        res = ((numbers[mid - 1] + numbers[mid]) / 2.0).round() as u64;
    } else {
        res = numbers[mid].round() as u64;
    }
    if res == 0 {
        res = 1;
    }
    return res;
}

fn average(numbers: Vec<f64>) -> u64 {
    let sum: f64 = numbers.iter().sum();
    let count = numbers.len() as f64;

    let mut res = (sum / count).round() as u64;
    if res == 0 {
        res = 1;
    }

    return res; 
}