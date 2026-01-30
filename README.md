# Sanitizable Signatures with Different Admissibility Policies for Multiple Sanitizers
Implementation of the paper "Sanitizable Signatures with Different Admissibility Policies for Multiple Sanitizers" which was accepted to be published in ASIA CCS 2026. URL: https://hal.science/hal-05411833/
## Disclaimer
This is an experimental prototype implementation intended solely to validate the algorithms described in the associated paper and to assess their performance. It has not been reviewed or audited by any third party. Thus, it is not suitable for production use, and you should proceed at your own risk if you choose to use it.
## Building Blocks
### Public Key Encryption (PKE)
The [Paillier Cryptosystem](https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=592dd02703a7e2b5776f0467026b8f4c1bad9d26) implemented in the [kzen-paillier](https://crates.io/crates/kzen-paillier) crate.
### Chameleon Hash (CHash)
The discrete log Chameleon hash construction from Krawczyk and Rabin's work "[Chameleon hashing and signatures](https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=cd94a5cd939a2f05c892ecaca3713188f4754d63)".
Implemented using the [glass_pumpkin](https://crates.io/crates/glass_pumpkin) and [num-bigint](https://crates.io/crates/num-bigint) crates.
### Digital Signature (SIG)
[Schnorr Signature](https://link.springer.com/content/pdf/10.1007/bf00196725.pdf) using the [k256](https://crates.io/crates/k256) crate.
### Boneh-Lynn-Shacham Signature (BLS)
A modified version of the [BLS Signature](https://www.cs.utexas.edu/~hovav/dist/sigs.pdf) as proposed in [the work of Bultel et al.](https://eprint.iacr.org/2019/648.pdf). Implemented on the `BLS12-381` curve using the [ark-bls12-381](https://crates.io/crates/ark-bls12-381) and associated crates.
### Equivalence Class Signature (EQS)
[Mercurial Signature](https://eprint.iacr.org/2018/923.pdf) due to Crites and Lysyanskaya. We use the [delegatable_credentials](https://crates.io/crates/delegatable_credentials) crate.
### Verifiable Ring Signature (VRS)
We implement the construction of Bultel and Lafourcade's [Verifiable Ring Signature](https://eprint.iacr.org/2017/605.pdf) using the [glass_pumpkin](https://crates.io/crates/glass_pumpkin) and [num-bigint](https://crates.io/crates/num-bigint) crates.
## Constructions
### Full-Sanitization-Verifiable $k$-Sanitizer Sanitizable Signature (FSV-k-SAN)
The construction uses PKE, CHash, SIG, and VRS.
#### Security Parameters
- `bits_chash_vrs`: Controls how large the prime numbers for CHash and VRS are. You need to make sure to pick a large enough value so that the prime number is bigger than `256` bits. Recommended value: greater than or equal `2048`.
- `bits_pke`: Controls how large the prime numbers for PKE are.
### Invisible-Unlinkable-Transparent $k$-Sanitizer Sanitizable Signature (IUT-k-SAN)
The construction uses PKE, BLS, EQS, and VRS.
#### Security Parameters
- `bits_vrs`: Controls how large the prime numbers for VRS are. You need to make sure to pick a large enough value so that the prime number is bigger than `256` bits. Recommended value: greater than or equal `2048`.
- `bits_pke`: Controls how large the prime numbers for PKE are.
- `n`: The length of the messages to be signed (number of message parts not characters).
- `dst`: The Domain Separation Tag for the hash to curve function used in BLS. Any string would work.
## Hash Techniques
- `H1` - Hash a `String` to a `BigInt` in $Z^*_q$: hash the `String` to bytes using `Sha256`, then convert the bytes to a `BigInt` using the method `BigInt::from_bytes_be`. Here $q$ should be bigger than 256 bits.
- `H2` - Hash a `String` to `G2Projective`: This is needed for `BLS`. We use the [Hash To Curve](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html) implementation in the [ark-ec](https://crates.io/crates/ark-ec) crate.
- `H3` - Hash the `R` and `S` elements in a `VRS` proof to a `BigInt` in $Z^*_q$: assemble a `String` and use `H1`.
- `H4` - Hash a `String` to $G_q$ where a safe prime $p = 2q + 1$: This is used for `VRS`. Use `H1` on the message concatenated to a counter to generate the hash $h$. If $h^q$ mod $p = 1$, return $h$, otherwise, increment the counter and try again.
## How to Use?
Check the test files `/src/ksan/fsv/tests.rs` and `/src/ksan/iut/tests.rs` for examples of how to use the signature scheme.

To run the performance tests you can use the following command:
```
ksan --num-exec 200 --op-time --perf --perf-sec
```
The argument `--num-exec` specifies the number of times each operation is executed to calculate an average execution time.

To get the execution time of exponentiation and pairing operations in the different groups and fields used, you can use the `--op-time` option. The results of this test are printed to the consol. 

To get the execution time of the algorithms of both constructions with secure security parameters ($\lambda = 2048$ for CHash and VRS and $\lambda = 2056$ for PKE), you can use the `--perf-sec` option. The `--perf` option does the same test but with $\lambda = 512$ for CHash and VRS and $\lambda = 520$ for PKE. The results of both of these tests can be found in the text files `data\perf_sec.txt` and `data\perf.txt`.

## License
Licensed under the AGPL-3.0 license (see [LICENSE-AGPL](LICENSE-AGPL)) with an exception for any company that is part of Be-Invest (see [LICENSE-AGPL-EXCEPTION](LICENSE-AGPL-EXCEPTION)).

## Third-Party Libraries
We use the following third-party Rust crates.
- [kzen-paillier](https://crates.io/crates/kzen-paillier): MIT License. See [LICENSES/kzen-paillier-MIT](LICENSES/kzen-paillier-MIT)
- [k256](https://crates.io/crates/k256): MIT License. See [LICENSES/k256-MIT](LICENSES/k256-MIT)
- [rand](https://crates.io/crates/rand): MIT License. See [LICENSES/rand-MIT](LICENSES/rand-MIT)
- [num-integer](https://crates.io/crates/num-integer): MIT License. See [LICENSES/num-integer-MIT](LICENSES/num-integer-MIT)
- [num-traits](https://crates.io/crates/num-traits): MIT License. See [LICENSES/k256-MIT](LICENSES/num-traits-MIT)
- [glass_pumpkin](https://crates.io/crates/glass_pumpkin): Apache-2.0 License. See [LICENSES/glass_pumpkin-APACHE](LICENSES/glass_pumpkin-APACHE)
- [rand_core](https://crates.io/crates/rand_core): MIT License. See [LICENSES/rand_core-MIT](LICENSES/rand_core-MIT)
- [num-bigint](https://crates.io/crates/num-bigint): MIT License. See [LICENSES/num-bigint-MIT](LICENSES/num-bigint-MIT)
- [sha2](https://crates.io/crates/sha2): MIT License. See [LICENSES/sha2-MIT](LICENSES/sha2-MIT)
- [base64](https://crates.io/crates/base64): MIT License. See [LICENSES/base64-MIT](LICENSES/base64-MIT)
- [serde](https://crates.io/crates/serde): MIT License. See [LICENSES/serde-MIT](LICENSES/serde-MIT)
- [serde_json](https://crates.io/crates/serde_json): MIT License. See [LICENSES/serde_json-MIT](LICENSES/serde_json-MIT)
- [delegatable_credentials](https://crates.io/crates/delegatable_credentials): Apache-2.0 License. See [LICENSES/delegatable_credentials-APACHE](LICENSES/delegatable_credentials-APACHE)
- [ark-bls12-381](https://crates.io/crates/ark-bls12-381): MIT License. See [LICENSES/ark-bls12-381-MIT](LICENSES/ark-bls12-381-MIT)
- [ark-std](https://crates.io/crates/ark-std): MIT License. See [LICENSES/ark-std-MIT](LICENSES/ark-std-MIT)
- [ark-ec](https://crates.io/crates/ark-ec): MIT License. See [LICENSES/ark-ec-MIT](LICENSES/ark-ec-MIT)
- [ark-serialize](https://crates.io/crates/ark-serialize): MIT License. See [LICENSES/ark-serialize-MIT](LICENSES/ark-serialize-MIT)
- [ark-ff](https://crates.io/crates/ark-ff): MIT License. See [LICENSES/ark-ff-MIT](LICENSES/ark-ff-MIT)
- [curv-kzen](https://crates.io/crates/curv-kzen): MIT License. See [LICENSES/curv-kzen-MIT](LICENSES/curv-kzen-MIT)
- [mercurial-signature](https://crates.io/crates/mercurial-signature): MIT License. See [LICENSES/mercurial-signature-MIT](LICENSES/mercurial-signature-MIT)