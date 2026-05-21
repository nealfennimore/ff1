// FF1 Format-Preserving Encryption
// Implements NIST SP 800-38G
//
// Arithmetic strategy:
// - Fast path (u128): used when radix^max(u,v) < 2^128, covering all NIST
//   sample inputs and most real-world usage.
// - BigUint path: engaged automatically when the plaintext is long enough that
//   NUMradix values would overflow u128 (e.g. radix=36, n=128).
//   y = NUM(S[0..d]) always fits in u128 (S is at most 16 AES bytes), so only
//   num_radix, pow, modulus, and str_m_radix need BigUint on the large path.

// WASM bindings — only compiled when targeting wasm32
#[cfg(target_arch = "wasm32")]
pub mod wasm;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use num_traits::identities::Zero;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Ff1Error {
    InvalidKeyLength(usize),
    TweakTooLong(usize),
    InvalidRadix(u32),
    PlaintextTooShort(usize),
    PlaintextTooLong(usize),
    SymbolOutOfRange(u32),
}

impl fmt::Display for Ff1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ff1Error::InvalidKeyLength(n) => {
                write!(f, "Invalid key length: {} bytes (must be 16, 24, or 32)", n)
            }
            Ff1Error::TweakTooLong(n) => write!(f, "Tweak too long: {} bytes", n),
            Ff1Error::InvalidRadix(r) => write!(f, "Invalid radix: {} (must be 2..=65536)", r),
            Ff1Error::PlaintextTooShort(n) => {
                write!(f, "Plaintext too short: {} symbols (minimum 2)", n)
            }
            Ff1Error::PlaintextTooLong(n) => write!(f, "Plaintext too long: {} symbols", n),
            Ff1Error::SymbolOutOfRange(s) => {
                write!(f, "Symbol value {} is out of range for radix", s)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AES-ECB single-block encrypt
// ---------------------------------------------------------------------------

fn aes_ecb(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    match key.len() {
        16 => {
            let c = Aes128::new_from_slice(key).unwrap();
            c.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        24 => {
            let c = Aes192::new_from_slice(key).unwrap();
            c.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        32 => {
            let c = Aes256::new_from_slice(key).unwrap();
            c.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        _ => panic!("Unexpected key length"),
    }
    out
}

// ---------------------------------------------------------------------------
// u128 arithmetic helpers (fast path)
// ---------------------------------------------------------------------------

#[inline]
fn num_radix_u128(radix: u128, x: &[u32]) -> u128 {
    x.iter().fold(0u128, |acc, &d| acc * radix + d as u128)
}

#[inline]
fn str_m_radix_u128(radix: u128, m: usize, mut x: u128) -> Vec<u32> {
    let mut digits = vec![0u32; m];
    for i in (0..m).rev() {
        digits[i] = (x % radix) as u32;
        x /= radix;
    }
    digits
}

#[inline]
fn pow_u128(base: u128, exp: usize) -> u128 {
    (0..exp).fold(1u128, |acc, _| acc * base)
}

// ---------------------------------------------------------------------------
// BigUint arithmetic helpers (large-input path)
// ---------------------------------------------------------------------------

#[inline]
fn num_radix_big(radix: &BigUint, x: &[u32]) -> BigUint {
    x.iter()
        .fold(BigUint::zero(), |acc, &d| acc * radix + BigUint::from(d))
}

#[inline]
fn str_m_radix_big(radix: &BigUint, m: usize, mut x: BigUint) -> Vec<u32> {
    let mut digits = vec![0u32; m];
    for i in (0..m).rev() {
        let rem = &x % radix;
        digits[i] = rem.to_u32().expect("radix <= 65536, digit always fits u32");
        x /= radix;
    }
    digits
}

// Serialize a BigUint to exactly `blen` big-endian bytes (right-aligned, zero-padded).
fn biguint_to_be_bytes_fixed(x: &BigUint, blen: usize) -> Vec<u8> {
    let raw = x.to_bytes_be();
    if raw.len() >= blen {
        raw[raw.len() - blen..].to_vec()
    } else {
        let mut out = vec![0u8; blen];
        out[blen - raw.len()..].copy_from_slice(&raw);
        out
    }
}

// ---------------------------------------------------------------------------
// Ff1Cipher
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct Ff1Cipher {
    key: Vec<u8>,
    radix: u32,
    max_tlen: usize,
}

impl Ff1Cipher {
    pub fn new(key: &[u8], radix: u32, max_tlen: usize) -> Result<Self, Ff1Error> {
        match key.len() {
            16 | 24 | 32 => {}
            n => return Err(Ff1Error::InvalidKeyLength(n)),
        }
        if radix < 2 || radix > 65536 {
            return Err(Ff1Error::InvalidRadix(radix));
        }
        Ok(Ff1Cipher {
            key: key.to_vec(),
            radix,
            max_tlen,
        })
    }

    pub fn new_default(key: &[u8], radix: u32) -> Result<Self, Ff1Error> {
        Self::new(key, radix, 256)
    }

    fn check_tweak(&self, tweak: &[u8]) -> Result<(), Ff1Error> {
        if tweak.len() > self.max_tlen {
            return Err(Ff1Error::TweakTooLong(tweak.len()));
        }
        Ok(())
    }

    fn check_length(&self, n: usize) -> Result<(), Ff1Error> {
        if n < 2 {
            return Err(Ff1Error::PlaintextTooShort(n));
        }
        // NIST SP 800-38G §5.2: minlen >= 2, maxlen <= 2^32.
        if n > u32::MAX as usize {
            return Err(Ff1Error::PlaintextTooLong(n));
        }
        Ok(())
    }

    /// b = ceil(ceil(v * log2(radix)) / 8) — byte width of NUMradix(B)
    fn compute_b(&self, v: usize) -> usize {
        let bits = (v as f64 * (self.radix as f64).log2()).ceil() as usize;
        (bits + 7) / 8
    }

    /// Returns true when the u128 fast path is safe for the given max half-length.
    /// Safe when radix^m < 2^128, i.e. m <= floor(128 / log2(radix)).
    fn fits_u128(&self, m: usize) -> bool {
        let log2_radix = (self.radix as f64).log2();
        (m as f64) * log2_radix < 128.0
    }

    /// CBC-MAC over `data` (must be a multiple of 16 bytes), zero IV.
    fn prf(&self, data: &[u8]) -> [u8; 16] {
        debug_assert!(data.len() % 16 == 0);
        let mut r = [0u8; 16];
        for chunk in data.chunks_exact(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = r[i] ^ chunk[i];
            }
            r = aes_ecb(&self.key, &block);
        }
        r
    }

    /// Compute y = NUM(S[0..d]) for one Feistel round.
    ///
    /// Builds PQ = P || T || 0^pad || [i]_1 || num_half_bytes, runs PRF+AES
    /// to get S, and returns NUM(S[0..d]) as a u128.
    ///
    /// y always fits in u128: S is at most 16 bytes (one AES block), so
    /// NUM(S) <= 2^128 - 1 regardless of radix or plaintext length.
    fn compute_y(
        &self,
        p_block: &[u8; 16],
        pq: &mut Vec<u8>,
        tweak: &[u8],
        blen: usize,
        d: usize,
        i: usize,
        num_half_bytes: &[u8], // exactly blen bytes, big-endian
    ) -> u128 {
        let t = tweak.len();
        let pad_len = (-(t as isize) - blen as isize - 1).rem_euclid(16) as usize;

        pq.clear();
        pq.extend_from_slice(p_block);
        pq.extend_from_slice(tweak);
        pq.extend(std::iter::repeat(0u8).take(pad_len));
        pq.push(i as u8);
        pq.extend_from_slice(num_half_bytes);

        let rem = pq.len() % 16;
        if rem != 0 {
            pq.extend(std::iter::repeat(0u8).take(16 - rem));
        }

        let r_block = self.prf(pq);

        // S = R || AES(R xor [j]_4) || …  — take first d bytes
        let mut s_bytes = [0u8; 32];
        s_bytes[..16].copy_from_slice(&r_block);
        let num_extra = (d + 15) / 16 - 1;
        for j in 1..=num_extra {
            let mut xored = r_block;
            xored[12] ^= ((j >> 24) & 0xFF) as u8;
            xored[13] ^= ((j >> 16) & 0xFF) as u8;
            xored[14] ^= ((j >> 8) & 0xFF) as u8;
            xored[15] ^= (j & 0xFF) as u8;
            s_bytes[16..32].copy_from_slice(&aes_ecb(&self.key, &xored));
        }

        // NUM(S[0..d]): d <= 16 always, so right-shift away unused low bytes.
        if d <= 16 {
            let shift = (16 - d) * 8;
            u128::from_be_bytes(s_bytes[..16].try_into().unwrap()) >> shift
        } else {
            u128::from_be_bytes(s_bytes[..16].try_into().unwrap())
        }
    }

    pub fn encrypt(&self, plaintext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        self.check_length(plaintext.len())?;
        for &s in plaintext {
            if s >= self.radix {
                return Err(Ff1Error::SymbolOutOfRange(s));
            }
        }
        Ok(self.cipher_core(plaintext, tweak, true))
    }

    pub fn decrypt(&self, ciphertext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        self.check_length(ciphertext.len())?;
        for &s in ciphertext {
            if s >= self.radix {
                return Err(Ff1Error::SymbolOutOfRange(s));
            }
        }
        Ok(self.cipher_core(ciphertext, tweak, false))
    }

    fn cipher_core(&self, x: &[u32], tweak: &[u8], encrypt: bool) -> Vec<u32> {
        let n = x.len();
        let u = n / 2; // floor(n/2) per NIST SP 800-38G §6 Algorithm 7 Step 1
        let v = n - u;

        let mut a: Vec<u32> = x[..u].to_vec();
        let mut b: Vec<u32> = x[u..].to_vec();

        let blen = self.compute_b(v);
        let d = 4 * ((blen + 3) / 4) + 4;
        let t = tweak.len();

        // P header (NIST Algorithm 7 Step 2)
        let r = self.radix;
        let p_block: [u8; 16] = [
            0x01,
            0x02,
            0x01,
            ((r >> 16) & 0xFF) as u8,
            ((r >> 8) & 0xFF) as u8,
            (r & 0xFF) as u8,
            0x0A,
            (u & 0xFF) as u8,
            ((n >> 24) & 0xFF) as u8,
            ((n >> 16) & 0xFF) as u8,
            ((n >> 8) & 0xFF) as u8,
            (n & 0xFF) as u8,
            ((t >> 24) & 0xFF) as u8,
            ((t >> 16) & 0xFF) as u8,
            ((t >> 8) & 0xFF) as u8,
            (t & 0xFF) as u8,
        ];

        // PQ buffer reused each round
        let pq_max = 16 + t + 15 + 1 + blen;
        let mut pq: Vec<u8> = Vec::with_capacity((pq_max + 15) & !15);

        let iter_range: Vec<usize> = if encrypt {
            (0..10).collect()
        } else {
            (0..10).rev().collect()
        };

        // Choose arithmetic path once based on whether radix^max(u,v) fits u128.
        if self.fits_u128(u.max(v)) {
            // ---- Fast path: pure u128 ----
            let radix = self.radix as u128;

            // b-byte mask: clamps NUMradix to blen bytes (needed when B
            // temporarily holds u > v digits on odd-n even rounds).
            let b_mask: u128 = if blen >= 16 {
                u128::MAX
            } else {
                (1u128 << (blen * 8)) - 1
            };

            for &i in iter_range.iter() {
                let m = if i % 2 == 0 { u } else { v };
                let modulus = pow_u128(radix, m);

                let half = if encrypt { &b } else { &a };
                let num_half = num_radix_u128(radix, half) & b_mask;
                let num_half_be = num_half.to_be_bytes();
                let num_half_bytes = &num_half_be[16 - blen..];

                let y = self.compute_y(&p_block, &mut pq, tweak, blen, d, i, num_half_bytes);

                if encrypt {
                    let num_a = num_radix_u128(radix, &a);
                    let c = (num_a + y % modulus) % modulus;
                    a = std::mem::replace(&mut b, str_m_radix_u128(radix, m, c));
                } else {
                    let num_b = num_radix_u128(radix, &b);
                    let y_mod = y % modulus;
                    let c = if num_b >= y_mod {
                        num_b - y_mod
                    } else {
                        modulus - (y_mod - num_b)
                    };
                    b = std::mem::replace(&mut a, str_m_radix_u128(radix, m, c));
                }
            }
        } else {
            // ---- BigUint path ----
            let radix = BigUint::from(self.radix);

            for &i in iter_range.iter() {
                let m = if i % 2 == 0 { u } else { v };
                let modulus = radix.pow(m as u32);

                let half = if encrypt { &b } else { &a };
                let num_half = num_radix_big(&radix, half);
                let num_half_bytes = biguint_to_be_bytes_fixed(&num_half, blen);

                let y_u128 = self.compute_y(&p_block, &mut pq, tweak, blen, d, i, &num_half_bytes);
                let y = BigUint::from(y_u128);

                if encrypt {
                    let num_a = num_radix_big(&radix, &a);
                    let c = (num_a + y % &modulus) % &modulus;
                    a = std::mem::replace(&mut b, str_m_radix_big(&radix, m, c));
                } else {
                    let num_b = num_radix_big(&radix, &b);
                    let y_mod = y % &modulus;
                    let c = if num_b >= y_mod {
                        num_b - y_mod
                    } else {
                        &modulus - (y_mod - num_b)
                    };
                    b = std::mem::replace(&mut a, str_m_radix_big(&radix, m, c));
                }
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    pub fn encrypt_str(
        &self,
        plaintext: &str,
        tweak: &[u8],
        alphabet: &str,
    ) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = plaintext
            .chars()
            .map(|c| {
                chars
                    .iter()
                    .position(|&a| a == c)
                    .map(|i| i as u32)
                    .ok_or(Ff1Error::SymbolOutOfRange(c as u32))
            })
            .collect();
        let enc = self.encrypt(&symbols?, tweak)?;
        Ok(enc.iter().map(|&i| chars[i as usize]).collect())
    }

    pub fn decrypt_str(
        &self,
        ciphertext: &str,
        tweak: &[u8],
        alphabet: &str,
    ) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = ciphertext
            .chars()
            .map(|c| {
                chars
                    .iter()
                    .position(|&a| a == c)
                    .map(|i| i as u32)
                    .ok_or(Ff1Error::SymbolOutOfRange(c as u32))
            })
            .collect();
        let dec = self.decrypt(&symbols?, tweak)?;
        Ok(dec.iter().map(|&i| chars[i as usize]).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn digits(s: &str) -> Vec<u32> {
        s.chars().map(|c| c.to_digit(10).unwrap()).collect()
    }

    fn digit_str(v: &[u32]) -> String {
        v.iter()
            .map(|d| char::from_digit(*d, 10).unwrap())
            .collect()
    }

    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    fn r36_str(v: &[u32]) -> String {
        v.iter()
            .map(|&d| ALPHA36.chars().nth(d as usize).unwrap())
            .collect()
    }

    // -------------------------------------------------------------------------
    // NIST samples 1–3: AES-128
    // -------------------------------------------------------------------------

    #[test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample1 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample1 decrypt");
    }

    #[test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![6, 1, 2, 4, 2, 0, 0, 7, 7, 3];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample2 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample2 decrypt");
    }

    #[test]
    fn nist_sample3_aes128_radix36_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![
            10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample3 encrypt");
        assert_eq!(
            r36_str(&ct),
            "a9tv40mll9kdu509eum",
            "sample3 encrypt string"
        );
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample3 decrypt");
    }

    // -------------------------------------------------------------------------
    // NIST samples 4–6: AES-192
    // -------------------------------------------------------------------------

    #[test]
    fn nist_sample4_aes192_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 8, 3, 0, 6, 6, 8, 1, 3, 2];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample4 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample4 decrypt");
    }

    #[test]
    fn nist_sample5_aes192_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 4, 9, 6, 6, 5, 5, 5, 4, 9];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample5 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample5 decrypt");
    }

    #[test]
    fn nist_sample6_aes192_radix36_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![
            33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample6 encrypt");
        assert_eq!(
            r36_str(&ct),
            "xbj3kv35jrawxv32ysr",
            "sample6 encrypt string"
        );
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample6 decrypt");
    }

    // -------------------------------------------------------------------------
    // NIST samples 7–9: AES-256
    // -------------------------------------------------------------------------

    #[test]
    fn nist_sample7_aes256_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![6, 6, 5, 7, 6, 6, 7, 0, 0, 9];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample7 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample7 decrypt");
    }

    #[test]
    fn nist_sample8_aes256_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![1, 0, 0, 1, 6, 2, 3, 4, 6, 3];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample8 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample8 decrypt");
    }

    #[test]
    fn nist_sample9_aes256_radix36_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample9 encrypt");
        assert_eq!(
            r36_str(&ct),
            "xs8a0azh2avyalyzuwd",
            "sample9 encrypt string"
        );
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample9 decrypt");
    }

    // -------------------------------------------------------------------------
    // CapitalOne TestLong: AES-256, radix 36, 128 symbols, no tweak.
    // Ported from https://github.com/capitalone/fpe/blob/master/ff1/ff1_test.go
    // The original is a round-trip test only — no expected ciphertext is given.
    // This exercises the BigUint path (radix^64 overflows u128).
    // -------------------------------------------------------------------------

    #[test]
    fn capitalone_long_aes256_radix36_round_trip() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        // plaintext = "xs8a0azh2avyalyzuwd" repeated, truncated to 128 chars
        // (same string used in TestLong and BenchmarkEncryptLong)
        let pt_str = "xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyal";
        let pt: Vec<u32> = pt_str
            .chars()
            .map(|c| ALPHA36.find(c).unwrap() as u32)
            .collect();
        assert_eq!(pt.len(), 128);

        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();

        // ciphertext must be a valid radix-36 string of the same length
        assert_eq!(ct.len(), 128);
        assert!(ct.iter().all(|&d| d < 36));

        // decrypt must recover the original plaintext
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    // -------------------------------------------------------------------------
    // BigUint path boundary and coverage tests
    // -------------------------------------------------------------------------

    #[test]
    fn bigint_boundary_first_crossover_n49_radix36() {
        // n=49 is the first radix-36 length that requires BigUint:
        // max(u,v) = 25, and 25 * log2(36) = 129.25 bits > 128.
        // n=48 (u=v=24, 124 bits) still fits u128; this is the crossover.
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = (0..49).map(|i| i % 36).collect();
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct.len(), 49);
        assert!(ct.iter().all(|&d| d < 36));
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn bigint_odd_length_n127_radix36() {
        // Odd n gives u=63, v=64, so even rounds use m=63 and odd rounds m=64.
        // This exercises both modulus sizes and asymmetric biguint_to_be_bytes_fixed
        // serialization on the BigInt path — not covered by the even-n=128 test.
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = (0..127).map(|i| i % 36).collect();
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct.len(), 127);
        assert!(ct.iter().all(|&d| d < 36));
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn bigint_with_tweak_n128_radix36() {
        // All BigInt tests so far use an empty tweak. Verify the tweak bytes
        // are correctly included in PQ on the BigInt path.
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = (0..128).map(|i| i % 36).collect();
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct_with = c.encrypt(&pt, &tweak).unwrap();
        let ct_without = c.encrypt(&pt, &[]).unwrap();
        // tweak must change the output
        assert_ne!(ct_with, ct_without);
        assert_eq!(ct_with.len(), 128);
        assert!(ct_with.iter().all(|&d| d < 36));
        assert_eq!(c.decrypt(&ct_with, &tweak).unwrap(), pt);
    }

    #[test]
    fn minimum_length_n2_radix10() {
        // n=2 is the minimum permitted length. Exercises the edge of the Feistel
        // where u=1, v=1, and each half is a single symbol.
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        for first in 0u32..10 {
            for second in 0u32..10 {
                let pt = vec![first, second];
                let ct = c.encrypt(&pt, &[]).unwrap();
                assert_eq!(ct.len(), 2);
                assert!(ct.iter().all(|&d| d < 10));
                assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Zcash test vectors — radix 2, AES-256
    // -------------------------------------------------------------------------

    #[test]
    fn zcash_1_aes256_radix2_all_zeros_88bits() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![0u32; 88];
        let expected: Vec<u32> = vec![
            0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1,
            1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
            1,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_1 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "zcash_1 decrypt");
    }

    #[test]
    fn zcash_2_aes256_radix2_chained_88bits() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![
            0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1,
            1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
            1,
        ];
        let expected: Vec<u32> = vec![
            1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
            1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0,
            1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0,
            0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_2 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "zcash_2 decrypt");
    }

    #[test]
    fn zcash_3_aes256_radix2_alternating_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect();
        let expected: Vec<u32> = vec![
            0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0,
            1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
            1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1,
            0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_3 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "zcash_3 decrypt");
    }

    #[test]
    fn zcash_4_aes256_radix2_alternating_long_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak: Vec<u8> = (0u8..=254).collect();
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect();
        let expected: Vec<u32> = vec![
            0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
            0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1,
            1,
        ];
        let c = Ff1Cipher::new(&key, 2, 256).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "zcash_4 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "zcash_4 decrypt");
    }

    #[test]
    fn specific_aes256_zero_key_radix2_32bits() {
        let key = vec![0u8; 32];
        let pt: Vec<u32> = vec![0u32; 32];
        let expected: Vec<u32> = vec![
            1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
            0, 0, 0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zero-key encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "zero-key decrypt");
    }

    // -------------------------------------------------------------------------
    // Error / validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn error_bad_key_length() {
        assert_eq!(
            Ff1Cipher::new_default(&[0u8; 15], 10),
            Err(Ff1Error::InvalidKeyLength(15))
        );
    }

    #[test]
    fn error_tweak_too_long() {
        let c = Ff1Cipher::new(&[0u8; 16], 10, 8).unwrap();
        assert_eq!(
            c.encrypt(&digits("0123456789"), &[0u8; 9]),
            Err(Ff1Error::TweakTooLong(9))
        );
    }

    #[test]
    fn error_plaintext_too_short() {
        let c = Ff1Cipher::new_default(&[0u8; 16], 10).unwrap();
        assert_eq!(c.encrypt(&[0], &[]), Err(Ff1Error::PlaintextTooShort(1)));
    }

    #[test]
    fn error_symbol_out_of_range() {
        let c = Ff1Cipher::new_default(&[0u8; 16], 10).unwrap();
        assert_eq!(
            c.encrypt(&[0, 1, 10, 3], &[]),
            Err(Ff1Error::SymbolOutOfRange(10))
        );
    }

    #[test]
    fn error_invalid_radix() {
        assert_eq!(
            Ff1Cipher::new_default(&[0u8; 16], 1),
            Err(Ff1Error::InvalidRadix(1))
        );
    }

    // -------------------------------------------------------------------------
    // Round-trip smoke tests
    // -------------------------------------------------------------------------

    #[test]
    fn round_trip_radix2() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt = vec![1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert!(ct.iter().all(|&b| b < 2));
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn tweak_changes_output() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt = digits("0123456789");
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_ne!(
            c.encrypt(&pt, b"tweak1").unwrap(),
            c.encrypt(&pt, b"tweak2").unwrap()
        );
    }

    #[test]
    fn deterministic() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt = digits("0123456789");
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, b"t").unwrap(), c.encrypt(&pt, b"t").unwrap());
    }

    #[test]
    fn empty_tweak_differs_from_nonempty() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt = digits("0123456789");
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_ne!(c.encrypt(&pt, &[]).unwrap(), c.encrypt(&pt, b"t").unwrap());
    }
}
