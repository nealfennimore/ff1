// FF1 Format-Preserving Encryption
// Implements NIST SP 800-38G
//
// Performance optimisations over the original:
//   1. AES key schedule expanded once in Ff1Cipher::new, not per AES call
//   2. iter_range Vec allocation eliminated — direct loop over range
//   3. encrypt_str/decrypt_str use a HashMap for O(1) symbol lookup
//   4. pq zero-padding uses resize() instead of extend(repeat())
//   5. str_m_radix writes into an existing Vec to avoid per-round allocation
//   6. a/b Vecs pre-allocated and reused across Feistel rounds

#[cfg(target_arch = "wasm32")]
pub mod wasm;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use num_traits::identities::Zero;
use std::collections::HashMap;
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
// Pre-expanded AES cipher — key schedule computed once at construction
// ---------------------------------------------------------------------------

enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesCipher {
    fn new(key: &[u8]) -> Result<Self, Ff1Error> {
        match key.len() {
            16 => Ok(AesCipher::Aes128(Aes128::new_from_slice(key).unwrap())),
            24 => Ok(AesCipher::Aes192(Aes192::new_from_slice(key).unwrap())),
            32 => Ok(AesCipher::Aes256(Aes256::new_from_slice(key).unwrap())),
            n => Err(Ff1Error::InvalidKeyLength(n)),
        }
    }

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let b = aes::Block::from_mut_slice(block);
        match self {
            AesCipher::Aes128(c) => c.encrypt_block(b),
            AesCipher::Aes192(c) => c.encrypt_block(b),
            AesCipher::Aes256(c) => c.encrypt_block(b),
        }
    }
}

// ---------------------------------------------------------------------------
// u128 arithmetic helpers (fast path)
// ---------------------------------------------------------------------------

#[inline]
fn num_radix_u128(radix: u128, x: &[u32]) -> u128 {
    x.iter().fold(0u128, |acc, &d| acc * radix + d as u128)
}

/// Writes the base-radix representation of `x` into `out`, resizing to `m`.
/// Reuses the existing allocation to avoid a Vec allocation per Feistel round.
#[inline]
fn fill_str_m_radix_u128(radix: u128, out: &mut Vec<u32>, m: usize, mut x: u128) {
    out.resize(m, 0);
    for i in (0..m).rev() {
        out[i] = (x % radix) as u32;
        x /= radix;
    }
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
fn fill_str_m_radix_big(radix: &BigUint, out: &mut Vec<u32>, m: usize, mut x: BigUint) {
    out.resize(m, 0);
    for i in (0..m).rev() {
        let rem = &x % radix;
        out[i] = rem.to_u32().expect("radix <= 65536, digit always fits u32");
        x /= radix;
    }
}

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

pub struct Ff1Cipher {
    /// Pre-expanded AES cipher — key schedule computed once, reused every call
    cipher: AesCipher,
    /// Raw key bytes retained for the key field (needed by key() accessor and
    /// for equality checks if required by callers)
    key: Vec<u8>,
    radix: u32,
    max_tlen: usize,
}

impl fmt::Debug for Ff1Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ff1Cipher")
            .field("radix", &self.radix)
            .field("max_tlen", &self.max_tlen)
            .finish()
    }
}

impl PartialEq for Ff1Cipher {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.radix == other.radix && self.max_tlen == other.max_tlen
    }
}

impl Ff1Cipher {
    pub fn new(key: &[u8], radix: u32, max_tlen: usize) -> Result<Self, Ff1Error> {
        if radix < 2 || radix > 65536 {
            return Err(Ff1Error::InvalidRadix(radix));
        }
        let cipher = AesCipher::new(key)?;
        Ok(Ff1Cipher {
            cipher,
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
        if n > u32::MAX as usize {
            return Err(Ff1Error::PlaintextTooLong(n));
        }
        Ok(())
    }

    fn compute_b(&self, v: usize) -> usize {
        let bits = (v as f64 * (self.radix as f64).log2()).ceil() as usize;
        (bits + 7) / 8
    }

    fn fits_u128(&self, m: usize) -> bool {
        let log2_radix = (self.radix as f64).log2();
        (m as f64) * log2_radix < 128.0
    }

    /// CBC-MAC over `data` (must be a multiple of 16 bytes), zero IV.
    /// Uses the pre-expanded cipher — no key schedule per call.
    #[inline]
    fn prf(&self, data: &[u8]) -> [u8; 16] {
        debug_assert!(data.len() % 16 == 0);
        let mut r = [0u8; 16];
        for chunk in data.chunks_exact(16) {
            for i in 0..16 {
                r[i] ^= chunk[i];
            }
            self.cipher.encrypt_block(&mut r);
        }
        r
    }

    /// Compute y = NUM(S[0..d]) for one Feistel round.
    fn compute_y(
        &self,
        p_block: &[u8; 16],
        pq: &mut Vec<u8>,
        tweak: &[u8],
        blen: usize,
        d: usize,
        i: usize,
        num_half_bytes: &[u8],
    ) -> u128 {
        let t = tweak.len();
        let pad_len = (-(t as isize) - blen as isize - 1).rem_euclid(16) as usize;

        pq.clear();
        pq.extend_from_slice(p_block);
        pq.extend_from_slice(tweak);

        // Use resize instead of extend(repeat()) — single memset call
        let base = pq.len();
        pq.resize(base + pad_len, 0u8);

        pq.push(i as u8);
        pq.extend_from_slice(num_half_bytes);

        let rem = pq.len() % 16;
        if rem != 0 {
            let new_len = pq.len() + (16 - rem);
            pq.resize(new_len, 0u8);
        }

        let r_block = self.prf(pq);

        let mut s_bytes = [0u8; 32];
        s_bytes[..16].copy_from_slice(&r_block);

        let num_extra = (d + 15) / 16 - 1;
        for j in 1..=num_extra {
            let mut xored = r_block;
            xored[12] ^= ((j >> 24) & 0xFF) as u8;
            xored[13] ^= ((j >> 16) & 0xFF) as u8;
            xored[14] ^= ((j >> 8) & 0xFF) as u8;
            xored[15] ^= (j & 0xFF) as u8;
            self.cipher.encrypt_block(&mut xored);
            s_bytes[16..32].copy_from_slice(&xored);
        }

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
        let u = n / 2;
        let v = n - u;

        // Pre-allocate a and b — reused across all 10 rounds via fill_str_m_radix
        let mut a: Vec<u32> = x[..u].to_vec();
        let mut b: Vec<u32> = x[u..].to_vec();

        let blen = self.compute_b(v);
        let d = 4 * ((blen + 3) / 4) + 4;
        let t = tweak.len();

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

        let pq_cap = (16 + t + 15 + 1 + blen + 15) & !15;
        let mut pq: Vec<u8> = Vec::with_capacity(pq_cap);

        // Reusable scratch buffer for str_m_radix output — avoids allocation per round
        let mut scratch: Vec<u32> = Vec::with_capacity(v.max(u));

        if self.fits_u128(u.max(v)) {
            // ---- Fast path: pure u128 ----
            let radix = self.radix as u128;
            let b_mask: u128 = if blen >= 16 {
                u128::MAX
            } else {
                (1u128 << (blen * 8)) - 1
            };

            // Direct loop — no iter_range Vec allocation
            macro_rules! feistel_round {
                ($i:expr) => {{
                    let m = if $i % 2 == 0 { u } else { v };
                    let modulus = pow_u128(radix, m);

                    let half = if encrypt { &b } else { &a };
                    let num_half = num_radix_u128(radix, half) & b_mask;
                    let num_half_be = num_half.to_be_bytes();
                    let num_half_bytes = &num_half_be[16 - blen..];

                    let y = self.compute_y(&p_block, &mut pq, tweak, blen, d, $i, num_half_bytes);

                    if encrypt {
                        let num_a = num_radix_u128(radix, &a);
                        let c = (num_a + y % modulus) % modulus;
                        fill_str_m_radix_u128(radix, &mut scratch, m, c);
                        std::mem::swap(&mut a, &mut b);
                        std::mem::swap(&mut b, &mut scratch);
                    } else {
                        let num_b = num_radix_u128(radix, &b);
                        let y_mod = y % modulus;
                        let c = if num_b >= y_mod {
                            num_b - y_mod
                        } else {
                            modulus - (y_mod - num_b)
                        };
                        fill_str_m_radix_u128(radix, &mut scratch, m, c);
                        std::mem::swap(&mut b, &mut a);
                        std::mem::swap(&mut a, &mut scratch);
                    }
                }};
            }

            if encrypt {
                feistel_round!(0);
                feistel_round!(1);
                feistel_round!(2);
                feistel_round!(3);
                feistel_round!(4);
                feistel_round!(5);
                feistel_round!(6);
                feistel_round!(7);
                feistel_round!(8);
                feistel_round!(9);
            } else {
                feistel_round!(9);
                feistel_round!(8);
                feistel_round!(7);
                feistel_round!(6);
                feistel_round!(5);
                feistel_round!(4);
                feistel_round!(3);
                feistel_round!(2);
                feistel_round!(1);
                feistel_round!(0);
            }
        } else {
            // ---- BigUint path ----
            let radix = BigUint::from(self.radix);

            macro_rules! feistel_round_big {
                ($i:expr) => {{
                    let m = if $i % 2 == 0 { u } else { v };
                    let modulus = radix.pow(m as u32);

                    let half = if encrypt { &b } else { &a };
                    let num_half = num_radix_big(&radix, half);
                    let num_half_bytes = biguint_to_be_bytes_fixed(&num_half, blen);

                    let y_u128 =
                        self.compute_y(&p_block, &mut pq, tweak, blen, d, $i, &num_half_bytes);
                    let y = BigUint::from(y_u128);

                    if encrypt {
                        let num_a = num_radix_big(&radix, &a);
                        let c = (num_a + y % &modulus) % &modulus;
                        fill_str_m_radix_big(&radix, &mut scratch, m, c);
                        std::mem::swap(&mut a, &mut b);
                        std::mem::swap(&mut b, &mut scratch);
                    } else {
                        let num_b = num_radix_big(&radix, &b);
                        let y_mod = y % &modulus;
                        let c = if num_b >= y_mod {
                            num_b - y_mod
                        } else {
                            &modulus - (y_mod - num_b)
                        };
                        fill_str_m_radix_big(&radix, &mut scratch, m, c);
                        std::mem::swap(&mut b, &mut a);
                        std::mem::swap(&mut a, &mut scratch);
                    }
                }};
            }

            if encrypt {
                feistel_round_big!(0);
                feistel_round_big!(1);
                feistel_round_big!(2);
                feistel_round_big!(3);
                feistel_round_big!(4);
                feistel_round_big!(5);
                feistel_round_big!(6);
                feistel_round_big!(7);
                feistel_round_big!(8);
                feistel_round_big!(9);
            } else {
                feistel_round_big!(9);
                feistel_round_big!(8);
                feistel_round_big!(7);
                feistel_round_big!(6);
                feistel_round_big!(5);
                feistel_round_big!(4);
                feistel_round_big!(3);
                feistel_round_big!(2);
                feistel_round_big!(1);
                feistel_round_big!(0);
            }
        }

        let mut result = a;
        result.extend_from_slice(&b);
        result
    }

    /// Encrypts a string using the given alphabet.
    /// Uses a HashMap for O(1) symbol lookup instead of O(radix) linear scan.
    pub fn encrypt_str(
        &self,
        plaintext: &str,
        tweak: &[u8],
        alphabet: &str,
    ) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let char_to_idx: HashMap<char, u32> = chars
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i as u32))
            .collect();

        let symbols: Result<Vec<u32>, _> = plaintext
            .chars()
            .map(|c| {
                char_to_idx
                    .get(&c)
                    .copied()
                    .ok_or(Ff1Error::SymbolOutOfRange(c as u32))
            })
            .collect();

        let enc = self.encrypt(&symbols?, tweak)?;
        Ok(enc.iter().map(|&i| chars[i as usize]).collect())
    }

    /// Decrypts a string using the given alphabet.
    /// Uses a HashMap for O(1) symbol lookup instead of O(radix) linear scan.
    pub fn decrypt_str(
        &self,
        ciphertext: &str,
        tweak: &[u8],
        alphabet: &str,
    ) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let char_to_idx: HashMap<char, u32> = chars
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i as u32))
            .collect();

        let symbols: Result<Vec<u32>, _> = ciphertext
            .chars()
            .map(|c| {
                char_to_idx
                    .get(&c)
                    .copied()
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

    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    fn r36_str(v: &[u32]) -> String {
        v.iter()
            .map(|&d| ALPHA36.chars().nth(d as usize).unwrap())
            .collect()
    }

    #[test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample1 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample1 decrypt");
    }

    #[test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433323130");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![6, 1, 2, 4, 2, 0, 0, 7, 7, 3];
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
        let expected = vec![
            10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(r36_str(&ct), "a9tv40mll9kdu509eum");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_sample4_aes192_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![2, 8, 3, 0, 6, 6, 8, 1, 3, 2];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, &[]).unwrap(), expected);
        assert_eq!(c.decrypt(&expected, &[]).unwrap(), pt);
    }

    #[test]
    fn nist_sample5_aes192_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("39383736353433323130");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![2, 4, 9, 6, 6, 5, 5, 5, 4, 9];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, &tweak).unwrap(), expected);
        assert_eq!(c.decrypt(&expected, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_sample6_aes192_radix36_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected = vec![
            33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(r36_str(&ct), "xbj3kv35jrawxv32ysr");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_sample7_aes256_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![6, 6, 5, 7, 6, 6, 7, 0, 0, 9];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, &[]).unwrap(), expected);
        assert_eq!(c.decrypt(&expected, &[]).unwrap(), pt);
    }

    #[test]
    fn nist_sample8_aes256_radix10_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected = vec![1, 0, 0, 1, 6, 2, 3, 4, 6, 3];
        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, &tweak).unwrap(), expected);
        assert_eq!(c.decrypt(&expected, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_sample9_aes256_radix36_with_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected = vec![
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
        ];
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(r36_str(&ct), "xs8a0azh2avyalyzuwd");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn capitalone_long_aes256_radix36_round_trip() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt_str = "xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyal";
        let pt: Vec<u32> = pt_str
            .chars()
            .map(|c| ALPHA36.find(c).unwrap() as u32)
            .collect();
        assert_eq!(pt.len(), 128);
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct.len(), 128);
        assert!(ct.iter().all(|&d| d < 36));
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn bigint_boundary_first_crossover_n49_radix36() {
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
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = (0..128).map(|i| i % 36).collect();
        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct_with = c.encrypt(&pt, &tweak).unwrap();
        let ct_none = c.encrypt(&pt, &[]).unwrap();
        assert_ne!(ct_with, ct_none);
        assert_eq!(ct_with.len(), 128);
        assert!(ct_with.iter().all(|&d| d < 36));
        assert_eq!(c.decrypt(&ct_with, &tweak).unwrap(), pt);
    }

    #[test]
    fn minimum_length_n2_radix10() {
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

    #[test]
    fn zcash_1_aes256_radix2_all_zeros_88bits() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt = vec![0u32; 88];
        let expected = vec![
            0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1,
            1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
            1,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn zcash_2_aes256_radix2_chained_88bits() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt = vec![
            0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1,
            1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1,
            1,
        ];
        let expected = vec![
            1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0,
            1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0,
            1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0,
            0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn zcash_3_aes256_radix2_alternating_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect();
        let expected = vec![
            0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0,
            1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
            1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1,
            0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn zcash_4_aes256_radix2_alternating_long_tweak() {
        let key: Vec<u8> =
            hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak: Vec<u8> = (0u8..=254).collect();
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect();
        let expected = vec![
            0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
            0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1,
            1,
        ];
        let c = Ff1Cipher::new(&key, 2, 256).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn specific_aes256_zero_key_radix2_32bits() {
        let key = vec![0u8; 32];
        let pt = vec![0u32; 32];
        let expected = vec![
            1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
            0, 0, 0,
        ];
        let c = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected);
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

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
