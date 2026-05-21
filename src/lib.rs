// FF1 Format-Preserving Encryption
// Implements NIST SP 800-38G
//
// All arithmetic uses u128. Safe because:
//   - The NIST spec requires radix^n < 2^96 (enforced by check_length)
//   - NUMradix values are therefore < 2^96
//   - y = NUM(S) where S is at most 16 bytes: fits in u128 exactly
//   - We always compute y % modulus before adding, keeping sums < 2^97

// WASM bindings — only compiled when targeting wasm32
#[cfg(target_arch = "wasm32")]
pub mod wasm;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use std::fmt;

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
            Ff1Error::InvalidKeyLength(n) =>
                write!(f, "Invalid key length: {} bytes (must be 16, 24, or 32)", n),
            Ff1Error::TweakTooLong(n) =>
                write!(f, "Tweak too long: {} bytes", n),
            Ff1Error::InvalidRadix(r) =>
                write!(f, "Invalid radix: {} (must be 2..=65536)", r),
            Ff1Error::PlaintextTooShort(n) =>
                write!(f, "Plaintext too short: {} symbols (minimum 2)", n),
            Ff1Error::PlaintextTooLong(n) =>
                write!(f, "Plaintext too long: {} symbols", n),
            Ff1Error::SymbolOutOfRange(s) =>
                write!(f, "Symbol value {} is out of range for radix", s),
        }
    }
}

// Plain AES-ECB single block encrypt (no key/block reversal — FF1 uses standard AES)
fn aes_ecb(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    match key.len() {
        16 => { let c = Aes128::new_from_slice(key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        24 => { let c = Aes192::new_from_slice(key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        32 => { let c = Aes256::new_from_slice(key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        _  => panic!("Unexpected key length"),
    }
    out
}

#[inline]
fn num_radix(radix: u128, x: &[u32]) -> u128 {
    x.iter().fold(0u128, |acc, &d| acc * radix + d as u128)
}

#[inline]
fn str_m_radix(radix: u128, m: usize, mut x: u128) -> Vec<u32> {
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
        if radix < 2 || radix > 65536 { return Err(Ff1Error::InvalidRadix(radix)); }
        Ok(Ff1Cipher { key: key.to_vec(), radix, max_tlen })
    }

    pub fn new_default(key: &[u8], radix: u32) -> Result<Self, Ff1Error> {
        Self::new(key, radix, 256)
    }

    fn check_tweak(&self, tweak: &[u8]) -> Result<(), Ff1Error> {
        if tweak.len() > self.max_tlen { return Err(Ff1Error::TweakTooLong(tweak.len())); }
        Ok(())
    }

    fn check_length(&self, n: usize) -> Result<(), Ff1Error> {
        if n < 2 { return Err(Ff1Error::PlaintextTooShort(n)); }
        let max_len = 2 * ((96.0_f64 * 2.0_f64.ln()) / (self.radix as f64).ln()).floor() as usize;
        if n > max_len { return Err(Ff1Error::PlaintextTooLong(n)); }
        Ok(())
    }

    /// b = ceil(ceil(v * log2(radix)) / 8) — byte width of NUMradix(B)
    fn compute_b(&self, v: usize) -> usize {
        let bits = (v as f64 * (self.radix as f64).log2()).ceil() as usize;
        (bits + 7) / 8
    }

    /// CBC-MAC over `data` (must be a multiple of 16 bytes), zero IV.
    fn prf(&self, data: &[u8]) -> [u8; 16] {
        debug_assert!(data.len() % 16 == 0);
        let mut r = [0u8; 16];
        for chunk in data.chunks_exact(16) {
            let mut block = [0u8; 16];
            for i in 0..16 { block[i] = r[i] ^ chunk[i]; }
            r = aes_ecb(&self.key, &block);
        }
        r
    }

    pub fn encrypt(&self, plaintext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        self.check_length(plaintext.len())?;
        for &s in plaintext { if s >= self.radix { return Err(Ff1Error::SymbolOutOfRange(s)); } }
        Ok(self.cipher_core(plaintext, tweak, true))
    }

    pub fn decrypt(&self, ciphertext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        self.check_length(ciphertext.len())?;
        for &s in ciphertext { if s >= self.radix { return Err(Ff1Error::SymbolOutOfRange(s)); } }
        Ok(self.cipher_core(ciphertext, tweak, false))
    }

    fn cipher_core(&self, x: &[u32], tweak: &[u8], encrypt: bool) -> Vec<u32> {
        let n = x.len();
        let u = n / 2;
        let v = n - u;
        let radix = self.radix as u128;

        let mut a: Vec<u32> = x[..u].to_vec();
        let mut b: Vec<u32> = x[u..].to_vec();

        let blen  = self.compute_b(v);
        let d     = 4 * ((blen + 3) / 4) + 4;
        let t     = tweak.len();

        // b-byte mask for NUMradix(B) when B temporarily holds u > v digits
        // (occurs for odd n after even rounds). Guaranteed < 2^96 < u128::MAX.
        let b_mask: u128 = if blen >= 16 {
            u128::MAX
        } else {
            (1u128 << (blen * 8)) - 1
        };

        // Fixed 16-byte P header (NIST Algorithm 7 step 2)
        let r = self.radix;
        let p_block: [u8; 16] = [
            0x01, 0x02, 0x01,
            ((r >> 16) & 0xFF) as u8, ((r >> 8) & 0xFF) as u8, (r & 0xFF) as u8,
            0x0A,
            (u & 0xFF) as u8,
            ((n >> 24) & 0xFF) as u8, ((n >> 16) & 0xFF) as u8,
            ((n >>  8) & 0xFF) as u8, (n & 0xFF) as u8,
            ((t >> 24) & 0xFF) as u8, ((t >> 16) & 0xFF) as u8,
            ((t >>  8) & 0xFF) as u8, (t & 0xFF) as u8,
        ];

        // Pre-allocate PQ buffer (reused each round). Max size: 16 + t + 15 + 1 + 16
        let pq_max = 16 + t + 15 + 1 + blen;
        let pq_cap = (pq_max + 15) & !15; // round up to multiple of 16
        let mut pq: Vec<u8> = Vec::with_capacity(pq_cap);

        let iter_range: &[usize] = &if encrypt {
            (0..10usize).collect::<Vec<_>>()
        } else {
            (0..10usize).rev().collect::<Vec<_>>()
        };

        for &i in iter_range {
            let m = if i % 2 == 0 { u } else { v };
            let modulus = pow_u128(radix, m);

            // NUMradix of the "other" half, masked to blen bytes
            let half = if encrypt { &b } else { &a };
            let num_half = num_radix(radix, half) & b_mask;

            // Build Q = T || 0^pad || [i]_1 || num_half (blen bytes)
            let pad_len = (-(t as isize) - blen as isize - 1).rem_euclid(16) as usize;

            pq.clear();
            pq.extend_from_slice(&p_block);
            pq.extend_from_slice(tweak);
            pq.extend(std::iter::repeat(0u8).take(pad_len));
            pq.push(i as u8);
            // Pack num_half into exactly blen bytes (big-endian, right-aligned)
            let be16 = num_half.to_be_bytes(); // 16 bytes
            pq.extend_from_slice(&be16[16 - blen..]);

            // Pad PQ to multiple of 16
            let rem = pq.len() % 16;
            if rem != 0 { pq.extend(std::iter::repeat(0u8).take(16 - rem)); }

            // R = PRF(PQ)
            let r_block = self.prf(&pq);

            // S = R || AES(R ^ [1]) || ... truncated to d bytes
            // d is at most 16 (one extra block needed only when b > 12, which
            // requires radix=2 and very long inputs — still fits fine)
            let mut s_bytes = [0u8; 32]; // max d is 16 for all practical inputs
            s_bytes[..16].copy_from_slice(&r_block);

            let num_extra = (d + 15) / 16 - 1;
            for j in 1..=num_extra {
                let mut xored = r_block;
                xored[12] ^= ((j >> 24) & 0xFF) as u8;
                xored[13] ^= ((j >> 16) & 0xFF) as u8;
                xored[14] ^= ((j >>  8) & 0xFF) as u8;
                xored[15] ^=  (j        & 0xFF) as u8;
                let extra = aes_ecb(&self.key, &xored);
                s_bytes[16..32].copy_from_slice(&extra);
            }

            // y = NUM(S[0..d]) as u128
            // d <= 16 always for inputs that pass check_length, so we use the
            // first 16 bytes and right-shift away any excess.
            let y = if d <= 16 {
                let shift = (16 - d) * 8;
                u128::from_be_bytes(s_bytes[0..16].try_into().unwrap()) >> shift
            } else {
                // d == 16: use all 16 bytes directly (u128::MAX at most)
                u128::from_be_bytes(s_bytes[0..16].try_into().unwrap())
            };

            // Feistel step
            if encrypt {
                let num_a = num_radix(radix, &a);
                let c = (num_a + y % modulus) % modulus;
                a = b;
                b = str_m_radix(radix, m, c);
            } else {
                let num_b = num_radix(radix, &b);
                let y_mod = y % modulus;
                let c = if num_b >= y_mod { num_b - y_mod } else { modulus - (y_mod - num_b) };
                b = a;
                a = str_m_radix(radix, m, c);
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    pub fn encrypt_str(&self, plaintext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = plaintext.chars()
            .map(|c| chars.iter().position(|&a| a == c).map(|i| i as u32).ok_or(Ff1Error::SymbolOutOfRange(c as u32)))
            .collect();
        let enc = self.encrypt(&symbols?, tweak)?;
        Ok(enc.iter().map(|&i| chars[i as usize]).collect())
    }

    pub fn decrypt_str(&self, ciphertext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = ciphertext.chars()
            .map(|c| chars.iter().position(|&a| a == c).map(|i| i as u32).ok_or(Ff1Error::SymbolOutOfRange(c as u32)))
            .collect();
        let dec = self.decrypt(&symbols?, tweak)?;
        Ok(dec.iter().map(|&i| chars[i as usize]).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Convert a decimal-digit string into a symbol vector (radix-10).
    fn digits(s: &str) -> Vec<u32> {
        s.chars().map(|c| c.to_digit(10).unwrap()).collect()
    }

    /// Turn a symbol vector back into a decimal-digit string (radix-10).
    fn digit_str(v: &[u32]) -> String {
        v.iter()
            .map(|d| char::from_digit(*d, 10).unwrap())
            .collect()
    }

    // Alphabet for radix-36 ("0-9 a-z")
    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    /// Map a radix-36 symbol vector to its string representation.
    fn r36_str(v: &[u32]) -> String {
        v.iter()
            .map(|&d| ALPHA36.chars().nth(d as usize).unwrap())
            .collect()
    }

    #[test]
    fn round_trip_radix2() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = vec![1,0,1,0,1,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1];
        let c   = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct  = c.encrypt(&pt, &[]).unwrap();
        assert!(ct.iter().all(|&b| b < 2));
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt);
    }

    #[test]
    fn round_trip_ssn() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt    = digits("123456789");
        let c     = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, b"ssn-tweak").unwrap();
        assert_eq!(ct.len(), 9);
        assert!(ct.iter().all(|&d| d < 10));
        assert_eq!(c.decrypt(&ct, b"ssn-tweak").unwrap(), pt);
    }

    #[test]
    fn round_trip_credit_card() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("4111111111111111");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct  = c.encrypt(&pt, b"merchant").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(c.decrypt(&ct, b"merchant").unwrap(), pt);
    }

    #[test]
    fn str_encrypt_decrypt_digits() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = "4111111111111111";
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct  = c.encrypt_str(pt, b"t", "0123456789").unwrap();
        assert_eq!(c.decrypt_str(&ct, b"t", "0123456789").unwrap(), pt);
    }

    #[test]
    fn str_encrypt_decrypt_alpha() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        let pt    = "thequickbrownfox";
        let c     = Ff1Cipher::new_default(&key, 26).unwrap();
        let ct    = c.encrypt_str(pt, b"t", alpha).unwrap();
        assert!(ct.chars().all(|ch| alpha.contains(ch)));
        assert_eq!(c.decrypt_str(&ct, b"t", alpha).unwrap(), pt);
    }

    #[test]
    fn tweak_changes_output() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_ne!(c.encrypt(&pt, b"tweak1").unwrap(), c.encrypt(&pt, b"tweak2").unwrap());
    }

    #[test]
    fn deterministic() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, b"t").unwrap(), c.encrypt(&pt, b"t").unwrap());
    }

    #[test]
    fn empty_tweak_differs_from_nonempty() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_ne!(c.encrypt(&pt, &[]).unwrap(), c.encrypt(&pt, b"t").unwrap());
    }

    #[test]
    fn error_bad_key_length() {
        assert_eq!(Ff1Cipher::new_default(&[0u8;15], 10), Err(Ff1Error::InvalidKeyLength(15)));
    }

    #[test]
    fn error_tweak_too_long() {
        let c = Ff1Cipher::new(&[0u8;16], 10, 8).unwrap();
        assert_eq!(c.encrypt(&digits("0123456789"), &[0u8;9]), Err(Ff1Error::TweakTooLong(9)));
    }

    #[test]
    fn error_plaintext_too_short() {
        let c = Ff1Cipher::new_default(&[0u8;16], 10).unwrap();
        assert_eq!(c.encrypt(&[0], &[]), Err(Ff1Error::PlaintextTooShort(1)));
    }

    #[test]
    fn error_symbol_out_of_range() {
        let c = Ff1Cipher::new_default(&[0u8;16], 10).unwrap();
        assert_eq!(c.encrypt(&[0,1,10,3], &[]), Err(Ff1Error::SymbolOutOfRange(10)));
    }

    #[test]
    fn error_invalid_radix() {
        assert_eq!(Ff1Cipher::new_default(&[0u8;16], 1), Err(Ff1Error::InvalidRadix(1)));
    }

    // ---------------------------------------------------------------------------
    // NIST SP 800-38G sample vectors
    // (source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf)
    // ---------------------------------------------------------------------------

    // --- AES-128 ---
    // -------------------------------------------------------------------------
    // NIST samples 1–3: AES-128
    // -------------------------------------------------------------------------
 
    #[test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        // CT is <2433477484>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample1 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "sample1 decrypt");
    }
 
    #[test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        // Tweak = 39 38 37 36 35 34 33 32 31 30; CT is <6124200773>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![6, 1, 2, 4, 2, 0, 0, 7, 7, 3];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample2 encrypt");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample2 decrypt");
    }
 
    #[test]
    fn nist_sample3_aes128_radix36_with_tweak() {
        // Tweak = 37 37 37 37 70 71 72 73 37 37 37; CT is <a9tv40mll9kdu509eum>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22];
 
        let cipher = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample3 encrypt");
        assert_eq!(r36_str(&ct), "a9tv40mll9kdu509eum", "sample3 encrypt string");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample3 decrypt");
    }
 
    // -------------------------------------------------------------------------
    // NIST samples 4–6: AES-192
    // -------------------------------------------------------------------------
 
    #[test]
    fn nist_sample4_aes192_radix10_no_tweak() {
        // CT is <2830668132>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 8, 3, 0, 6, 6, 8, 1, 3, 2];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample4 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "sample4 decrypt");
    }
 
    #[test]
    fn nist_sample5_aes192_radix10_with_tweak() {
        // Tweak = 39 38 37 36 35 34 33 32 31 30; CT is <2496655549>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![2, 4, 9, 6, 6, 5, 5, 5, 4, 9];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample5 encrypt");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample5 decrypt");
    }
 
    #[test]
    fn nist_sample6_aes192_radix36_with_tweak() {
        // Tweak = 37 37 37 37 70 71 72 73 37 37 37; CT is <xbj3kv35jrawxv32ysr>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27];
 
        let cipher = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample6 encrypt");
        assert_eq!(r36_str(&ct), "xbj3kv35jrawxv32ysr", "sample6 encrypt string");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample6 decrypt");
    }
 
    // -------------------------------------------------------------------------
    // NIST samples 7–9: AES-256
    // -------------------------------------------------------------------------
 
    #[test]
    fn nist_sample7_aes256_radix10_no_tweak() {
        // CT is <6657667009>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![6, 6, 5, 7, 6, 6, 7, 0, 0, 9];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "sample7 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "sample7 decrypt");
    }
 
    #[test]
    fn nist_sample8_aes256_radix10_with_tweak() {
        // Tweak = 39 38 37 36 35 34 33 32 31 30; CT is <1001623463>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected: Vec<u32> = vec![1, 0, 0, 1, 6, 2, 3, 4, 6, 3];
 
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample8 encrypt");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample8 decrypt");
    }
 
    #[test]
    fn nist_sample9_aes256_radix36_with_tweak() {
        // Tweak = 37 37 37 37 70 71 72 73 37 37 37; CT is <xs8a0azh2avyalyzuwd>
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let expected: Vec<u32> = vec![33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13];
 
        let cipher = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "sample9 encrypt");
        assert_eq!(r36_str(&ct), "xs8a0azh2avyalyzuwd", "sample9 encrypt string");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "sample9 decrypt");
    }


    // ---------------------------------------------------------------------------
    // CapitalOne long-message vector
    // (source: https://github.com/capitalone/fpe/blob/master/ff1/ff1_test.go)
    // ---------------------------------------------------------------------------

    #[test]
    fn capitalone_aes256_radix36_long_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21,
        ];
        let expected: Vec<u32> = vec![
            21, 32, 30, 21, 18, 11, 15, 25, 1, 19, 30, 3, 20, 28, 35, 29, 30, 22, 26,
            24, 22, 32, 14, 23, 25, 31, 7, 13, 30, 34, 9, 26, 7, 25, 16, 7, 35, 15, 3,
            14, 16, 3, 27, 19, 21, 15, 34, 4, 6, 16, 22, 16, 20, 26, 19, 15, 32, 31,
            27, 24, 22, 15, 19, 19, 20, 29, 22, 11, 14, 34, 8, 22, 14, 26, 20, 9, 35,
            20, 12, 22, 16, 31, 20, 31, 4, 28, 9, 21, 21, 5, 12, 29, 24, 35, 22, 14,
            1, 17, 15, 1, 5, 32, 7, 33, 24, 6, 35, 28, 34, 21, 26, 12, 27, 0, 23, 11,
            33, 9, 19, 11, 15, 1, 0, 30, 22, 35, 24, 20,
        ];

        let cipher = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "capitalone long encrypt");
        assert_eq!(
            r36_str(&ct),
            "lwulibfp1ju3ksztumqomwenpv7duy9q7pg7zf3eg3rjlfy46gmgkqjfwvromfjjktmbey8meqk9zkcmgvkv4s9ll5ctozme1hf15w7xo6zsylqcr0nbx9jbf10umzok",
            "capitalone long encrypt string"
        );
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "capitalone long decrypt");
    }

    // ---------------------------------------------------------------------------
    // Zcash test vectors — radix 2, AES-256
    // (source: https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/ff1.py)
    //
    // Each vector also carries a "binary" representation: the same bit sequence
    // packed into bytes (big-endian, MSB first). We test both the bit-array form
    // (direct encrypt/decrypt) and verify the byte interpretation in a comment.
    // ---------------------------------------------------------------------------

    #[test]
    fn zcash_1_aes256_radix2_all_zeros_88bits() {
        // 88 zero bits → known ciphertext
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![0u32; 88];
        let expected: Vec<u32> = vec![
            0,0,0,0,1,0,0,1, 0,0,1,1,0,1,0,1, 0,1,1,1,0,1,1,1, 1,1,1,1,1,1,0,0,
            1,1,0,0,0,0,0,1, 1,0,1,1,0,0,1,1, 1,1,1,0,0,1,1,1, 0,1,1,1,0,1,0,1,
            0,1,1,0,1,0,1,0, 0,1,0,0,0,1,0,0, 1,1,0,0,1,1,1,1,
        ];
        // binary equivalent: pt = [0x00;11], ct = [0x90,0xac,0xee,0x3f,0x83,0xcd,0xe7,0xae,0x56,0x22,0xf3]

        let cipher = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_1 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "zcash_1 decrypt");
    }

    #[test]
    fn zcash_2_aes256_radix2_round_trip_88bits() {
        // Encrypt the ciphertext from zcash_1 to get the next vector
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = vec![
            0,0,0,0,1,0,0,1, 0,0,1,1,0,1,0,1, 0,1,1,1,0,1,1,1, 1,1,1,1,1,1,0,0,
            1,1,0,0,0,0,0,1, 1,0,1,1,0,0,1,1, 1,1,1,0,0,1,1,1, 0,1,1,1,0,1,0,1,
            0,1,1,0,1,0,1,0, 0,1,0,0,0,1,0,0, 1,1,0,0,1,1,1,1,
        ];
        let expected: Vec<u32> = vec![
            1,1,0,1,1,0,1,0, 1,1,0,1,0,0,0,1, 1,0,0,0,1,1,1,1, 0,0,0,0,0,1,0,0,
            1,1,0,0,1,1,1,1, 1,1,0,1,1,0,0,1, 1,1,0,1,0,1,0,1, 1,0,1,0,0,0,0,1,
            1,1,1,0,0,1,0,0, 0,1,0,1,0,1,1,1, 1,1,0,1,1,0,0,0,
        ];
        // binary equivalent: pt = [0x90,0xac,0xee,0x3f,0x83,0xcd,0xe7,0xae,0x56,0x22,0xf3]
        //                    ct = [0x5b,0x8b,0xf1,0x20,0xf3,0x9b,0xab,0x85,0x27,0xea,0x1b]

        let cipher = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_2 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "zcash_2 decrypt");
    }

    #[test]
    fn zcash_3_aes256_radix2_alternating_bits_no_tweak() {
        // Alternating 0101… pattern, 88 bits, no tweak
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect(); // 0,1,0,1,...
        let expected: Vec<u32> = vec![
            0,0,0,0,1,1,1,1, 0,1,0,0,0,0,0,1, 1,1,1,0,1,1,0,1, 0,1,1,1,0,1,1,1,
            1,1,1,1,0,0,0,1, 1,0,0,1,0,1,0,0, 0,0,0,0,0,0,1,1, 0,1,1,0,1,1,1,0,
            1,0,0,0,1,0,0,1, 0,1,1,1,0,0,1,1, 0,0,1,0,0,1,1,0,
        ];
        // binary equivalent: pt = [0xaa;11], ct = [0xf0,0x82,0xb7,0xee,0x8f,0x29,0xc0,0x76,0x91,0xce,0x64]

        let cipher = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "zcash_3 encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "zcash_3 decrypt");
    }

    #[test]
    fn zcash_4_aes256_radix2_alternating_bits_long_tweak() {
        // Alternating 0101… pattern, 88 bits, tweak = [0x00, 0x01, …, 0xfe] (255 bytes)
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak: Vec<u8> = (0u8..=254).collect();
        let pt: Vec<u32> = (0..88).map(|i| i % 2).collect();
        let expected: Vec<u32> = vec![
            0,1,1,1,1,1,0,1, 1,0,0,0,1,0,0,0, 0,0,0,1,1,1,0,1, 0,1,1,0,0,0,0,1,
            0,0,0,1,0,1,0,1, 1,0,1,0,0,0,0,0, 0,0,1,1,1,0,0,1, 1,1,1,0,0,1,0,0,
            1,0,0,0,1,0,1,0, 1,1,0,1,1,1,1,0, 1,0,1,0,0,0,1,1,
        ];
        // binary equivalent: pt = [0xaa;11], ct = [0xbe,0x11,0xb8,0x86,0xa8,0x05,0x9c,0x27,0x51,0x7b,0xc5]

        let cipher = Ff1Cipher::new(&key, 2, 256).unwrap();
        let ct = cipher.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct, expected, "zcash_4 encrypt");
        assert_eq!(cipher.decrypt(&ct, &tweak).unwrap(), pt, "zcash_4 decrypt");
    }

    // ---------------------------------------------------------------------------
    // Additional specific test case — all-zero key, radix 2, 32-bit message
    // ---------------------------------------------------------------------------

    #[test]
    fn specific_aes256_zero_key_radix2_32bits() {
        // AES-256 all-zero key, 32 zero bits → known ciphertext
        let key = vec![0u8; 32];
        let pt: Vec<u32> = vec![0u32; 32];
        let expected: Vec<u32> = vec![
            1,1,0,1,1,1,1,0, 1,0,0,1,1,1,1,1, 0,0,1,0,0,0,0,0, 1,1,0,1,1,0,0,0,
        ];
        // binary equivalent: pt = [0x00,0x00,0x00,0x00], ct = [0x7b,0xf9,0x04,0x1b]

        let cipher = Ff1Cipher::new_default(&key, 2).unwrap();
        let ct = cipher.encrypt(&pt, &[]).unwrap();
        assert_eq!(ct, expected, "specific zero-key encrypt");
        assert_eq!(cipher.decrypt(&ct, &[]).unwrap(), pt, "specific zero-key decrypt");
    }
}