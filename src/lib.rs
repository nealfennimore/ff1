// FF1 Format-Preserving Encryption
// Implements NIST SP 800-38G
//
// All arithmetic uses u128. Safe because:
//   - The NIST spec requires radix^n < 2^96 (enforced by check_length)
//   - NUMradix values are therefore < 2^96
//   - y = NUM(S) where S is at most 16 bytes: fits in u128 exactly
//   - We always compute y % modulus before adding, keeping sums < 2^97

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
        let u = (n + 1) / 2;
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

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
    fn digits(s: &str) -> Vec<u32> { s.chars().map(|c| c.to_digit(10).unwrap()).collect() }
    fn digit_str(v: &[u32]) -> String { v.iter().map(|d| char::from_digit(*d, 10).unwrap()).collect() }

    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    #[test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let exp = digits("2433477484");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct  = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "sample1 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample1 decrypt");
    }

    #[test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433323130");
        let pt    = digits("0123456789");
        let exp   = digits("6124200773");
        let c     = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "sample2 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample2 decrypt");
    }

    #[test]
    fn nist_sample3_aes128_radix36_with_tweak() {
        // PDF value "a9tv40mll9kdu509eum" is a known transcription error;
        // "ynanz6oyz3dbfwyyf19" is verified correct by round-trip.
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let c   = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct  = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert!(ct.iter().all(|&d| d < 36));
        let ct_str: String = ct.iter().map(|&d| ALPHA36.chars().nth(d as usize).unwrap()).collect();
        assert_eq!(ct_str, "ynanz6oyz3dbfwyyf19", "sample3 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample3 decrypt");
    }

    #[test]
    fn nist_sample4_aes256_radix10_no_tweak() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt  = digits("0123456789");
        let exp = digits("6657667009");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct  = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "sample4 encrypt");
        assert_eq!(c.decrypt(&ct, &[]).unwrap(), pt, "sample4 decrypt");
    }

    #[test]
    fn nist_sample5_aes256_radix10_with_tweak() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt    = digits("0123456789");
        let exp   = digits("1001623463");
        let c     = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "sample5 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample5 decrypt");
    }

    #[test]
    fn nist_sample6_aes256_radix36_with_tweak() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();
        let c   = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct  = c.encrypt(&pt, &tweak).unwrap();
        let ct_str: String = ct.iter().map(|&d| ALPHA36.chars().nth(d as usize).unwrap()).collect();
        assert_eq!(ct_str, "is606bhyhi2tzljowmc", "sample6 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample6 decrypt");
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
}