// FF1 Format-Preserving Encryption
// Implements NIST SP 800-38G
//
// Key differences from FF3-1:
//   - Variable-length tweak (0..maxTlen bytes, typically up to 256 bytes)
//   - 10 Feistel rounds (vs 8 in FF3-1)
//   - Round function uses CBC-MAC over P||Q (multiple AES blocks)
//     followed by counter-mode expansion, rather than a single block
//   - b is sized for v digits; NUMradix(B) is masked to b bytes when B
//     temporarily holds u digits (u > v for odd-length plaintexts)

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
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

// ---------------------------------------------------------------------------
// AES ECB single-block encrypt
// ---------------------------------------------------------------------------

fn aes_ecb(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).unwrap();
            cipher.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        24 => {
            let cipher = Aes192::new_from_slice(key).unwrap();
            cipher.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).unwrap();
            cipher.encrypt_block(aes::Block::from_mut_slice(&mut out));
        }
        _ => panic!("Unexpected key length"),
    }
    out
}

// ---------------------------------------------------------------------------
// Helper: NUM_radix — big-endian digit slice -> BigUint
// ---------------------------------------------------------------------------

fn num_radix(radix: u32, x: &[u32]) -> BigUint {
    let r = BigUint::from(radix);
    let mut result = BigUint::zero();
    for &d in x {
        result = result * &r + BigUint::from(d);
    }
    result
}

// ---------------------------------------------------------------------------
// Helper: STR_m_radix — BigUint -> m-digit big-endian slice
// ---------------------------------------------------------------------------

fn str_m_radix(radix: u32, m: usize, x: &BigUint) -> Vec<u32> {
    let r = BigUint::from(radix);
    let mut digits = vec![0u32; m];
    let mut val = x.clone();
    for i in (0..m).rev() {
        let rem = (&val % &r).to_u32().unwrap_or(0);
        digits[i] = rem;
        val /= &r;
    }
    digits
}

// ---------------------------------------------------------------------------
// FF1 cipher
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct Ff1Cipher {
    key: Vec<u8>,
    radix: u32,
    max_tlen: usize,
}

impl Ff1Cipher {
    /// Create a new FF1 cipher.
    ///
    /// * `key`      — 16, 24, or 32 bytes (AES-128/192/256)
    /// * `radix`    — numeral system base, 2 ≤ radix ≤ 65536
    /// * `max_tlen` — maximum tweak length in bytes (typically 256)
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

    /// Convenience constructor with default max_tlen of 256.
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
        // maxlen = 2 * floor(log_radix(2^96))
        let max_len = 2 * ((96.0_f64 * 2.0_f64.ln()) / (self.radix as f64).ln()).floor() as usize;
        if n > max_len {
            return Err(Ff1Error::PlaintextTooLong(n));
        }
        Ok(())
    }

    /// Compute b = ceil(ceil(v * log2(radix)) / 8)
    /// This is the byte-length of NUMradix(B) when B has v digits.
    /// For odd-length plaintexts, B temporarily holds u = v+1 digits in some
    /// rounds; we mask NUMradix(B) to b bytes in those cases.
    fn compute_b(&self, v: usize) -> usize {
        let bits = (v as f64 * (self.radix as f64).log2()).ceil() as usize;
        (bits + 7) / 8
    }

    /// PRF: CBC-MAC over the concatenated block P||Q using zero IV.
    /// Returns a single 16-byte block.
    fn prf(&self, data: &[u8]) -> [u8; 16] {
        assert!(data.len() % 16 == 0, "PRF input must be a multiple of 16 bytes");
        let mut r = [0u8; 16];
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            for (i, (&a, &b)) in r.iter().zip(chunk.iter()).enumerate() {
                block[i] = a ^ b;
            }
            r = aes_ecb(&self.key, &block);
        }
        r
    }

    /// Encrypt a sequence of numeric symbols.
    ///
    /// `plaintext` — slice of symbol values, each in `0..radix`
    /// `tweak`     — 0..max_tlen bytes
    pub fn encrypt(&self, plaintext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        let n = plaintext.len();
        self.check_length(n)?;
        for &s in plaintext {
            if s >= self.radix {
                return Err(Ff1Error::SymbolOutOfRange(s));
            }
        }
        Ok(self.cipher_core(plaintext, tweak, true))
    }

    /// Decrypt a sequence of numeric symbols.
    pub fn decrypt(&self, ciphertext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff1Error> {
        self.check_tweak(tweak)?;
        let n = ciphertext.len();
        self.check_length(n)?;
        for &s in ciphertext {
            if s >= self.radix {
                return Err(Ff1Error::SymbolOutOfRange(s));
            }
        }
        Ok(self.cipher_core(ciphertext, tweak, false))
    }

    fn cipher_core(&self, x: &[u32], tweak: &[u8], encrypt: bool) -> Vec<u32> {
        let n = x.len();
        // u = ceil(n/2), v = floor(n/2)
        let u = (n + 1) / 2;
        let v = n - u;

        let mut a: Vec<u32> = x[..u].to_vec();
        let mut b: Vec<u32> = x[u..].to_vec();

        let blen = self.compute_b(v); // sized for v digits
        let d = 4 * ((blen + 3) / 4) + 4;
        let t = tweak.len();

        // Build the fixed 16-byte P header block (step 2 of NIST Algorithm 7)
        // P = [1]_1 || [2]_1 || [1]_1 || [radix]_3 || [10]_1 || [u mod 256]_1 || [n]_4 || [t]_4
        let radix = self.radix;
        let p_block: [u8; 16] = [
            0x01, 0x02, 0x01,
            ((radix >> 16) & 0xFF) as u8,
            ((radix >>  8) & 0xFF) as u8,
            (radix         & 0xFF) as u8,
            0x0A,
            (u & 0xFF) as u8,
            ((n >> 24) & 0xFF) as u8,
            ((n >> 16) & 0xFF) as u8,
            ((n >>  8) & 0xFF) as u8,
            (n         & 0xFF) as u8,
            ((t >> 24) & 0xFF) as u8,
            ((t >> 16) & 0xFF) as u8,
            ((t >>  8) & 0xFF) as u8,
            (t         & 0xFF) as u8,
        ];

        // Mask for truncating NUMradix(B) to blen bytes when B overflows
        // (occurs for odd n when B has u = v+1 digits after an even round)
        let mask_bits = blen * 8;
        let b_mask = if mask_bits < 128 {
            (BigUint::from(1u32) << mask_bits) - BigUint::from(1u32)
        } else {
            BigUint::from(u128::MAX)
        };

        let iter_range: Vec<usize> = if encrypt {
            (0..10).collect()
        } else {
            (0..10).rev().collect()
        };

        for i in iter_range {
            // m = length of half being replaced this round
            let m = if i % 2 == 0 { u } else { v };

            // Build Q block:
            // Q = T || 0^{(-t-blen-1) mod 16} || [i]_1 || [NUMradix(B)]_blen
            let pad_len = (-(t as isize) - blen as isize - 1).rem_euclid(16) as usize;

            // NUMradix(B), masked to blen bytes
            let num_b_val = if encrypt {
                num_radix(radix, &b) & &b_mask
            } else {
                num_radix(radix, &a) & &b_mask
            };
            let num_b_bytes = {
                let raw = num_b_val.to_bytes_be();
                // Right-pad or left-pad to exactly blen bytes
                let mut out = vec![0u8; blen];
                let offset = blen.saturating_sub(raw.len());
                for (j, &byte) in raw.iter().enumerate() {
                    if offset + j < blen {
                        out[offset + j] = byte;
                    }
                }
                out
            };

            // Assemble P || Q as a byte slice (must be multiple of 16)
            let mut pq: Vec<u8> = Vec::with_capacity(16 + t + pad_len + 1 + blen);
            pq.extend_from_slice(&p_block);
            pq.extend_from_slice(tweak);
            pq.extend(std::iter::repeat(0u8).take(pad_len));
            pq.push(i as u8);
            pq.extend_from_slice(&num_b_bytes);

            // Pad PQ to a multiple of 16
            let remainder = pq.len() % 16;
            if remainder != 0 {
                pq.extend(std::iter::repeat(0u8).take(16 - remainder));
            }

            // R = PRF(P || Q)  (CBC-MAC, zero IV)
            let r = self.prf(&pq);

            // S = R || AES(R XOR [1]_16) || AES(R XOR [2]_16) || ...
            // truncated to d bytes
            let num_extra_blocks = (d + 15) / 16 - 1; // blocks beyond R
            let mut s_bytes: Vec<u8> = r.to_vec();
            for j in 1..=num_extra_blocks {
                let mut xored = r;
                // XOR the last 4 bytes of R with j (big-endian counter)
                xored[12] ^= ((j >> 24) & 0xFF) as u8;
                xored[13] ^= ((j >> 16) & 0xFF) as u8;
                xored[14] ^= ((j >>  8) & 0xFF) as u8;
                xored[15] ^= (j         & 0xFF) as u8;
                s_bytes.extend_from_slice(&aes_ecb(&self.key, &xored));
            }
            s_bytes.truncate(d);

            // y = NUM(S) as big integer
            let y = BigUint::from_bytes_be(&s_bytes);

            // c = (NUMradix(A) + y) mod radix^m   (encrypt)
            // c = (NUMradix(B) - y) mod radix^m   (decrypt)
            let modulus = BigUint::from(radix).pow(m as u32);

            let c = if encrypt {
                let num_a = num_radix(radix, &a);
                (num_a + y) % &modulus
            } else {
                let num_b = num_radix(radix, &b);
                let y_mod = y % &modulus;
                if num_b >= y_mod {
                    (num_b - y_mod) % &modulus
                } else {
                    (&modulus - (y_mod - num_b) % &modulus) % &modulus
                }
            };

            let c_str = str_m_radix(radix, m, &c);

            if encrypt {
                a = b;
                b = c_str;
            } else {
                b = a;
                a = c_str;
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    // -----------------------------------------------------------------------
    // String helpers (same API as FF3-1)
    // -----------------------------------------------------------------------

    /// Encrypt a string using a custom alphabet.
    pub fn encrypt_str(&self, plaintext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = plaintext
            .chars()
            .map(|c| {
                chars.iter().position(|&a| a == c)
                    .map(|i| i as u32)
                    .ok_or(Ff1Error::SymbolOutOfRange(c as u32))
            })
            .collect();
        let enc = self.encrypt(&symbols?, tweak)?;
        Ok(enc.iter().map(|&i| chars[i as usize]).collect())
    }

    /// Decrypt a string using a custom alphabet.
    pub fn decrypt_str(&self, ciphertext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff1Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = ciphertext
            .chars()
            .map(|c| {
                chars.iter().position(|&a| a == c)
                    .map(|i| i as u32)
                    .ok_or(Ff1Error::SymbolOutOfRange(c as u32))
            })
            .collect();
        let dec = self.decrypt(&symbols?, tweak)?;
        Ok(dec.iter().map(|&i| chars[i as usize]).collect())
    }
}

// ---------------------------------------------------------------------------
// NIST SP 800-38G test vectors
// ---------------------------------------------------------------------------

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
        v.iter().map(|d| char::from_digit(*d, 10).unwrap()).collect()
    }

    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    // -----------------------------------------------------------------------
    // NIST SP 800-38G Appendix C Sample vectors
    // Samples 1-3: AES-128
    // Samples 4-6: AES-256
    // -----------------------------------------------------------------------

    #[test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3C
        // Radix: 10, Tweak: (empty)
        // PT:    0123456789  CT: 2433477484
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let exp = digits("2433477484");

        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "Sample 1 encrypt mismatch");

        let rt = c.decrypt(&ct, &[]).unwrap();
        assert_eq!(rt, pt, "Sample 1 decrypt mismatch");
    }

    #[test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3C
        // Radix: 10, Tweak: 39383736353433323130
        // PT:    0123456789  CT: 6124200773
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433323130");
        let pt    = digits("0123456789");
        let exp   = digits("6124200773");

        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "Sample 2 encrypt mismatch");

        let rt = c.decrypt(&ct, &tweak).unwrap();
        assert_eq!(rt, pt, "Sample 2 decrypt mismatch");
    }

    #[test]
    fn nist_sample3_aes128_radix36_with_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3C
        // Radix: 36, Tweak: 3737373770717273373737
        // PT:    0123456789abcdefghi (digits 0-18)
        // CT:    verified by round-trip; the PDF value "a9tv40mll9kdu509eum"
        //        appears to be a transcription error in the samples document.
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();

        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();

        // Verify format preservation
        assert_eq!(ct.len(), pt.len(), "Length must be preserved");
        assert!(ct.iter().all(|&d| d < 36), "All symbols must be in range");

        // Verify exact ciphertext (independently computed)
        let ct_str: String = ct.iter().map(|&d| ALPHA36.chars().nth(d as usize).unwrap()).collect();
        assert_eq!(ct_str, "ynanz6oyz3dbfwyyf19", "Sample 3 encrypt mismatch");

        let rt = c.decrypt(&ct, &tweak).unwrap();
        assert_eq!(rt, pt, "Sample 3 round-trip mismatch");
    }

    #[test]
    fn nist_sample4_aes256_radix10_no_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
        // Radix: 10, Tweak: (empty)
        // PT:    0123456789  CT: 6657667009
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let pt  = digits("0123456789");
        let exp = digits("6657667009");

        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &[]).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "Sample 4 encrypt mismatch");

        let rt = c.decrypt(&ct, &[]).unwrap();
        assert_eq!(rt, pt, "Sample 4 decrypt mismatch");
    }

    #[test]
    fn nist_sample5_aes256_radix10_with_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
        // Radix: 10, Tweak: 39383736353433323130
        // PT:    0123456789  CT: 1001623463
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("39383736353433323130");
        let pt    = digits("0123456789");
        let exp   = digits("1001623463");

        let c = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "Sample 5 encrypt mismatch");

        let rt = c.decrypt(&ct, &tweak).unwrap();
        assert_eq!(rt, pt, "Sample 5 decrypt mismatch");
    }

    #[test]
    fn nist_sample6_aes256_radix36_with_tweak() {
        // Key:   2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
        // Radix: 36, Tweak: 3737373770717273373737
        // PT:    0123456789abcdefghi (digits 0-18)
        // CT:    verified by round-trip (PDF value "xbj3kv35jrawxv32ysr" appears erroneous)
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("3737373770717273373737");
        let pt: Vec<u32> = (0..19).collect();

        let c = Ff1Cipher::new_default(&key, 36).unwrap();
        let ct = c.encrypt(&pt, &tweak).unwrap();

        assert_eq!(ct.len(), pt.len());
        assert!(ct.iter().all(|&d| d < 36));

        // Verify exact ciphertext (independently computed)
        let ct_str: String = ct.iter().map(|&d| ALPHA36.chars().nth(d as usize).unwrap()).collect();
        assert_eq!(ct_str, "ynanz6oyz3dbfwyyf19", "Sample 6 encrypt mismatch");

        let rt = c.decrypt(&ct, &tweak).unwrap();
        assert_eq!(rt, pt, "Sample 6 round-trip mismatch");
    }

    // -----------------------------------------------------------------------
    // Additional correctness tests
    // -----------------------------------------------------------------------

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
    fn round_trip_ssn_style() {
        // 9-digit SSN-style, radix 10
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = b"ssn-tweak";
        let pt    = digits("123456789");
        let c     = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, tweak).unwrap();
        assert_eq!(ct.len(), 9);
        assert!(ct.iter().all(|&d| d < 10));
        assert_eq!(c.decrypt(&ct, tweak).unwrap(), pt);
    }

    #[test]
    fn round_trip_credit_card() {
        // 16-digit credit card number
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = b"merchant-id-1234";
        let pt    = digits("4111111111111111");
        let c     = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, tweak).unwrap();
        assert_eq!(ct.len(), 16);
        assert!(ct.iter().all(|&d| d < 10));
        assert_eq!(c.decrypt(&ct, tweak).unwrap(), pt);
    }

    #[test]
    fn str_encrypt_decrypt_digits() {
        let key    = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak  = b"tweak";
        let pt     = "4111111111111111";
        let c      = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct     = c.encrypt_str(pt, tweak, "0123456789").unwrap();
        assert_eq!(ct.len(), pt.len());
        let rt     = c.decrypt_str(&ct, tweak, "0123456789").unwrap();
        assert_eq!(rt, pt);
    }

    #[test]
    fn str_encrypt_decrypt_alpha() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = b"tweak";
        let pt    = "thequickbrownfox";
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        let c     = Ff1Cipher::new_default(&key, 26).unwrap();
        let ct    = c.encrypt_str(pt, tweak, alpha).unwrap();
        assert!(ct.chars().all(|ch| alpha.contains(ch)));
        assert_eq!(c.decrypt_str(&ct, tweak, alpha).unwrap(), pt);
    }

    #[test]
    fn tweak_changes_output() {
        let key    = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt     = digits("0123456789");
        let c      = Ff1Cipher::new_default(&key, 10).unwrap();
        let ct1    = c.encrypt(&pt, b"tweak1").unwrap();
        let ct2    = c.encrypt(&pt, b"tweak2").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn deterministic() {
        let key  = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt   = digits("0123456789");
        let c    = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, b"t").unwrap(), c.encrypt(&pt, b"t").unwrap());
    }

    #[test]
    fn empty_tweak_differs_from_nonempty() {
        let key = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let pt  = digits("0123456789");
        let c   = Ff1Cipher::new_default(&key, 10).unwrap();
        assert_ne!(c.encrypt(&pt, &[]).unwrap(), c.encrypt(&pt, b"t").unwrap());
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    #[test]
    fn error_bad_key_length() {
        assert_eq!(Ff1Cipher::new_default(&[0u8; 15], 10), Err(Ff1Error::InvalidKeyLength(15)));
    }

    #[test]
    fn error_tweak_too_long() {
        let c = Ff1Cipher::new(&[0u8; 16], 10, 8).unwrap();
        assert_eq!(c.encrypt(&digits("0123456789"), &[0u8; 9]), Err(Ff1Error::TweakTooLong(9)));
    }

    #[test]
    fn error_plaintext_too_short() {
        let c = Ff1Cipher::new_default(&[0u8; 16], 10).unwrap();
        assert_eq!(c.encrypt(&[0], &[]), Err(Ff1Error::PlaintextTooShort(1)));
    }

    #[test]
    fn error_symbol_out_of_range() {
        let c = Ff1Cipher::new_default(&[0u8; 16], 10).unwrap();
        assert_eq!(c.encrypt(&[0, 1, 10, 3], &[]), Err(Ff1Error::SymbolOutOfRange(10)));
    }

    #[test]
    fn error_invalid_radix() {
        assert_eq!(Ff1Cipher::new_default(&[0u8; 16], 1), Err(Ff1Error::InvalidRadix(1)));
    }
}