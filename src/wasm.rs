// wasm.rs — wasm-bindgen wrapper for FF1
//
// This module exposes a JS-friendly API on top of the core Ff1Cipher.
// It is only compiled when targeting wasm32; native builds use lib.rs directly.
//
// Usage from JavaScript/TypeScript:
//
//   import init, { Ff1 } from "./pkg/ff1.js";
//   await init();
//
//   const cipher = new Ff1(keyHex, 10);
//   const ct = cipher.encryptStr("4111111111111111", "merchant-001", "0123456789");
//   const pt = cipher.decryptStr(ct,                "merchant-001", "0123456789");
//
// TWEAK NOTE:
//   encryptStr / decryptStr accept the tweak as a UTF-8 string. If your tweak
//   contains arbitrary binary bytes, use encryptStrHexTweak / decryptStrHexTweak
//   and pass the tweak as a lowercase hex string instead.
//
//   NIST sample vectors use binary tweaks. To reproduce them from JS:
//     cipher.encryptStrHexTweak(pt, "39383736353433323130", alphabet)
//   NOT:
//     cipher.encryptStr(pt, "39383736353433323130", alphabet)  // WRONG — passes the
//                                                               // hex string as UTF-8

use crate::Ff1Cipher;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// JS-visible error helper
// ---------------------------------------------------------------------------

fn to_js_err(e: crate::Ff1Error) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ---------------------------------------------------------------------------
// Ff1 — the JS-visible class
// ---------------------------------------------------------------------------

/// FF1 Format-Preserving Encryption cipher.
///
/// ```js
/// const cipher = new Ff1("2B7E151628AED2A6ABF7158809CF4F3C", 10);
/// const ct = cipher.encryptStr("0123456789", "", "0123456789");
/// ```
#[wasm_bindgen]
pub struct Ff1 {
    inner: Ff1Cipher,
}

#[wasm_bindgen]
impl Ff1 {
    /// Create a new FF1 cipher.
    ///
    /// @param keyHex  - AES key as a hex string (32, 48, or 64 hex chars = 128/192/256 bits)
    /// @param radix   - Numeral base, 2–65536
    /// @param maxTlen - Maximum tweak length in bytes (default: 256)
    #[wasm_bindgen(constructor)]
    pub fn new(key_hex: &str, radix: u32, max_tlen: Option<u32>) -> Result<Ff1, JsValue> {
        let key = hex_decode(key_hex).map_err(|e| JsValue::from_str(&e))?;
        let tlen = max_tlen.unwrap_or(256) as usize;
        let inner = Ff1Cipher::new(&key, radix, tlen).map_err(to_js_err)?;
        Ok(Ff1 { inner })
    }

    // -----------------------------------------------------------------------
    // String interface — tweak is a UTF-8 string
    // -----------------------------------------------------------------------

    /// Encrypt a string using a custom alphabet.
    ///
    /// @param plaintext - Every character must be in `alphabet`.
    /// @param tweak     - Context string (UTF-8). Passed as raw UTF-8 bytes to the cipher.
    ///                    For binary tweaks (e.g. NIST test vectors), use encryptStrHexTweak.
    /// @param alphabet  - The character set, length must equal `radix`, characters must be unique.
    #[wasm_bindgen(js_name = encryptStr)]
    pub fn encrypt_str(
        &self,
        plaintext: &str,
        tweak: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_str(plaintext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    /// Decrypt a string using a custom alphabet.
    ///
    /// @param ciphertext - Every character must be in `alphabet`.
    /// @param tweak      - Must match the tweak used during encryption.
    /// @param alphabet   - Must match the alphabet used during encryption.
    #[wasm_bindgen(js_name = decryptStr)]
    pub fn decrypt_str(
        &self,
        ciphertext: &str,
        tweak: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_str(ciphertext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Numeric symbol interface — Uint32Array in, Uint32Array out
    // -----------------------------------------------------------------------

    /// Encrypt a sequence of numeric symbols.
    ///
    /// @param symbols - Uint32Array of values in [0, radix).
    /// @param tweak   - Context string (UTF-8). For binary tweaks use encryptHexTweak.
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, symbols: &[u32], tweak: &str) -> Result<Vec<u32>, JsValue> {
        self.inner
            .encrypt(symbols, tweak.as_bytes())
            .map_err(to_js_err)
    }

    /// Decrypt a sequence of numeric symbols.
    ///
    /// @param symbols - Uint32Array of values in [0, radix).
    /// @param tweak   - Must match the tweak used during encryption.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, symbols: &[u32], tweak: &str) -> Result<Vec<u32>, JsValue> {
        self.inner
            .decrypt(symbols, tweak.as_bytes())
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Hex tweak interface — for binary tweaks
    // -----------------------------------------------------------------------

    /// Encrypt with a binary tweak supplied as a hex string.
    ///
    /// Use this when the tweak contains non-printable bytes, or when reproducing
    /// NIST test vectors (whose tweaks are specified as hex).
    ///
    /// @param plaintext - The string to encrypt.
    /// @param tweakHex  - Tweak as a lowercase hex string, e.g. "39383736353433323130".
    /// @param alphabet  - The character set.
    #[wasm_bindgen(js_name = encryptStrHexTweak)]
    pub fn encrypt_str_hex_tweak(
        &self,
        plaintext: &str,
        tweak_hex: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner
            .encrypt_str(plaintext, &tweak, alphabet)
            .map_err(to_js_err)
    }

    /// Decrypt with a binary tweak supplied as a hex string.
    #[wasm_bindgen(js_name = decryptStrHexTweak)]
    pub fn decrypt_str_hex_tweak(
        &self,
        ciphertext: &str,
        tweak_hex: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner
            .decrypt_str(ciphertext, &tweak, alphabet)
            .map_err(to_js_err)
    }

    /// Encrypt numeric symbols with a binary tweak supplied as a hex string.
    #[wasm_bindgen(js_name = encryptHexTweak)]
    pub fn encrypt_hex_tweak(&self, symbols: &[u32], tweak_hex: &str) -> Result<Vec<u32>, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner.encrypt(symbols, &tweak).map_err(to_js_err)
    }

    /// Decrypt numeric symbols with a binary tweak supplied as a hex string.
    #[wasm_bindgen(js_name = decryptHexTweak)]
    pub fn decrypt_hex_tweak(&self, symbols: &[u32], tweak_hex: &str) -> Result<Vec<u32>, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner.decrypt(symbols, &tweak).map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Convenience alphabet constants
    // -----------------------------------------------------------------------

    /// "0123456789"
    #[wasm_bindgen(getter, js_name = DIGITS)]
    pub fn digits() -> String {
        "0123456789".to_string()
    }

    /// "abcdefghijklmnopqrstuvwxyz"
    #[wasm_bindgen(getter, js_name = ALPHA_LOWER)]
    pub fn alpha_lower() -> String {
        "abcdefghijklmnopqrstuvwxyz".to_string()
    }

    /// "0123456789abcdefghijklmnopqrstuvwxyz"
    #[wasm_bindgen(getter, js_name = ALPHANUM)]
    pub fn alphanum() -> String {
        "0123456789abcdefghijklmnopqrstuvwxyz".to_string()
    }
}

// ---------------------------------------------------------------------------
// Utility: hex string -> Vec<u8>
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("Hex string has odd length: {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_char(pair[0])?;
            let lo = hex_char(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_char(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("Invalid hex character: {}", c as char)),
    }
}

// ---------------------------------------------------------------------------
// WASM tests (run with: wasm-pack test --headless --chrome)
//
// These mirror the test suite in lib.rs. All NIST sample vector tweaks are
// binary and must be passed via the HexTweak methods.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ALPHA10: &str = "0123456789";
    const ALPHA36: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    // Tweak hex strings for the NIST samples
    const TWEAK_SAMPLE_2_5_8: &str = "39383736353433323130"; // AES-128/192/256 radix-10 with tweak
    const TWEAK_SAMPLE_3_6_9: &str = "3737373770717273373737"; // AES-128/192/256 radix-36 with tweak

    // -----------------------------------------------------------------------
    // NIST samples 1–3: AES-128
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn nist_sample1_aes128_radix10_no_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ct = c.encrypt_str("0123456789", "", ALPHA10).unwrap();
        assert_eq!(ct, "2433477484", "sample1 encrypt");
        assert_eq!(
            c.decrypt_str(&ct, "", ALPHA10).unwrap(),
            "0123456789",
            "sample1 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample2_aes128_radix10_with_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789", TWEAK_SAMPLE_2_5_8, ALPHA10)
            .unwrap();
        assert_eq!(ct, "6124200773", "sample2 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_2_5_8, ALPHA10)
                .unwrap(),
            "0123456789",
            "sample2 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample3_aes128_radix36_with_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 36, None).unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789abcdefghi", TWEAK_SAMPLE_3_6_9, ALPHA36)
            .unwrap();
        assert_eq!(ct, "a9tv40mll9kdu509eum", "sample3 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_3_6_9, ALPHA36)
                .unwrap(),
            "0123456789abcdefghi",
            "sample3 decrypt"
        );
    }

    // -----------------------------------------------------------------------
    // NIST samples 4–6: AES-192
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn nist_sample4_aes192_radix10_no_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, None).unwrap();
        let ct = c.encrypt_str("0123456789", "", ALPHA10).unwrap();
        assert_eq!(ct, "2830668132", "sample4 encrypt");
        assert_eq!(
            c.decrypt_str(&ct, "", ALPHA10).unwrap(),
            "0123456789",
            "sample4 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample5_aes192_radix10_with_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, None).unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789", TWEAK_SAMPLE_2_5_8, ALPHA10)
            .unwrap();
        assert_eq!(ct, "2496655549", "sample5 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_2_5_8, ALPHA10)
                .unwrap(),
            "0123456789",
            "sample5 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample6_aes192_radix36_with_tweak() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 36, None).unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789abcdefghi", TWEAK_SAMPLE_3_6_9, ALPHA36)
            .unwrap();
        assert_eq!(ct, "xbj3kv35jrawxv32ysr", "sample6 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_3_6_9, ALPHA36)
                .unwrap(),
            "0123456789abcdefghi",
            "sample6 decrypt"
        );
    }

    // -----------------------------------------------------------------------
    // NIST samples 7–9: AES-256
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn nist_sample7_aes256_radix10_no_tweak() {
        let c = Ff1::new(
            "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
            10,
            None,
        )
        .unwrap();
        let ct = c.encrypt_str("0123456789", "", ALPHA10).unwrap();
        assert_eq!(ct, "6657667009", "sample7 encrypt");
        assert_eq!(
            c.decrypt_str(&ct, "", ALPHA10).unwrap(),
            "0123456789",
            "sample7 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample8_aes256_radix10_with_tweak() {
        let c = Ff1::new(
            "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
            10,
            None,
        )
        .unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789", TWEAK_SAMPLE_2_5_8, ALPHA10)
            .unwrap();
        assert_eq!(ct, "1001623463", "sample8 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_2_5_8, ALPHA10)
                .unwrap(),
            "0123456789",
            "sample8 decrypt"
        );
    }

    #[wasm_bindgen_test]
    fn nist_sample9_aes256_radix36_with_tweak() {
        let c = Ff1::new(
            "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
            36,
            None,
        )
        .unwrap();
        let ct = c
            .encrypt_str_hex_tweak("0123456789abcdefghi", TWEAK_SAMPLE_3_6_9, ALPHA36)
            .unwrap();
        assert_eq!(ct, "xs8a0azh2avyalyzuwd", "sample9 encrypt");
        assert_eq!(
            c.decrypt_str_hex_tweak(&ct, TWEAK_SAMPLE_3_6_9, ALPHA36)
                .unwrap(),
            "0123456789abcdefghi",
            "sample9 decrypt"
        );
    }

    // -----------------------------------------------------------------------
    // Numeric symbol interface — mirrors the lib.rs u32 tests
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn nist_sample1_via_encrypt_symbols() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let pt: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ct = c.encrypt(&pt, "").unwrap();
        assert_eq!(ct, vec![2u32, 4, 3, 3, 4, 7, 7, 4, 8, 4]);
        assert_eq!(c.decrypt(&ct, "").unwrap(), pt);
    }

    #[wasm_bindgen_test]
    fn nist_sample9_via_encrypt_hex_tweak_symbols() {
        let c = Ff1::new(
            "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
            36,
            None,
        )
        .unwrap();
        let pt: Vec<u32> = (0..19).collect();
        let ct = c.encrypt_hex_tweak(&pt, TWEAK_SAMPLE_3_6_9).unwrap();
        let expected: Vec<u32> = vec![
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
        ];
        assert_eq!(ct, expected, "sample9 symbol encrypt");
        assert_eq!(
            c.decrypt_hex_tweak(&ct, TWEAK_SAMPLE_3_6_9).unwrap(),
            pt,
            "sample9 symbol decrypt"
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip and regression tests
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn round_trip_credit_card() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ccn = "4111111111111111";
        let ct = c.encrypt_str(ccn, "merchant-001", ALPHA10).unwrap();
        assert_eq!(ct.len(), ccn.len());
        assert_eq!(c.decrypt_str(&ct, "merchant-001", ALPHA10).unwrap(), ccn);
    }

    #[wasm_bindgen_test]
    fn round_trip_alpha() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 26, None).unwrap();
        let pt = "secretmessage";
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        let ct = c.encrypt_str(pt, "ctx", alpha).unwrap();
        assert_eq!(c.decrypt_str(&ct, "ctx", alpha).unwrap(), pt);
    }

    #[wasm_bindgen_test]
    fn tweak_changes_output() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ct1 = c.encrypt_str("0123456789", "tweak1", ALPHA10).unwrap();
        let ct2 = c.encrypt_str("0123456789", "tweak2", ALPHA10).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[wasm_bindgen_test]
    fn empty_tweak_differs_from_nonempty() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ct_empty = c.encrypt_str("0123456789", "", ALPHA10).unwrap();
        let ct_nonempty = c.encrypt_str("0123456789", "t", ALPHA10).unwrap();
        assert_ne!(ct_empty, ct_nonempty);
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn invalid_key_throws() {
        assert!(Ff1::new("deadbeef", 10, None).is_err()); // 4 bytes — too short
    }

    #[wasm_bindgen_test]
    fn invalid_radix_throws() {
        assert!(Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 1, None).is_err());
    }

    #[wasm_bindgen_test]
    fn symbol_out_of_range_throws() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        assert!(c.encrypt(&[0, 1, 10, 3], "").is_err()); // 10 >= radix 10
    }

    #[wasm_bindgen_test]
    fn plaintext_too_short_throws() {
        let c = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        assert!(c.encrypt(&[0], "").is_err());
    }

    // -----------------------------------------------------------------------
    // hex_decode utility
    // -----------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn hex_decode_works() {
        assert_eq!(hex_decode("2B7E").unwrap(), vec![0x2B, 0x7E]);
        assert!(hex_decode("ZZ").is_err());
        assert!(hex_decode("ABC").is_err()); // odd length
    }
}
