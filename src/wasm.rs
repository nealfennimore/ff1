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

use wasm_bindgen::prelude::*;
use crate::Ff1Cipher;

// ---------------------------------------------------------------------------
// JS-visible error helper
// Converts Ff1Error into a JS Error thrown as a JsValue.
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
    /// @param radix   - Numeral base, 2–65536. Use 10 for decimal digits, 26 for lowercase alpha, etc.
    /// @param maxTlen - Maximum tweak length in bytes (default: 256)
    ///
    /// Throws if the key length or radix is invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(key_hex: &str, radix: u32, max_tlen: Option<u32>) -> Result<Ff1, JsValue> {
        let key = hex_decode(key_hex)
            .map_err(|e| JsValue::from_str(&e))?;
        let tlen = max_tlen.unwrap_or(256) as usize;
        let inner = Ff1Cipher::new(&key, radix, tlen).map_err(to_js_err)?;
        Ok(Ff1 { inner })
    }

    // -----------------------------------------------------------------------
    // String interface (most convenient from JS)
    // -----------------------------------------------------------------------

    /// Encrypt a string using a custom alphabet.
    ///
    /// @param plaintext - The string to encrypt. Every character must be in `alphabet`.
    /// @param tweak     - Context string (UTF-8). Can be empty. Acts like a per-record IV.
    /// @param alphabet  - The character set, e.g. "0123456789" or "abcdefghijklmnopqrstuvwxyz".
    ///                    Length must equal `radix`. Characters must be unique.
    ///
    /// Returns the encrypted string, same length and alphabet as the input.
    #[wasm_bindgen(js_name = encryptStr)]
    pub fn encrypt_str(&self, plaintext: &str, tweak: &str, alphabet: &str) -> Result<String, JsValue> {
        self.inner
            .encrypt_str(plaintext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    /// Decrypt a string using a custom alphabet.
    ///
    /// @param ciphertext - The string to decrypt. Every character must be in `alphabet`.
    /// @param tweak      - Must match the tweak used during encryption.
    /// @param alphabet   - Must match the alphabet used during encryption.
    #[wasm_bindgen(js_name = decryptStr)]
    pub fn decrypt_str(&self, ciphertext: &str, tweak: &str, alphabet: &str) -> Result<String, JsValue> {
        self.inner
            .decrypt_str(ciphertext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Numeric symbol interface (Uint32Array in, Uint32Array out)
    // -----------------------------------------------------------------------

    /// Encrypt a sequence of numeric symbols.
    ///
    /// @param symbols - Uint32Array of symbol values, each in the range [0, radix).
    /// @param tweak   - Context string (UTF-8). Can be empty.
    ///
    /// Returns a Uint32Array of the same length.
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, symbols: &[u32], tweak: &str) -> Result<Vec<u32>, JsValue> {
        self.inner
            .encrypt(symbols, tweak.as_bytes())
            .map_err(to_js_err)
    }

    /// Decrypt a sequence of numeric symbols.
    ///
    /// @param symbols - Uint32Array of symbol values, each in the range [0, radix).
    /// @param tweak   - Must match the tweak used during encryption.
    ///
    /// Returns a Uint32Array of the same length.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, symbols: &[u32], tweak: &str) -> Result<Vec<u32>, JsValue> {
        self.inner
            .decrypt(symbols, tweak.as_bytes())
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Hex byte interface (for binary tweaks or raw symbol encoding)
    // -----------------------------------------------------------------------

    /// Encrypt using a raw hex-encoded tweak instead of a UTF-8 string.
    ///
    /// Useful when the tweak contains non-UTF-8 bytes (e.g. a UUID or record ID
    /// stored as raw bytes).
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

    /// Decrypt using a raw hex-encoded tweak.
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

    // -----------------------------------------------------------------------
    // Convenience constants exposed to JS
    // -----------------------------------------------------------------------

    /// Standard decimal digit alphabet: "0123456789"
    #[wasm_bindgen(getter, js_name = DIGITS)]
    pub fn digits() -> String {
        "0123456789".to_string()
    }

    /// Standard lowercase alphabet: "abcdefghijklmnopqrstuvwxyz"
    #[wasm_bindgen(getter, js_name = ALPHA_LOWER)]
    pub fn alpha_lower() -> String {
        "abcdefghijklmnopqrstuvwxyz".to_string()
    }

    /// Alphanumeric alphabet (radix 36): "0123456789abcdefghijklmnopqrstuvwxyz"
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
// WASM-specific tests (run with: wasm-pack test --headless --chrome)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn nist_sample1_via_wasm() {
        let cipher = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ct = cipher.encrypt_str("0123456789", "", "0123456789").unwrap();
        assert_eq!(ct, "2433477484");
        let pt = cipher.decrypt_str(&ct, "", "0123456789").unwrap();
        assert_eq!(pt, "0123456789");
    }

    #[wasm_bindgen_test]
    fn nist_sample2_via_wasm() {
        let cipher = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        // Tweak as UTF-8 bytes of the hex-decoded tweak: "9876543210"
        let ct = cipher.encrypt_str_hex_tweak("0123456789", "39383736353433323130", "0123456789").unwrap();
        assert_eq!(ct, "6124200773");
    }

    #[wasm_bindgen_test]
    fn round_trip_credit_card() {
        let cipher = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 10, None).unwrap();
        let ccn = "4111111111111111";
        let ct  = cipher.encrypt_str(ccn, "merchant-001", "0123456789").unwrap();
        assert_eq!(ct.len(), ccn.len());
        assert_eq!(cipher.decrypt_str(&ct, "merchant-001", "0123456789").unwrap(), ccn);
    }

    #[wasm_bindgen_test]
    fn round_trip_alpha() {
        let cipher = Ff1::new("2B7E151628AED2A6ABF7158809CF4F3C", 26, None).unwrap();
        let pt = "secretmessage";
        let ct = cipher.encrypt_str(pt, "ctx", "abcdefghijklmnopqrstuvwxyz").unwrap();
        assert_eq!(cipher.decrypt_str(&ct, "ctx", "abcdefghijklmnopqrstuvwxyz").unwrap(), pt);
    }

    #[wasm_bindgen_test]
    fn invalid_key_throws() {
        let result = Ff1::new("deadbeef", 10, None); // 4 bytes — too short
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn hex_decode_works() {
        assert_eq!(hex_decode("2B7E").unwrap(), vec![0x2B, 0x7E]);
        assert!(hex_decode("ZZ").is_err());
        assert!(hex_decode("ABC").is_err()); // odd length
    }
}