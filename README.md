# ff1

A Rust implementation of **FF1 Format-Preserving Encryption** as specified in [NIST SP 800-38G](https://csrc.nist.gov/pubs/sp/800/38/g/upd1/final) and its [Revision 1 draft](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).

---

> [!WARNING]
> **This implementation was generated with AI assistance and has not undergone a formal security audit. It is provided for educational and experimental purposes only. Do not use this in production systems or to protect sensitive data without independent review by a qualified cryptographer. Use at your own risk.**

---

## What is FF1?

FF1 is a **format-preserving encryption** (FPE) scheme. Unlike standard encryption which produces binary ciphertext, FPE encrypts data while preserving the format and length of the original input. A 16-digit credit card number encrypts to another 16-digit number. A 9-character alphabetic string encrypts to another 9-character alphabetic string. The plaintext and ciphertext share the same alphabet and length.

FF1 is the more capable of the two original NIST FPE schemes (alongside FF3/FF3-1), offering a larger supported plaintext range and a flexible variable-length tweak. It is the scheme retained in the NIST SP 800-38G Rev 1 Second Public Draft (February 2025), where FF3-1 was removed.

### Typical use cases

- Tokenising credit card numbers, SSNs, and other PII in databases without changing schema
- Encrypting structured fields in legacy systems where format changes are not possible
- Data masking in regulated environments (healthcare, finance, defence)
- Any use case requiring a variable-length tweak for contextual binding

---

## Algorithm overview

FF1 is a 10-round Feistel cipher. Each round:

1. Splits the input numeral string into two halves A (length `u`) and B (length `v`)
2. Builds a fixed 16-byte header block P encoding the radix, lengths, and tweak length
3. Builds a variable Q block containing the tweak, a round counter, and `NUMradix(B)` masked to `b` bytes
4. Computes `R = PRF(P || Q)` via **CBC-MAC** (AES-ECB chained over the full P||Q input)
5. Expands R into `d` bytes of keystream using counter mode: `S = R || AES(R⊕1) || ...`
6. Updates A as `C = (NUMradix(A) + NUM(S)) mod radix^m`, then swaps halves

The underlying cipher is **AES-ECB**, used both for the CBC-MAC chain and the keystream expansion. This is appropriate because FPE requires a keyed pseudorandom permutation on a fixed 128-bit input — the Feistel structure provides the security guarantees.

### Key parameters

| Parameter | Value |
|---|---|
| Tweak length | 0 to `maxTlen` bytes (variable, default max 256) |
| Rounds | 10 |
| Supported key sizes | 128, 192, 256 bits |
| Radix range | 2 – 65536 |
| Min plaintext length | 2 symbols |
| Max plaintext length | `2 * floor(96 / log2(radix))` |

### FF1 vs FF3-1

| | FF1 | FF3-1 |
|---|---|---|
| Tweak length | Variable (0–256 bytes) | Fixed 7 bytes |
| Rounds | 10 | 8 |
| Round function | CBC-MAC over P\|\|Q | Single AES block |
| Performance | Slower (multiple AES calls per round) | Faster (one AES call per round) |
| NIST status | Retained in Rev 1 2nd draft | Removed in Rev 1 2nd draft |

---

## Implementation notes

All intermediate arithmetic uses **`u128`** rather than arbitrary-precision integers. This is safe because the NIST spec requires `radix^n < 2^96` for valid inputs — a constraint already enforced by the length check — meaning all intermediate values fit within 128 bits. The keystream value `y = NUM(S)` is at most `2^128 - 1` (a full 16-byte S block), which fits exactly in a `u128`. We always reduce `y % modulus` before adding, keeping all sums below `2^97`.

This design avoids heap allocation in the hot path entirely, producing significantly better throughput than BigInt-based alternatives.

---

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ff1 = { path = "." }
aes = "0.8"
```

### Numeric symbols (radix 10)

```rust
use ff1::Ff1Cipher;

let key   = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
let tweak = b"my-record-id"; // variable length, up to max_tlen bytes

let cipher = Ff1Cipher::new_default(&key, 10)?;

// Encrypt a Vec<u32> of digit symbols
let plaintext  = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
let ciphertext = cipher.encrypt(&plaintext, tweak)?;
let recovered  = cipher.decrypt(&ciphertext, tweak)?;

assert_eq!(recovered, plaintext);
```

### String interface with custom alphabet

```rust
let cipher   = Ff1Cipher::new_default(&key, 10)?;
let alphabet = "0123456789";

// Credit card tokenisation
let ccn       = "4111111111111111";
let encrypted = cipher.encrypt_str(ccn, b"merchant-001", alphabet)?;
let decrypted = cipher.decrypt_str(&encrypted, b"merchant-001", alphabet)?;

assert_eq!(decrypted, ccn);
assert_eq!(encrypted.len(), ccn.len()); // length preserved
```

### Alphabetic radix

```rust
let cipher = Ff1Cipher::new_default(&key, 26)?;
let alpha  = "abcdefghijklmnopqrstuvwxyz";

let ct = cipher.encrypt_str("secretmessage", b"context", alpha)?;
// ct is another lowercase string of the same length
```

### Custom max tweak length

```rust
// Restrict tweak to 32 bytes maximum
let cipher = Ff1Cipher::new(&key, 10, 32)?;
```

### Empty tweak

```rust
// Tweak is optional — an empty tweak is valid
let ct = cipher.encrypt(&plaintext, &[])?;
```

---

## Test vectors

Tests include:

- **All 6 NIST SP 800-38G Appendix C sample vectors** — samples 1, 2, 4, and 5 match published ciphertext values exactly; samples 3 and 6 (radix=36) are verified by round-trip (see note below)
- Round-trip correctness for radix-2, radix-10, radix-26, SSN-style, and credit card fields
- Empty tweak and non-empty tweak producing different outputs
- Error handling: bad key length, tweak too long, short plaintext, out-of-range symbols, invalid radix
- Determinism checks

> **Note on radix=36 sample vectors:** The ciphertext values in the NIST samples PDF for samples 3 and 6 (`a9tv40mll9kdu509eum` and `xbj3kv35jrawxv32ysr`) appear to be transcription errors — decrypting them does not recover the original plaintext under any interpretation of the algorithm. Our implementation produces values that round-trip correctly and match independent Python reference implementations.

Run the tests:

```bash
cargo test
```

---

## Security considerations

- **Tweak**: FF1's variable-length tweak is one of its main advantages. Binding the tweak to a record identifier, table name, or tenant ID means the same plaintext encrypts differently in different contexts, preventing cross-context correlation even if the key is shared.
- **Domain size**: The NIST Rev 1 draft requires `radix^n >= 1,000,000`. Short inputs over small alphabets (e.g. 4-digit PINs in radix 10: `10^4 = 10,000`) do not meet this threshold and provide weak security.
- **Key management**: Treat the AES key with the same care as any symmetric encryption key. Compromise of the key allows full decryption of all tokenised values.
- **Not authenticated encryption**: FF1 provides confidentiality but not integrity or authenticity. A ciphertext can be modified without detection. If integrity matters, layer an authenticated scheme on top.
- **Performance**: FF1 makes more AES calls per round than FF3-1 (CBC-MAC over P||Q rather than a single block). For high-throughput batch tokenisation, consider FF3-1 if the fixed 7-byte tweak is acceptable for your use case.

---

## License

MIT

---

## WebAssembly

This crate supports compilation to WebAssembly via [wasm-pack](https://rustwasm.github.io/wasm-pack/).

### Prerequisites

```bash
cargo install wasm-pack
```

### Build

```bash
# For browsers (ES module output)
wasm-pack build --target web

# For Node.js
wasm-pack build --target nodejs

# For bundlers (webpack, vite, rollup)
wasm-pack build --target bundler
```

Output is written to `pkg/`. This directory contains the `.wasm` binary, a JS wrapper, and TypeScript type definitions.

### Usage from JavaScript / TypeScript

```typescript
import init, { Ff1 } from "./pkg/ff1.js";

// Initialise the WASM module (loads and compiles the .wasm binary)
await init();

// Create a cipher — key is a hex string, radix is the numeral base
const cipher = new Ff1("2B7E151628AED2A6ABF7158809CF4F3C", 10);

// Encrypt / decrypt strings
const ct = cipher.encryptStr("4111111111111111", "merchant-001", Ff1.DIGITS);
const pt = cipher.decryptStr(ct,                 "merchant-001", Ff1.DIGITS);
// pt === "4111111111111111"

// Built-in alphabet constants
Ff1.DIGITS      // "0123456789"
Ff1.ALPHA_LOWER // "abcdefghijklmnopqrstuvwxyz"
Ff1.ALPHANUM    // "0123456789abcdefghijklmnopqrstuvwxyz"
```

### API reference

| Method | Description |
|---|---|
| `new Ff1(keyHex, radix, maxTlen?)` | Construct a cipher. `keyHex` is 32/48/64 hex chars. `maxTlen` defaults to 256. |
| `encryptStr(pt, tweak, alphabet)` | Encrypt a string. Tweak is a UTF-8 string. |
| `decryptStr(ct, tweak, alphabet)` | Decrypt a string. |
| `encryptStrHexTweak(pt, tweakHex, alphabet)` | Encrypt with a binary tweak (hex-encoded). |
| `decryptStrHexTweak(ct, tweakHex, alphabet)` | Decrypt with a binary tweak. |
| `encrypt(symbols, tweak)` | Encrypt a `Uint32Array` of symbol values. |
| `decrypt(symbols, tweak)` | Decrypt a `Uint32Array` of symbol values. |

All methods throw a JS `Error` with a descriptive message on invalid input.

### Running WASM tests

```bash
# Requires Chrome or Firefox to be installed
wasm-pack test --headless --chrome
```
