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

1. Splits the input numeral string into two halves A (length `u = floor(n/2)`) and B (length `v = n - u`)
2. Builds a fixed 16-byte header block P encoding the radix, lengths, and tweak length
3. Builds a variable Q block containing the tweak, a round counter, and `NUMradix(B)` masked to `b` bytes
4. Computes `R = PRF(P || Q)` via **CBC-MAC** (AES-ECB chained over the full P||Q input)
5. Expands R into `d` bytes of keystream using counter mode: `S = R || AES(R⊕1) || ...`
6. Updates A as `C = (NUMradix(A) + NUM(S)) mod radix^m`, then swaps halves

The underlying cipher is **AES-ECB**, used both for the CBC-MAC chain and the keystream expansion.

### Key parameters

| Parameter | Value |
|---|---|
| Tweak length | 0 to `maxTlen` bytes (variable, default max 256) |
| Rounds | 10 |
| Supported key sizes | 128, 192, 256 bits |
| Radix range | 2 – 65536 |
| Min plaintext length | 2 symbols |
| Max plaintext length | `2^32 - 1` symbols (NIST SP 800-38G §5.2) |

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

### Arithmetic

Intermediate values — `NUMradix(A/B)`, `modulus = radix^m`, and the Feistel accumulator — are computed using one of two paths chosen automatically at runtime:

**u128 fast path** — used when `radix^max(u,v) < 2^128`. This covers essentially all common usage: radix 10 up to ~76 symbols, radix 36 up to ~48 symbols, radix 2 up to 256 symbols. No heap allocation in the hot path.

**BigUint path** — engaged automatically for longer inputs where intermediate values would overflow `u128`. The switch is transparent; no configuration is needed.

The crossover point per radix:

| radix | max n on u128 path | BigUint required above |
|------:|-------------------:|-----------------------:|
| 2     | 256                | 257                    |
| 10    | 76                 | 77                     |
| 36    | 48                 | 49                     |
| 65536 | 16                 | 17                     |

`y = NUM(S[0..d])` is derived from at most one 16-byte AES block and always fits in `u128`, so `num-bigint` is only pulled in for `NUMradix`, `pow`, and `str_m_radix` on the large path.

### Cargo.toml dependencies

```toml
[dependencies]
aes          = "0.8"
num-bigint   = "0.4"
num-traits   = "0.4"
```

---

## Usage

### Numeric symbols (radix 10)

```rust
use ff1::Ff1Cipher;

let key   = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
let tweak = b"my-record-id";

let cipher = Ff1Cipher::new_default(&key, 10)?;

let plaintext  = vec![0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9];
let ciphertext = cipher.encrypt(&plaintext, tweak)?;
let recovered  = cipher.decrypt(&ciphertext, tweak)?;

assert_eq!(recovered, plaintext);
```

### String interface with custom alphabet

```rust
let cipher   = Ff1Cipher::new_default(&key, 10)?;
let alphabet = "0123456789";

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

### Long inputs (BigUint path)

Long inputs are handled automatically — no API change required:

```rust
// radix=36, 128 symbols: requires BigUint (36^64 > 2^128)
let cipher = Ff1Cipher::new_default(&key, 36)?;
let pt: Vec<u32> = (0..128).map(|i| i % 36).collect();
let ct = cipher.encrypt(&pt, &[])?;
assert_eq!(cipher.decrypt(&ct, &[])?, pt);
```

### Custom max tweak length

```rust
let cipher = Ff1Cipher::new(&key, 10, 32)?;
```

---

## Test vectors

Tests cover:

- **All 9 NIST SP 800-38G sample vectors** (samples 1–9, AES-128/192/256, radix 10 and 36) verified against the [official NIST PDF](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf)
- **4 Zcash FF1 radix-2 vectors** from the [zcash-test-vectors](https://github.com/zcash-hackworks/zcash-test-vectors) reference implementation, including an 88-bit input with a 255-byte tweak
- **All-zero AES-256 key** with radix-2 32-bit input
- **BigUint path coverage**: boundary crossover (n=49), odd-length input (n=127), and non-empty tweak on the BigUint path
- **CapitalOne long round-trip**: 128-symbol radix-36 input (ported from [capitalone/fpe TestLong](https://github.com/capitalone/fpe/blob/master/ff1/ff1_test.go))
- **Minimum length** (n=2): exhaustive test over all 100 two-digit radix-10 inputs
- Error handling: bad key length, tweak too long, short plaintext, out-of-range symbols, invalid radix

```bash
cargo test
```

---

## Security considerations

- **Tweak**: Bind the tweak to a record identifier, table name, or tenant ID so the same plaintext encrypts differently in different contexts, preventing cross-context correlation.
- **Domain size**: NIST Rev 1 requires `radix^n >= 1,000,000`. Short inputs over small alphabets (e.g. 4-digit PINs: `10^4 = 10,000`) do not meet this threshold and provide weak security.
- **Key management**: Treat the AES key with the same care as any symmetric key. Compromise allows full decryption of all tokenised values.
- **Not authenticated encryption**: FF1 provides confidentiality but not integrity or authenticity. A ciphertext can be modified without detection. Layer an authenticated scheme on top if integrity matters.
- **Performance**: FF1 makes more AES calls per round than FF3-1. For high-throughput batch tokenisation with a fixed 7-byte tweak, FF3-1 may be preferable.

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

await init();

const cipher = new Ff1("2B7E151628AED2A6ABF7158809CF4F3C", 10);

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
wasm-pack test --headless --chrome
```
