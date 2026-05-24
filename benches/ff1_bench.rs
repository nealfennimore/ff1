use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ff1::Ff1Cipher;

// ── helpers ───────────────────────────────────────────────────────────────────

fn key_128() -> Vec<u8> {
    hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C")
}

fn key_256() -> Vec<u8> {
    hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn digits(n: usize) -> Vec<u32> {
    (0..n).map(|i| (i % 10) as u32).collect()
}

fn alpha36(n: usize) -> Vec<u32> {
    (0..n).map(|i| (i % 36) as u32).collect()
}

const DIGITS_ALPHABET: &str = "0123456789";
const ALPHA_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const ALPHANUMERIC: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// ── encrypt benchmarks ────────────────────────────────────────────────────────

/// Core encrypt with pre-converted symbol Vec — isolates pure Feistel cost
fn bench_encrypt_radix10(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_radix10");

    for &n in &[6usize, 9, 10, 16, 19] {
        let cipher = Ff1Cipher::new_default(&key_128(), 10).unwrap();
        let pt = digits(n);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("aes128", n), &n, |b, _| {
            b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
        });
    }

    for &n in &[6usize, 9, 10, 16, 19] {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = digits(n);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("aes256", n), &n, |b, _| {
            b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
        });
    }

    group.finish();
}

/// encrypt_str — includes alphabet lookup overhead
fn bench_encrypt_str(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_str");

    // Numeric SSN shape
    {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = "123456789";
        group.bench_function("ssn_9digits", |b| {
            b.iter(|| cipher.encrypt_str(black_box(pt), black_box(&[]), black_box(DIGITS_ALPHABET)))
        });
    }

    // 16-digit card number
    {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = "4111111111111111";
        group.bench_function("card_16digits", |b| {
            b.iter(|| cipher.encrypt_str(black_box(pt), black_box(&[]), black_box(DIGITS_ALPHABET)))
        });
    }

    // Alpha lower name
    {
        let cipher = Ff1Cipher::new_default(&key_256(), 26).unwrap();
        let pt = "johnsmith";
        group.bench_function("name_alpha_lower", |b| {
            b.iter(|| cipher.encrypt_str(black_box(pt), black_box(&[]), black_box(ALPHA_LOWER)))
        });
    }

    // Alphanumeric 9-char
    {
        let cipher = Ff1Cipher::new_default(&key_256(), 62).unwrap();
        let pt = "abc123XYZ";
        group.bench_function("alphanumeric_9", |b| {
            b.iter(|| cipher.encrypt_str(black_box(pt), black_box(&[]), black_box(ALPHANUMERIC)))
        });
    }

    group.finish();
}

// ── decrypt benchmarks ────────────────────────────────────────────────────────

fn bench_decrypt_radix10(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_radix10");

    for &n in &[6usize, 9, 10, 16, 19] {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = digits(n);
        let ct = cipher.encrypt(&pt, &[]).unwrap();

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("aes256", n), &n, |b, _| {
            b.iter(|| cipher.decrypt(black_box(&ct), black_box(&[])))
        });
    }

    group.finish();
}

fn bench_decrypt_str(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_str");

    {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = "123456789";
        let ct = cipher.encrypt_str(pt, &[], DIGITS_ALPHABET).unwrap();
        group.bench_function("ssn_9digits", |b| {
            b.iter(|| {
                cipher.decrypt_str(black_box(&ct), black_box(&[]), black_box(DIGITS_ALPHABET))
            })
        });
    }

    {
        let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
        let pt = "4111111111111111";
        let ct = cipher.encrypt_str(pt, &[], DIGITS_ALPHABET).unwrap();
        group.bench_function("card_16digits", |b| {
            b.iter(|| {
                cipher.decrypt_str(black_box(&ct), black_box(&[]), black_box(DIGITS_ALPHABET))
            })
        });
    }

    group.finish();
}

// ── tweak overhead ────────────────────────────────────────────────────────────

fn bench_tweak_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("tweak_overhead");

    let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();
    let pt = digits(10);
    let tweak10 = b"0123456789".to_vec();
    let tweak32 = vec![0u8; 32];

    group.bench_function("no_tweak", |b| {
        b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
    });
    group.bench_function("tweak_10bytes", |b| {
        b.iter(|| cipher.encrypt(black_box(&pt), black_box(&tweak10)))
    });
    group.bench_function("tweak_32bytes", |b| {
        b.iter(|| cipher.encrypt(black_box(&pt), black_box(&tweak32)))
    });

    group.finish();
}

// ── key size comparison ───────────────────────────────────────────────────────

fn bench_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_sizes");
    let pt = digits(10);

    let key192 = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F");

    let c128 = Ff1Cipher::new_default(&key_128(), 10).unwrap();
    let c192 = Ff1Cipher::new_default(&key192, 10).unwrap();
    let c256 = Ff1Cipher::new_default(&key_256(), 10).unwrap();

    group.bench_function("aes128", |b| {
        b.iter(|| c128.encrypt(black_box(&pt), black_box(&[])))
    });
    group.bench_function("aes192", |b| {
        b.iter(|| c192.encrypt(black_box(&pt), black_box(&[])))
    });
    group.bench_function("aes256", |b| {
        b.iter(|| c256.encrypt(black_box(&pt), black_box(&[])))
    });

    group.finish();
}

// ── radix comparison ──────────────────────────────────────────────────────────

fn bench_radix_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("radix_comparison");

    let cases: &[(u32, &str)] = &[
        (2, "radix2_binary"),
        (10, "radix10_numeric"),
        (26, "radix26_alpha"),
        (36, "radix36_alphanumeric"),
        (62, "radix62_full"),
    ];

    for &(radix, label) in cases {
        let cipher = Ff1Cipher::new_default(&key_256(), radix).unwrap();
        let pt: Vec<u32> = (0..10).map(|i| i % radix).collect();
        group.bench_function(label, |b| {
            b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
        });
    }

    group.finish();
}

// ── BigUint path ──────────────────────────────────────────────────────────────

fn bench_biguint_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("biguint_path");

    let key = key_256();

    // n=48 — last length that fits u128 (fast path)
    let c48 = Ff1Cipher::new_default(&key, 36).unwrap();
    let pt48 = alpha36(48);
    group.bench_function("radix36_n48_u128_path", |b| {
        b.iter(|| c48.encrypt(black_box(&pt48), black_box(&[])))
    });

    // n=49 — first length that requires BigUint (slow path)
    let c49 = Ff1Cipher::new_default(&key, 36).unwrap();
    let pt49 = alpha36(49);
    group.bench_function("radix36_n49_biguint_path", |b| {
        b.iter(|| c49.encrypt(black_box(&pt49), black_box(&[])))
    });

    // n=128 — deep into BigUint path
    let c128 = Ff1Cipher::new_default(&key, 36).unwrap();
    let pt128 = alpha36(128);
    group.bench_function("radix36_n128_biguint_path", |b| {
        b.iter(|| c128.encrypt(black_box(&pt128), black_box(&[])))
    });

    group.finish();
}

// ── construction overhead ─────────────────────────────────────────────────────

fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("construction");

    // Cost of new() — key schedule expansion
    group.bench_function("new_aes128", |b| {
        b.iter(|| Ff1Cipher::new_default(black_box(&key_128()), black_box(10)))
    });
    group.bench_function("new_aes256", |b| {
        b.iter(|| Ff1Cipher::new_default(black_box(&key_256()), black_box(10)))
    });

    group.finish();
}

// ── throughput — ops/sec at typical field sizes ───────────────────────────────

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1));

    let cipher = Ff1Cipher::new_default(&key_256(), 10).unwrap();

    // Simulate a batch of 28 fields — representative of a full JSON document
    let fields: Vec<Vec<u32>> = vec![
        digits(9),  // ssn
        digits(16), // card number
        digits(10), // phone
        digits(9),  // routing
        digits(10), // bank account
        digits(8),  // dob
        digits(3),  // cvv
        digits(4),  // expiry
    ];

    group.bench_function("single_ssn_9digits", |b| {
        let pt = digits(9);
        b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
    });

    group.bench_function("batch_8_fields", |b| {
        b.iter(|| {
            for f in &fields {
                let _ = cipher.encrypt(black_box(f), black_box(&[]));
            }
        })
    });

    group.finish();
}

fn bench_biguint_degradation(c: &mut Criterion) {
    let mut group = c.benchmark_group("biguint_degradation");

    // Disable the default measurement time — long inputs take seconds
    group.measurement_time(std::time::Duration::from_secs(30));
    group.sample_size(10); // fewer samples for long inputs

    let key = key_256();

    // Lengths around and beyond the u128/BigUint crossover for radix 10
    // Crossover at radix 10: floor(128 / log2(10)) = floor(128 / 3.32) = 38
    // So n=38 is last u128, n=39 is first BigUint for radix 10
    let lengths: &[usize] = &[
        // u128 fast path
        10, 20, 30, 38, // BigUint crossover
        39, 40, // BigUint scaling
        50, 64, 100, 128, 256, 512, 1024,
    ];

    for &n in lengths {
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let pt: Vec<u32> = (0..n).map(|i| (i % 10) as u32).collect();

        let path = if n <= 38 { "u128" } else { "biguint" };
        let label = format!("n{}_{}", n, path);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(&label, |b| {
            b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
        });
    }

    group.finish();
}

// Also show radix effect on BigUint crossover point
fn bench_biguint_crossover_by_radix(c: &mut Criterion) {
    let mut group = c.benchmark_group("biguint_crossover_by_radix");
    group.measurement_time(std::time::Duration::from_secs(20));
    group.sample_size(10);

    let key = key_256();

    // For each radix, show the last u128 length and first BigUint length
    // Crossover: floor(128 / log2(radix))
    let cases: &[(u32, usize, usize)] = &[
        // (radix, last_u128_n, first_biguint_n)
        (2, 128, 129), // binary: crossover at 128
        (10, 38, 39),  // decimal: crossover at 38
        (16, 32, 33),  // hex: crossover at 32
        (36, 24, 25),  // base36: crossover at 24 (confirmed in earlier bench)
        (62, 21, 22),  // base62: crossover at 21
    ];

    for &(radix, last_u128, first_biguint) in cases {
        let cipher_u128 = Ff1Cipher::new_default(&key, radix).unwrap();
        let cipher_big = Ff1Cipher::new_default(&key, radix).unwrap();
        let pt_u128: Vec<u32> = (0..last_u128).map(|i| i as u32 % radix).collect();
        let pt_big: Vec<u32> = (0..first_biguint).map(|i| i as u32 % radix).collect();

        group.bench_function(&format!("radix{}_n{}_u128", radix, last_u128), |b| {
            b.iter(|| cipher_u128.encrypt(black_box(&pt_u128), black_box(&[])))
        });

        group.bench_function(&format!("radix{}_n{}_biguint", radix, first_biguint), |b| {
            b.iter(|| cipher_big.encrypt(black_box(&pt_big), black_box(&[])))
        });
    }

    group.finish();
}

// Show O(n^2) BigUint scaling visually
fn bench_biguint_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("biguint_scaling");
    group.measurement_time(std::time::Duration::from_secs(60));
    group.sample_size(10);

    let key = key_256();

    // Evenly spaced lengths deep in BigUint territory
    // These will show the quadratic curve clearly
    let lengths: &[usize] = &[50, 100, 200, 400, 800, 1600, 3200];

    for &n in lengths {
        let cipher = Ff1Cipher::new_default(&key, 10).unwrap();
        let pt: Vec<u32> = (0..n).map(|i| (i % 10) as u32).collect();

        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(&format!("n{}", n), |b| {
            b.iter(|| cipher.encrypt(black_box(&pt), black_box(&[])))
        });
    }

    group.finish();
}

// ── register all benches ──────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_encrypt_radix10,
    bench_encrypt_str,
    bench_decrypt_radix10,
    bench_decrypt_str,
    bench_tweak_overhead,
    bench_key_sizes,
    bench_radix_comparison,
    bench_biguint_degradation,
    bench_biguint_crossover_by_radix,
    bench_biguint_scaling,
    bench_biguint_path,
    bench_construction,
    bench_throughput,
);
criterion_main!(benches);
