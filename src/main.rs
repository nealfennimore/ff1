use ff1::Ff1Cipher;

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
    let alpha_digits = "0123456789";

    println!("=== FF1 Demo ===\n");

    // --- NIST Sample 1 ---
    let c1  = Ff1Cipher::new_default(&key, 10).unwrap();
    let pt1 = "0123456789";
    let ct1 = c1.encrypt_str(pt1, &[], alpha_digits).unwrap();
    let rt1 = c1.decrypt_str(&ct1, &[], alpha_digits).unwrap();
    println!("[NIST Sample 1] radix=10, no tweak");
    println!("  PT:         {}", pt1);
    println!("  CT:         {}  (expected: 2433477484)", ct1);
    println!("  Decrypted:  {}", rt1);
    println!("  Pass: {}\n", if ct1 == "2433477484" { "✓" } else { "✗" });

    // --- NIST Sample 2 ---
    let tweak2 = hex_bytes("39383736353433323130");
    let ct2    = c1.encrypt_str(pt1, &tweak2, alpha_digits).unwrap();
    let rt2    = c1.decrypt_str(&ct2, &tweak2, alpha_digits).unwrap();
    println!("[NIST Sample 2] radix=10, tweak=39383736353433323130");
    println!("  PT:         {}", pt1);
    println!("  CT:         {}  (expected: 6124200773)", ct2);
    println!("  Decrypted:  {}", rt2);
    println!("  Pass: {}\n", if ct2 == "6124200773" { "✓" } else { "✗" });

    // --- Credit card tokenisation ---
    let ccn   = "4111111111111111";
    let tweak = b"merchant-001";
    let ct_cc = c1.encrypt_str(ccn, tweak, alpha_digits).unwrap();
    let rt_cc = c1.decrypt_str(&ct_cc, tweak, alpha_digits).unwrap();
    println!("[Credit card tokenisation]");
    println!("  PT:         {}", ccn);
    println!("  CT:         {}", ct_cc);
    println!("  Decrypted:  {}", rt_cc);
    println!("  Round-trip: {}\n", if rt_cc == ccn { "✓" } else { "✗" });

    // --- Alphabetic (radix=26) ---
    let c26   = Ff1Cipher::new_default(&key, 26).unwrap();
    let alpha = "abcdefghijklmnopqrstuvwxyz";
    let msg   = "secretmessage";
    let ct_al = c26.encrypt_str(msg, b"mytweak", alpha).unwrap();
    let rt_al = c26.decrypt_str(&ct_al, b"mytweak", alpha).unwrap();
    println!("[Alphabetic radix=26]");
    println!("  PT:         {}", msg);
    println!("  CT:         {}", ct_al);
    println!("  Decrypted:  {}", rt_al);
    println!("  Round-trip: {}", if rt_al == msg { "✓" } else { "✗" });
}