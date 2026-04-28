use std::env;
use std::fs;
use std::path::PathBuf;

const OBFUSCATION_KEY: u8 = 0x5a;

fn main() {
    println!("cargo:rerun-if-changed=assets/Rules.go");

    let source = fs::read("assets/Rules.go").expect("web fingerprint rules should be readable");
    let obfuscated = source
        .iter()
        .map(|byte| (byte ^ OBFUSCATION_KEY).to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let output = format!("const RULES_SOURCE: &[u8] = &[{obfuscated}];\n");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR should be set"));
    fs::write(out_dir.join("rules_obfuscated.rs"), output)
        .expect("obfuscated web fingerprint rules should be writable");
}
