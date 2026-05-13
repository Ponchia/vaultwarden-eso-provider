#![no_main]

use libfuzzer_sys::fuzz_target;

use bweso_bitwarden::EncryptedString;

// Property: parsing arbitrary bytes-as-UTF-8 into an EncryptedString must
// never panic. Any malformed input must surface as a typed error.
fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let _ = raw.parse::<EncryptedString>();
});
