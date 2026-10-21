#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kekkai_fuzz::relay_config(data));
