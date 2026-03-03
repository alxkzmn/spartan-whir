#[test]
fn lib_uses_no_std_guard() {
    let lib_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(lib_rs.contains("#![cfg_attr(not(test), no_std)]"));
}
