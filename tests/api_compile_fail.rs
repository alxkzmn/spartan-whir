#[test]
fn privacy_mode_api_boundaries_are_static() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
