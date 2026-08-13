//! The removed constructors must stay removed (mecmcp#273).

#[test]
fn unauthenticated_config_requires_an_acknowledgement() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/unauthenticated_without_acknowledgement.rs");
}
