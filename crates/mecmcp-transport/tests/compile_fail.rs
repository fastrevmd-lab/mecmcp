//! The removed constructors must stay removed (mecmcp#273).
//!
//! ## What this guards
//!
//! Pre-0.9.0, `HttpTransportConfig::new` could build an unauthenticated listener
//! with nothing recording that anyone chose unauthenticated mode. mecmcp#273
//! removed that constructor — this test fails if it is reintroduced.
//!
//! ## If this test fails after you changed `authenticated` or `unauthenticated`
//!
//! The `.stderr` fixture embeds rustc's `note:` block quoting the full
//! signatures of those constructors. Any parameter rename, type change, or
//! reordering makes this test fail, even though the guard is still valid.
//!
//! **To fix:**
//! 1. Run: `TRYBUILD=overwrite cargo test -p mecmcp-transport --test compile_fail`
//! 2. **Read the regenerated `.stderr`** and confirm it still reports **E0599**
//!    with `new` not found. If it reports anything else (import error, syntax
//!    error), the test is broken and proves nothing — fix the UI test source
//!    until the error is E0599, then regenerate again.
//! 3. Commit the regenerated fixture.
//!
//! **Do not delete this test to make your build green.** It is the only thing
//! in the codebase that detects `new` being re-added. Regenerating blindly
//! without confirming E0599 turns this into a test that passes while proving
//! nothing.

#[test]
fn unauthenticated_config_requires_an_acknowledgement() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/unauthenticated_without_acknowledgement.rs");
}
