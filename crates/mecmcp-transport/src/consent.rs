//! Operator intent, carried as types the transport cannot infer.

/// The operator explicitly chose to serve without authentication.
///
/// Required by `HttpTransportConfig::unauthenticated`. The transport cannot
/// infer this: an absent bearer boundary means either a deliberate
/// `--allow-no-auth` or a consumer that forgot, and those were the same value
/// until mecmcp#273 gave them different types.
///
/// **This acknowledgement is loopback-only.** It does not permit an
/// off-loopback bind; `serve_router` refuses that regardless
/// (`ListenerRefusal::UnauthenticatedOffLoopback`).
///
/// The tuple field is private, so this does not compile:
///
/// ```compile_fail
/// let _ = mecmcp_transport::NoAuthAcknowledgement(());
/// ```
///
/// And there is no `Default`, so neither does this:
///
/// ```compile_fail
/// let _: mecmcp_transport::NoAuthAcknowledgement = Default::default();
/// ```
#[derive(Clone, Copy)]
pub struct NoAuthAcknowledgement(());

impl std::fmt::Debug for NoAuthAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoAuthAcknowledgement")
    }
}

impl NoAuthAcknowledgement {
    /// Record that the operator passed `--allow-no-auth`.
    ///
    /// Call this only from a code path that actually read that flag. Calling it
    /// unconditionally reintroduces the defect this type exists to prevent.
    #[must_use]
    pub fn operator_allowed_no_auth() -> Self {
        Self(())
    }
}

/// The operator explicitly accepted a plaintext off-loopback listener.
///
/// Absence is fail-closed: without this, `serve_router` refuses to bind an
/// off-loopback address that has no TLS.
///
/// The tuple field is private, so this does not compile:
///
/// ```compile_fail
/// let _ = mecmcp_transport::InsecureBindAcknowledgement(());
/// ```
///
/// And there is no `Default`, so neither does this:
///
/// ```compile_fail
/// let _: mecmcp_transport::InsecureBindAcknowledgement = Default::default();
/// ```
#[derive(Clone, Copy)]
pub struct InsecureBindAcknowledgement(());

impl std::fmt::Debug for InsecureBindAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InsecureBindAcknowledgement")
    }
}

impl InsecureBindAcknowledgement {
    /// Record that the operator passed `--allow-insecure-bind`.
    #[must_use]
    pub fn operator_allowed_insecure_bind() -> Self {
        Self(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_are_copy_and_debug() {
        let no_auth = NoAuthAcknowledgement::operator_allowed_no_auth();
        let insecure = InsecureBindAcknowledgement::operator_allowed_insecure_bind();
        // Copy semantics: passing one to a config must not move it away from a caller
        // that wants to log it too.
        let _copy = no_auth;
        let _copy2 = insecure;
        assert_eq!(format!("{no_auth:?}"), "NoAuthAcknowledgement");
        assert_eq!(format!("{insecure:?}"), "InsecureBindAcknowledgement");
    }
}
