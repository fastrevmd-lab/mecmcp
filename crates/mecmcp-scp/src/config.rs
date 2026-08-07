//! SSH configuration for SCP connections.

use mecmcp_secret::OutboundSecret;
use std::path::PathBuf;

/// SSH connection configuration for SCP client.
#[derive(Clone)]
pub struct SshConfig {
    /// Hostname or IP address.
    pub host: String,
    /// SSH port (typically 22).
    pub port: u16,
    /// Username for authentication.
    pub username: String,
    /// SSH authentication method.
    pub auth: SshAuth,
    /// Host key verification policy.
    pub host_key_verification: HostKeyVerification,
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("host_key_verification", &self.host_key_verification)
            .finish()
    }
}

/// SSH authentication method.
#[derive(Clone)]
pub enum SshAuth {
    /// Use a specific private key file.
    PrivateKey {
        /// Path to the private key file.
        path: PathBuf,
        /// Optional passphrase for encrypted keys (redacted in Debug output).
        passphrase: Option<OutboundSecret>,
    },
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::PrivateKey { path, passphrase } => f
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
        }
    }
}

/// Host key verification policy.
#[derive(Clone, Debug)]
pub enum HostKeyVerification {
    /// Verify against known_hosts file (strict mode).
    ///
    /// Unknown hosts are rejected. Use `AcceptNew` to add new hosts.
    KnownHosts(PathBuf),

    /// Verify against known_hosts file, accept new hosts.
    ///
    /// Unknown hosts are added to the known_hosts file on first connection.
    /// Changed keys are still rejected.
    AcceptNew(PathBuf),

    /// Accept a specific host key fingerprint (SHA256 base64).
    ///
    /// Example: `"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"` or
    /// `"nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"` (SHA256: prefix optional).
    Fingerprint(String),

    /// Accept any host key (insecure, for testing only).
    AcceptAll,
}
