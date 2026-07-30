//! Vendor-neutral hardened outbound HTTP client for mechub MCP servers.
//!
//! Provides a reusable HTTP client with strict security defaults: HTTPS-only,
//! no redirects, no proxy autodiscovery, bounded concurrency, and whole-request
//! deadlines. Designed for outbound API calls where credential leakage and
//! resource exhaustion are the primary concerns.
//!
//! ## Response bodies are bounded while they stream
//!
//! `max_response_bytes` is enforced against the running total as each chunk
//! arrives. `Content-Length` is a claim by the peer, so it is used only to fail
//! *earlier* and never as the enforcement — an endpoint can omit it entirely
//! under chunked transfer encoding, or send one value and stream another.
//!
//! ## What this crate does not own
//!
//! The transport posture is shared; everything vendor-shaped stays with the
//! product. This crate has no opinion about endpoint catalogs, header names,
//! payload schemas, authentication flows, terminal job states, or retry and
//! backoff policy — a consumer builds those on top. Nothing here should ever
//! grow vendor vocabulary.
//!
//! ## Security guarantees
//!
//! - **HTTPS only**: plaintext URLs are rejected at construction, not at send.
//! - **No redirects**: 3xx responses are returned as ordinary responses; the
//!   client never follows them automatically (a redirect could send credentials
//!   to an unintended host).
//! - **No proxy**: default features are disabled and `.no_proxy()` is set
//!   explicitly, so proxy environment variables cannot redirect traffic.
//! - **Bounded concurrency**: `max_concurrent_requests` enforced via a
//!   semaphore.
//! - **Whole-request deadline**: covers both permit acquisition and send, so a
//!   caller's deadline is a wall-clock promise and unbounded backlog cannot
//!   form.
//! - **Secrets marked sensitive**: `HeaderValue::set_sensitive(true)` is called
//!   for secret headers and bearer auth, keeping values out of logging paths.
//! - **One wire attempt per `send`**: reqwest's default protocol-NACK retry is
//!   turned off, so a replayable POST cannot be resent behind the caller's back.
//!
//! ## The consumer installs the crypto provider
//!
//! This crate enables reqwest's `rustls-no-provider` feature and picks **no**
//! rustls `CryptoProvider`. That is workspace decision D4, and it is not a
//! detail: reqwest's plain `rustls` feature would enable `rustls/aws-lc-rs`
//! across the whole dependency graph, and a shared crate choosing a provider is
//! how aws-lc-rs was once linked into a ring build and broke TLS. Install one in
//! the binary before constructing a client:
//!
//! ```text
//! rustls::crypto::aws_lc_rs::default_provider()
//!     .install_default()
//!     .expect("provider already installed");
//! ```
//!
//! Shown as text, not a doctest: this crate cannot compile that call, because it
//! deliberately does not enable a provider feature. That is the point.
//!
//! [`HttpClient::new`] returns [`HttpError::NoCryptoProvider`] if none is
//! installed, rather than letting reqwest panic.
//!
//! ## Examples
//!
//! ```
//! use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
//! use mecmcp_secret::OutboundSecret;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = HttpClientConfig {
//!     connect_timeout: Duration::from_secs(10),
//!     request_timeout: Duration::from_secs(30),
//!     max_concurrent_requests: 8,
//!     ..Default::default()
//! };
//!
//! let client = HttpClient::new(config)?;
//!
//! let request = HttpRequest::new(Method::Get, "https://api.example.com/status")?
//!     .header("Accept", "application/json")?;
//!
//! let response = client.send(request).await?;
//! assert_eq!(response.status(), 200);
//! # Ok(())
//! # }
//! ```

use mecmcp_secret::OutboundSecret;
use reqwest::header::{HeaderName, HeaderValue};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// HTTP methods supported by this client.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    /// GET request.
    Get,
    /// POST request.
    Post,
    /// PUT request.
    Put,
    /// PATCH request.
    Patch,
    /// DELETE request.
    Delete,
}

impl From<Method> for reqwest::Method {
    fn from(m: Method) -> Self {
        match m {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
        }
    }
}

/// Configuration for the HTTP client.
///
/// Plain public fields with validation at construction, following the workspace
/// house style.
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Connect timeout for individual connections.
    pub connect_timeout: Duration,
    /// Whole-request deadline covering permit acquisition and send.
    pub request_timeout: Duration,
    /// Maximum concurrent requests allowed.
    pub max_concurrent_requests: usize,
    /// Connection pool idle timeout.
    pub pool_idle_timeout: Duration,
    /// Maximum idle connections per host in the pool.
    pub pool_max_idle_per_host: usize,
    /// User-Agent header value.
    pub user_agent: String,
    /// Maximum response body accepted, in bytes.
    ///
    /// Enforced while the body streams in, not from `Content-Length` — see
    /// [`HttpError::ResponseTooLarge`].
    pub max_response_bytes: usize,
    /// Additional root certificates in PEM format (additive trust only).
    ///
    /// Each string is a PEM-encoded certificate. There is **no** API to disable
    /// certificate verification. This exists to support private-CA endpoints
    /// and integration testing against local TLS servers.
    pub extra_root_certificates: Vec<String>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_concurrent_requests: 8,
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 4,
            max_response_bytes: 8 * 1024 * 1024,
            user_agent: format!("mecmcp-http/{}", env!("CARGO_PKG_VERSION")),
            extra_root_certificates: Vec::new(),
        }
    }
}

/// An HTTP request ready to be sent.
pub struct HttpRequest {
    method: reqwest::Method,
    url: reqwest::Url,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Create a new HTTP request.
    ///
    /// The URL must use the `https://` scheme, must contain a host, and must not
    /// embed credentials. All three are enforced at construction so a bad URL
    /// fails early with a clear error rather than at send.
    ///
    /// Embedded credentials (`https://user:pass@host/`) are rejected because the
    /// URL is echoed in error messages and traces, which would leak the password
    /// on every failure. Pass credentials through [`HttpRequest::bearer_auth`] or
    /// [`HttpRequest::secret_header`] instead — those mark the value sensitive.
    ///
    /// # Errors
    /// Returns [`HttpError::InvalidUrl`] if the URL is malformed,
    /// [`HttpError::InsecureScheme`] if the scheme is not `https://`,
    /// [`HttpError::MissingHost`] if the URL has no host component, or
    /// [`HttpError::UrlHasEmbeddedCredentials`] if it carries userinfo.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_http::{HttpRequest, Method};
    ///
    /// let request = HttpRequest::new(Method::Get, "https://api.example.com/v1/status")?;
    /// # Ok::<(), mecmcp_http::HttpError>(())
    /// ```
    pub fn new(method: Method, url: &str) -> Result<Self, HttpError> {
        // Redacted even on the parse-failure path: a URL too malformed to parse
        // can still carry a readable password, and this error embeds the raw
        // string because there is nothing structured left to report.
        let parsed = reqwest::Url::parse(url).map_err(|error| HttpError::InvalidUrl {
            url: SafeUrl::from_unparsed(url),
            detail: error.to_string(),
        })?;

        // Userinfo is checked FIRST, before the scheme and host checks. Both of
        // those errors embed the URL, so testing them earlier would leak the
        // password for something as ordinary as `http://user:pass@host/` —
        // exactly the disclosure this check exists to prevent.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpError::UrlHasEmbeddedCredentials {
                host: parsed.host_str().unwrap_or_default().to_owned(),
            });
        }

        if parsed.scheme() != "https" {
            return Err(HttpError::InsecureScheme {
                url: SafeUrl::from_parsed(&parsed),
                scheme: parsed.scheme().to_owned(),
            });
        }

        // `url` rejects an empty host for special schemes such as https, so this
        // is a defensive backstop rather than the primary check.
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(HttpError::MissingHost {
                url: SafeUrl::from_parsed(&parsed),
            });
        }

        Ok(Self {
            method: method.into(),
            url: parsed,
            headers: Vec::new(),
            body: None,
        })
    }

    /// Add a header to the request.
    ///
    /// Framing headers (`Content-Length`, `Transfer-Encoding`) are rejected —
    /// those are derived from [`HttpRequest::body`].
    ///
    /// # Errors
    /// Returns [`HttpError::InvalidHeaderName`] if the name is invalid,
    /// [`HttpError::FramingHeaderNotAllowed`] if it is a framing header, or
    /// [`HttpError::InvalidHeaderValue`] if the value is invalid.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_http::{HttpRequest, Method};
    ///
    /// let request = HttpRequest::new(Method::Get, "https://api.example.com/")?
    ///     .header("Accept", "application/json")?;
    /// # Ok::<(), mecmcp_http::HttpError>(())
    /// ```
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, HttpError> {
        let header_name = parse_header_name(name)?;
        let header_value =
            HeaderValue::from_str(value).map_err(|_| HttpError::InvalidHeaderValue {
                name: name.to_owned(),
            })?;
        self.headers.push((header_name, header_value));
        Ok(self)
    }

    /// Add a secret header to the request with `sensitive = true`.
    ///
    /// Calls `HeaderValue::set_sensitive(true)` so the value stays out of
    /// logging paths.
    ///
    /// # Errors
    /// Returns [`HttpError::InvalidHeaderName`] if the name is invalid, or
    /// [`HttpError::InvalidHeaderValue`] if the value is invalid.
    ///
    /// # Examples
    /// ```no_run
    /// use mecmcp_http::{HttpRequest, Method};
    /// use mecmcp_secret::OutboundSecret;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let secret_path = std::path::Path::new("/path/to/secret");
    /// let secret = mecmcp_secret::load_from_file(
    ///     secret_path,
    ///     mecmcp_secret::SecretLimits::default()
    /// )?;
    /// let request = HttpRequest::new(Method::Get, "https://api.example.com/")?
    ///     .secret_header("X-API-Key", &secret)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn secret_header(mut self, name: &str, value: &OutboundSecret) -> Result<Self, HttpError> {
        let header_name = parse_header_name(name)?;
        let mut header_value =
            HeaderValue::from_str(value.expose()).map_err(|_| HttpError::InvalidHeaderValue {
                name: name.to_owned(),
            })?;
        header_value.set_sensitive(true);
        self.headers.push((header_name, header_value));
        Ok(self)
    }

    /// Add bearer authentication via the `Authorization` header.
    ///
    /// Calls `HeaderValue::set_sensitive(true)` so the token stays out of
    /// logging paths.
    ///
    /// # Errors
    /// Returns [`HttpError::InvalidHeaderValue`] if the token is invalid.
    ///
    /// # Examples
    /// ```no_run
    /// use mecmcp_http::{HttpRequest, Method};
    /// use mecmcp_secret::OutboundSecret;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let token_path = std::path::Path::new("/path/to/token");
    /// let token = mecmcp_secret::load_from_file(
    ///     token_path,
    ///     mecmcp_secret::SecretLimits::default()
    /// )?;
    /// let request = HttpRequest::new(Method::Get, "https://api.example.com/")?
    ///     .bearer_auth(&token)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bearer_auth(mut self, token: &OutboundSecret) -> Result<Self, HttpError> {
        // `Zeroizing`, not a bare `String`: the formatted value is a second live
        // copy of the credential, and dropping it plainly would leave it in the
        // heap. The same class of leak was found three times reviewing
        // `mecmcp-secret`.
        let auth_value = Zeroizing::new(format!("Bearer {}", token.expose()));
        let mut header_value =
            HeaderValue::from_str(&auth_value).map_err(|_| HttpError::InvalidHeaderValue {
                name: reqwest::header::AUTHORIZATION.to_string(),
            })?;
        header_value.set_sensitive(true);
        self.headers
            .push((reqwest::header::AUTHORIZATION, header_value));
        Ok(self)
    }

    /// Set the request body.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_http::{HttpRequest, Method};
    ///
    /// let body = b"{\"key\":\"value\"}".to_vec();
    /// let request = HttpRequest::new(Method::Post, "https://api.example.com/data")?
    ///     .header("Content-Type", "application/json")?
    ///     .body(body);
    /// # Ok::<(), mecmcp_http::HttpError>(())
    /// ```
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

impl std::fmt::Debug for HttpRequest {
    /// Metadata only — never the body, never a header value.
    ///
    /// A request body is frequently a credential in its own right: a token
    /// exchange, a login payload, a key-rotation call. Deriving `Debug` would
    /// print those bytes in full, so only the length is reported. Header values
    /// are omitted for the same reason — `set_sensitive` protects the ones routed
    /// through [`HttpRequest::secret_header`], but a caller can always put
    /// something sensitive through plain [`HttpRequest::header`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method.as_str())
            .field("url", &SafeUrl::from_parsed(&self.url))
            .field("headers", &header_names)
            .field("body_bytes", &self.body.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

/// A URL that has been rendered safe to put in a diagnostic.
///
/// The chokepoint for URL disclosure. The **only** ways to obtain one are
/// [`SafeUrl::from_parsed`] and [`SafeUrl::from_unparsed`], both of which strip
/// every credential-bearing component. There is deliberately no `From<String>`,
/// no constructor accepting arbitrary text, and no public field — so an error
/// variant that holds a `SafeUrl` cannot be handed an unredacted URL by
/// construction, rather than by everyone remembering to call a helper.
///
/// That distinction is the whole reason this type exists. Five consecutive
/// review rounds found a credential escaping through a URL in a diagnostic:
/// userinfo, then input with no `://`, then query and fragment, then fragment on
/// the unparsed path, then a bare token used as a query *key* and an `@` inside
/// a query defeating the userinfo scan. Every one was a place that formatted a
/// URL without going through the redaction. Making that unrepresentable is the
/// only fix that generalises.
///
/// # Examples
/// ```
/// # use mecmcp_http::{HttpRequest, Method, HttpError};
/// let error = HttpRequest::new(Method::Get, "https://u:pw@host/?api_key=SEKRIT")
///     .unwrap_err();
/// assert!(!error.to_string().contains("SEKRIT"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeUrl(String);

impl SafeUrl {
    /// Build from a successfully parsed URL.
    ///
    /// Strips userinfo, and drops the query and fragment entirely — replacing
    /// them with a marker that records only that they were present.
    ///
    /// The query is dropped whole rather than having its values blanked. An
    /// earlier version kept the keys, on the grounds that
    /// `?api_key=[redacted]&page=[redacted]` reads usefully; that was wrong,
    /// because an API taking a bare token (`?TOKEN`) parses the credential *as*
    /// the key. Structure is not worth a credential.
    #[must_use]
    pub fn from_parsed(url: &reqwest::Url) -> Self {
        let mut safe = url.clone();
        // Both setters fail only for cannot-be-a-base URLs, which carry no
        // userinfo.
        let _ = safe.set_username("");
        let _ = safe.set_password(None);

        let had_query = safe.query().is_some();
        let had_fragment = safe.fragment().is_some();
        safe.set_query(None);
        safe.set_fragment(None);

        let mut rendered = safe.to_string();
        if had_query {
            rendered.push_str("?[redacted]");
        }
        if had_fragment {
            rendered.push_str("#[redacted]");
        }
        Self(rendered)
    }

    /// Build from a string that could **not** be parsed as a URL.
    ///
    /// Deliberately blunt, because malformed input offers no structure to trust.
    /// The query and fragment are cut first, and only then is the remaining head
    /// scanned for userinfo — that order matters: an `@` inside a query (an
    /// `?email=user@example.com` parameter) would otherwise anchor the userinfo
    /// scan past the `?` and leave everything after it exposed.
    ///
    /// Over-redacting an error message costs a little debuggability.
    /// Under-redacting costs a credential.
    #[must_use]
    pub fn from_unparsed(raw: &str) -> Self {
        let (head, tail_present) = match raw.find(CREDENTIAL_BEARING_DELIMITERS) {
            Some(cut) => (&raw[..cut], true),
            None => (raw, false),
        };

        let mut rendered = match head.rfind('@') {
            Some(at) => format!("[redacted]{}", &head[at..]),
            None => head.to_owned(),
        };
        if tail_present {
            rendered.push_str("[redacted]");
        }
        Self(rendered)
    }

    /// The redacted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Every URL component that can carry a credential.
///
/// Enumerated in one place on purpose. Anything added here must be honoured by
/// both [`SafeUrl::from_parsed`] and [`SafeUrl::from_unparsed`].
///
/// - **userinfo** (`user:pass@`) — HTTP basic auth in a URL.
/// - **query** (`?api_key=…`, or a bare `?TOKEN`) — signed URLs and query-based
///   API keys. The key is as sensitive as the value.
/// - **fragment** (`#access_token=…`) — the OAuth implicit flow.
///
/// The path is deliberately *not* redacted: it is structural, and losing it
/// would leave errors with nothing actionable in them.
const CREDENTIAL_BEARING_DELIMITERS: [char; 2] = ['?', '#'];

/// Read a response body, enforcing `limit` **as the bytes arrive**.
///
/// The only path in this crate that produces a response body. `reqwest`'s
/// `bytes()` and `text()` are never called anywhere, and must not be: they
/// buffer the whole body first, so a limit applied to their result has already
/// let an unbounded allocation happen.
///
/// `Content-Length` is a claim by the peer, so it is used only to fail *earlier*
/// — never as the enforcement. A hostile endpoint can declare 10 bytes and
/// stream gigabytes, or omit the header entirely under `Transfer-Encoding:
/// chunked`. The running total is therefore checked against every chunk, and
/// checked *before* the chunk is appended, so over-limit bytes are never held.
async fn read_body_within_limit(
    response: &mut reqwest::Response,
    limit: usize,
    url: &SafeUrl,
) -> Result<Vec<u8>, HttpError> {
    // Fail fast on an honest oversized declaration, without reading a byte.
    // Only ever an optimisation: a lie here is caught by the loop below.
    if response
        .content_length()
        .is_some_and(|declared| declared > limit as u64)
    {
        return Err(HttpError::ResponseTooLarge {
            limit,
            url: url.clone(),
        });
    }

    // Deliberately not pre-allocated from `Content-Length`: reserving what the
    // peer claims hands it an allocation primitive.
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|error| HttpError::BodyRead {
                url: url.clone(),
                detail: describe_with_causes(&error.without_url()),
            })?;
        let Some(chunk) = chunk else { break };

        // Checked before the append, and with `checked_add` so a pathological
        // length cannot wrap past the comparison.
        //
        // Caveat worth keeping honest: moving this check *after* the append
        // survives mutation testing, because hyper hands out frames bounded by
        // its own read buffer, so no single chunk is large enough for the
        // difference to be observable. Before-append is still the right order —
        // it does not depend on that buffering behaviour staying true — but it
        // rests on review, not on a test.
        let would_be = body.len().checked_add(chunk.len());
        if would_be.is_none_or(|total| total > limit) {
            return Err(HttpError::ResponseTooLarge {
                limit,
                url: url.clone(),
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Render an error together with its source chain.
///
/// `reqwest::Error`'s `Display` prints only the top-level kind — after
/// `without_url()` that is the bare string "error sending request" — while the
/// actionable cause (DNS failure, connection refused, certificate not trusted,
/// protocol error) sits in the source chain. Without this, every transport
/// failure looks identical in the logs.
///
/// The chain is bounded: a cyclic or pathological chain must not spin here.
/// Only reqwest's own `Display` carries the request URL, and that is stripped
/// before this is called, so walking the causes adds no disclosure.
fn describe_with_causes(error: &dyn std::error::Error) -> String {
    const MAX_CAUSES: usize = 8;

    let mut description = error.to_string();
    let mut source = error.source();
    for _ in 0..MAX_CAUSES {
        let Some(cause) = source else { break };
        let text = cause.to_string();
        // Skip a cause that merely restates its parent, which hyper and io
        // layers do often enough to be noisy.
        if !description.contains(&text) {
            description.push_str(": ");
            description.push_str(&text);
        }
        source = cause.source();
    }
    description
}

/// Headers that describe how the body is framed on the wire.
///
/// These are derived from the body, never supplied by a caller. A
/// `Content-Length` that disagrees with `body.len()` panics hyper's HTTP/1
/// encoder in debug builds, and in release builds sends the caller's length with
/// the whole body — desynchronising a pooled connection that later requests will
/// reuse.
const FRAMING_HEADERS: [&str; 2] = ["content-length", "transfer-encoding"];

/// Parse and validate a header name.
///
/// Validating here rather than letting `reqwest` reject it means a typo fails at
/// construction with the name in hand, instead of surfacing later as an opaque
/// transport error.
fn parse_header_name(name: &str) -> Result<HeaderName, HttpError> {
    let parsed = HeaderName::try_from(name).map_err(|_| HttpError::InvalidHeaderName {
        name: name.to_owned(),
    })?;

    // `HeaderName` is already lowercase, so this comparison is total.
    if FRAMING_HEADERS.contains(&parsed.as_str()) {
        return Err(HttpError::FramingHeaderNotAllowed {
            name: parsed.as_str().to_owned(),
        });
    }

    Ok(parsed)
}

/// An HTTP client with hardened defaults.
#[derive(Debug)]
pub struct HttpClient {
    inner: reqwest::Client,
    semaphore: Arc<Semaphore>,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration.
    ///
    /// # Errors
    /// Returns [`HttpError::ConfigValidation`] if the configuration is invalid
    /// (zero timeouts or limits), [`HttpError::NoCryptoProvider`] if the process
    /// has no rustls provider installed, [`HttpError::InvalidRootCertificate`] if
    /// an entry in `extra_root_certificates` is not usable PEM, or
    /// [`HttpError::ClientConstruction`] if the underlying client cannot be built.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_http::{HttpClient, HttpClientConfig, HttpError};
    ///
    /// // Construction needs a rustls CryptoProvider installed by the binary.
    /// // Without one this is the error you get — not a panic, and not a client
    /// // that fails later at the first request.
    /// match HttpClient::new(HttpClientConfig::default()) {
    ///     Ok(client) => { /* ready to send */ }
    ///     Err(HttpError::NoCryptoProvider) => { /* install a provider first */ }
    ///     Err(other) => return Err(other),
    /// }
    /// # Ok::<(), HttpError>(())
    /// ```
    pub fn new(config: HttpClientConfig) -> Result<Self, HttpError> {
        // Validate configuration
        if config.connect_timeout.is_zero() {
            return Err(HttpError::ConfigValidation {
                field: "connect_timeout".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if config.request_timeout.is_zero() {
            return Err(HttpError::ConfigValidation {
                field: "request_timeout".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if config.max_concurrent_requests == 0 {
            return Err(HttpError::ConfigValidation {
                field: "max_concurrent_requests".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if config.max_response_bytes == 0 {
            return Err(HttpError::ConfigValidation {
                field: "max_response_bytes".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        // `Semaphore::new` panics above this bound, and a shared crate must not
        // turn an operator's typo into a crash at service startup.
        if config.max_concurrent_requests > Semaphore::MAX_PERMITS {
            return Err(HttpError::ConfigValidation {
                field: "max_concurrent_requests".to_owned(),
                detail: format!("must not exceed {}", Semaphore::MAX_PERMITS),
            });
        }
        if config.pool_max_idle_per_host == 0 {
            return Err(HttpError::ConfigValidation {
                field: "pool_max_idle_per_host".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if config.pool_idle_timeout.is_zero() {
            return Err(HttpError::ConfigValidation {
                field: "pool_idle_timeout".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }

        // reqwest panics if it needs a provider and none is installed, and a
        // shared crate must not hand a consumer a panic. Report it instead.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(HttpError::NoCryptoProvider);
        }

        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            // reqwest 0.13 retries protocol NACKs twice by default, and these
            // bodies are replayable — so an HTTP/2 GOAWAY or REFUSED_STREAM would
            // silently resend a POST or PATCH that changes device configuration,
            // without the product's retry policy ever seeing the first attempt.
            // Retry policy belongs to the consumer (see README), so this crate
            // makes exactly one wire attempt and lets the caller decide.
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(config.connect_timeout)
            // Deliberately no `.timeout()`. The whole-request deadline in `send`
            // is strictly stronger — it also covers time queued behind the
            // concurrency limit — and setting both to the same value makes the
            // reported error a race between two equal deadlines, so a caller
            // could not tell a slow request from a queued one.
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .user_agent(&config.user_agent);

        // Parse the PEM ourselves rather than handing the bytes to
        // `reqwest::Certificate::from_pem`, which was measured on reqwest 0.13 to
        // accept plainly invalid input without error — a typo'd private-CA file
        // would then produce a client that silently trusts nothing extra and
        // fails much later as an opaque TLS handshake error. Parsing here turns
        // that into an immediate, nameable configuration failure.
        //
        // Iterating rather than taking the first entry matters too: root bundles
        // routinely hold several certificates, and using only the first would be
        // a silent truncation of the trust the operator asked for.
        for (index, cert_pem) in config.extra_root_certificates.iter().enumerate() {
            let mut found = 0usize;
            for entry in CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
                let der = entry.map_err(|error| HttpError::InvalidRootCertificate {
                    index,
                    detail: error.to_string(),
                })?;
                // `reqwest::Certificate::from_der` does not parse the
                // certificate, it only wraps the bytes. Parse it here so that
                // valid base64 carrying malformed DER is reported against the
                // entry that caused it, rather than surfacing later from
                // `builder.build()` with no index attached.
                webpki::anchor_from_trusted_cert(&der).map_err(|error| {
                    HttpError::InvalidRootCertificate {
                        index,
                        detail: error.to_string(),
                    }
                })?;
                let cert = reqwest::Certificate::from_der(&der).map_err(|error| {
                    HttpError::InvalidRootCertificate {
                        index,
                        detail: error.to_string(),
                    }
                })?;
                builder = builder.add_root_certificate(cert);
                found += 1;
            }
            if found == 0 {
                return Err(HttpError::InvalidRootCertificate {
                    index,
                    detail: "no CERTIFICATE block found".to_owned(),
                });
            }
        }

        let inner = builder.build().map_err(|e| HttpError::ClientConstruction {
            detail: e.to_string(),
        })?;

        Ok(Self {
            inner,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            request_timeout: config.request_timeout,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Send an HTTP request.
    ///
    /// The whole-request deadline covers both semaphore permit acquisition and
    /// the send itself, so a caller's deadline is a wall-clock promise and
    /// unbounded backlog cannot form behind the semaphore.
    ///
    /// Redirects are never followed: a 3xx response is returned as an ordinary
    /// response. This prevents credentials from being sent to an unintended
    /// host.
    ///
    /// # Errors
    /// Returns [`HttpError::Timeout`] if the request exceeds the configured
    /// `request_timeout` — including time spent queued behind the concurrency
    /// limit — [`HttpError::LimiterClosed`] if the limiter has been closed,
    /// [`HttpError::Connect`] if the connection could not be established, or
    /// [`HttpError::RequestFailed`] if the request fails after connecting.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
    ///
    /// # async fn example() -> Result<(), mecmcp_http::HttpError> {
    /// let client = HttpClient::new(HttpClientConfig::default())?;
    /// let request = HttpRequest::new(Method::Get, "https://api.example.com/status")?;
    /// let response = client.send(request).await?;
    /// println!("Status: {}", response.status());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        // Computed once, up front: every error below reports it, and the raw URL
        // must never reach any of them.
        let url_for_diagnostics = SafeUrl::from_parsed(&request.url);

        // Whole-request deadline covering permit acquisition and send
        let result = tokio::time::timeout(self.request_timeout, async {
            // Acquire permit (bounded concurrency)
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_| HttpError::LimiterClosed)?;

            // Build the reqwest::Request
            let mut req = self.inner.request(request.method, request.url);
            for (name, value) in request.headers {
                req = req.header(name, value);
            }
            if let Some(body) = request.body {
                req = req.body(body);
            }

            // Send the request. Connect failures are classified separately: an
            // unreachable or untrusted endpoint is an operator problem, and
            // lumping it in with a mid-request failure loses that.
            let mut response = req.send().await.map_err(|error| {
                let is_connect = error.is_connect();
                // `without_url` first: reqwest's Display appends the *raw* URL,
                // query and all, which is where a signed-URL credential lives.
                // Then walk the causes, because reqwest's own Display alone says
                // only "error sending request" for every possible failure.
                let detail = describe_with_causes(&error.without_url());
                let url = url_for_diagnostics.clone();
                if is_connect {
                    HttpError::Connect { url, detail }
                } else {
                    HttpError::RequestFailed { url, detail }
                }
            })?;

            let status = response.status().as_u16();
            // Headers are kept as raw bytes. Converting here — lossily or by
            // skipping — corrupts legal non-UTF-8 field values such as an opaque
            // ETag, and a caller echoing that into If-Match would then send
            // different bytes (#177).
            let headers = response.headers().clone();

            // Note this read happens INSIDE the deadline and while the
            // concurrency permit is still held. Both matter: a body trickled one
            // byte at a time would otherwise run forever, and releasing the
            // permit at the headers would let any number of body reads exceed
            // `max_concurrent_requests`.
            let body = read_body_within_limit(
                &mut response,
                self.max_response_bytes,
                &url_for_diagnostics,
            )
            .await?;

            Ok::<HttpResponse, HttpError>(HttpResponse {
                status,
                headers,
                body,
            })
        })
        .await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_) => Err(HttpError::Timeout {
                url: url_for_diagnostics,
                timeout: self.request_timeout,
            }),
        }
    }
}

/// An HTTP response.
///
/// Phase 2a deliberately provides **no response body API**. That is added in
/// phase 2b with streaming response-size enforcement.
pub struct HttpResponse {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl HttpResponse {
    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response body.
    ///
    /// Bounded by `max_response_bytes`, enforced while the body streamed in.
    ///
    /// Frequently a credential in its own right — a token exchange, a login, a
    /// key rotation — so it is never printed by `Debug` and never appears in an
    /// error.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// A header value as raw bytes, looked up case-insensitively.
    ///
    /// Bytes rather than `&str` on purpose: a legal field value need not be
    /// UTF-8, and converting would corrupt an opaque `ETag` a caller intends to
    /// echo back in `If-Match` (#177).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.get(name).map(HeaderValue::as_bytes)
    }

    /// A header value as a string, or `None` if it is absent or not UTF-8.
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Every header, as name and raw bytes.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
    }
}

impl std::fmt::Debug for HttpResponse {
    /// Status, header **names**, and body **length** only.
    ///
    /// Never a header value (`Set-Cookie` and friends) and never a body byte —
    /// a token-exchange response is the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self.headers.keys().map(HeaderName::as_str).collect();
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &header_names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Errors that can occur when using the HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The URL is invalid.
    #[error("invalid URL '{url}': {detail}")]
    InvalidUrl {
        /// The URL that was invalid, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// Detail about what was invalid.
        detail: String,
    },
    /// The URL uses an insecure scheme (not HTTPS).
    #[error("insecure scheme '{scheme}' in URL '{url}' (only https:// is allowed)")]
    InsecureScheme {
        /// The URL that was rejected, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// The scheme that was used.
        scheme: String,
    },
    /// The URL has no host component.
    #[error("URL '{url}' has no host component")]
    MissingHost {
        /// The URL that was rejected, redacted. See [`SafeUrl`].
        url: SafeUrl,
    },
    /// The URL embeds credentials in its userinfo component.
    ///
    /// Only the host is reported. The URL is deliberately not echoed, because
    /// echoing it is exactly what this rejection exists to prevent.
    #[error(
        "URL for host '{host}' embeds credentials; pass them via bearer_auth or secret_header instead"
    )]
    UrlHasEmbeddedCredentials {
        /// The host the rejected URL named.
        host: String,
    },
    /// A header name is invalid.
    #[error("invalid header name '{name}'")]
    InvalidHeaderName {
        /// The invalid header name.
        name: String,
    },
    /// A framing header was supplied by the caller.
    ///
    /// `Content-Length` and `Transfer-Encoding` are derived from the body. A
    /// caller-supplied value that disagrees with it corrupts the connection.
    #[error("header '{name}' is set from the request body and cannot be supplied")]
    FramingHeaderNotAllowed {
        /// The rejected header name.
        name: String,
    },
    /// A header value is invalid.
    #[error("invalid header value for '{name}'")]
    InvalidHeaderValue {
        /// The header name (value is never included).
        name: String,
    },
    /// Configuration validation failed.
    #[error("configuration field '{field}': {detail}")]
    ConfigValidation {
        /// The field that failed validation.
        field: String,
        /// Detail about the validation failure.
        detail: String,
    },
    /// No process-wide rustls `CryptoProvider` has been installed.
    ///
    /// This crate deliberately does not choose one — the provider is the
    /// consumer's decision, so that a shared crate cannot link aws-lc-rs into a
    /// ring-based binary. Install one before building a client, for example
    /// `rustls::crypto::aws_lc_rs::default_provider().install_default()`.
    #[error(
        "no rustls CryptoProvider installed; call CryptoProvider::install_default() before building an HttpClient"
    )]
    NoCryptoProvider,
    /// An entry in `extra_root_certificates` is not usable.
    #[error("extra_root_certificates[{index}] is not a usable certificate: {detail}")]
    InvalidRootCertificate {
        /// Position in `extra_root_certificates`, so the operator knows which one.
        index: usize,
        /// Detail about why it was rejected.
        detail: String,
    },
    /// Client construction failed.
    #[error("failed to construct HTTP client: {detail}")]
    ClientConstruction {
        /// Detail about the construction failure.
        detail: String,
    },
    /// The request timed out.
    #[error("request to {url} timed out after {timeout:?}")]
    Timeout {
        /// The target, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// The timeout that was exceeded.
        timeout: Duration,
    },
    /// The client's concurrency limiter has been closed.
    ///
    /// Not the same thing as being *at* the limit — reaching the limit makes a
    /// caller wait, and waiting is bounded by `request_timeout`, which surfaces
    /// as [`HttpError::Timeout`]. This variant means the semaphore itself was
    /// closed, which the current implementation never does. It exists so permit
    /// acquisition has no panic path.
    #[error("HTTP client concurrency limiter is closed")]
    LimiterClosed,
    /// The connection could not be established.
    ///
    /// An unreachable host, a refused port, a certificate the client does not
    /// trust, or the connect timeout expiring.
    #[error("failed to connect to {url}: {detail}")]
    Connect {
        /// The target, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// Detail about the connection failure.
        detail: String,
    },
    /// The response body exceeded `max_response_bytes`.
    ///
    /// Reports the limit, never the bytes seen — a body can itself be a
    /// credential.
    #[error("response from {url} exceeded the {limit}-byte limit")]
    ResponseTooLarge {
        /// The configured limit.
        limit: usize,
        /// The target, redacted. See [`SafeUrl`].
        url: SafeUrl,
    },
    /// The response body could not be read.
    #[error("failed to read response body from {url}: {detail}")]
    BodyRead {
        /// The target, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// Detail about the failure.
        detail: String,
    },
    /// The underlying HTTP request failed.
    #[error("request to {url} failed: {detail}")]
    RequestFailed {
        /// The target, redacted. See [`SafeUrl`].
        url: SafeUrl,
        /// Detail about the failure.
        detail: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A distinctive string used to prove secrets never reach error output.
    const CANARY: &str = "canary-delta-9f2c";

    /// Generate a self-signed `localhost` certificate.
    ///
    /// Returns the PEM for the client's `extra_root_certificates` and a matching
    /// rustls server config. ALPN is pinned to `http/1.1` so the canned
    /// byte-level responses below are what the client actually negotiates.
    ///
    /// The crypto provider is named explicitly rather than left to
    /// `ServerConfig::builder`'s auto-detection. Under `cargo test --workspace`,
    /// feature unification enables both the `aws-lc-rs` and `ring` rustls
    /// providers, auto-detection cannot choose, and it panics — while
    /// `cargo test -p mecmcp-http` passes. Naming the provider makes the test
    /// behave the same either way.
    fn tls_material() -> (String, rustls::ServerConfig) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        (cert_pem, server_config)
    }

    /// Read an HTTP request's headers off a stream, stopping at the blank line.
    async fn read_request_head<S>(stream: &mut S)
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() {
            seen.push(byte[0]);
            if seen.ends_with(b"\r\n\r\n") {
                return;
            }
        }
    }

    /// Serve `connections` TLS requests, replying with `response` to each.
    ///
    /// `Connection: close` belongs in every canned response: the pool would
    /// otherwise reuse a socket whose handler has already returned, and the
    /// resulting retry makes connection-counting tests flaky.
    fn serve(
        listener: tokio::net::TcpListener,
        server_config: rustls::ServerConfig,
        response: &'static str,
        connections: usize,
    ) {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    read_request_head(&mut tls).await;
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });
    }

    async fn bind_local() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Install a crypto provider once for the whole test binary.
    ///
    /// The crate deliberately does not pick one (decision D4), so tests stand in
    /// for the consumer binary that must. `install_default` is process-global and
    /// one-shot, which is also why the `NoCryptoProvider` branch cannot be
    /// exercised in-process — see the note on that test.
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn build_client(config: HttpClientConfig) -> Result<HttpClient, HttpError> {
        ensure_crypto_provider();
        HttpClient::new(config)
    }

    fn client_trusting(cert_pem: String) -> HttpClient {
        build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            ..Default::default()
        })
        .unwrap()
    }

    fn secret_holding(value: &str) -> OutboundSecret {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(value.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        mecmcp_secret::load_from_file(&path, mecmcp_secret::SecretLimits::default()).unwrap()
    }

    #[tokio::test]
    async fn successful_https_get() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve(
            listener,
            server_config,
            "HTTP/1.1 200 OK\r\nX-Test-Header: test-value\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );

        let client = client_trusting(cert_pem);
        let request = HttpRequest::new(Method::Get, &format!("https://localhost:{port}/test"))
            .unwrap()
            .header("Accept", "application/json")
            .unwrap();

        let response = client.send(request).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.header_str("x-test-header"), Some("test-value"));
    }

    #[tokio::test]
    async fn request_body_is_transmitted() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        let received = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        {
            let received = Arc::clone(&received);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                read_request_head(&mut tls).await;
                // The payload below is 21 bytes; read exactly that so the test
                // fails on a short body rather than hanging on a long one.
                let mut body = vec![0u8; PAYLOAD.len()];
                let _ = tls.read_exact(&mut body).await;
                *received.lock().await = body;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }

        let client = client_trusting(cert_pem);
        let request = HttpRequest::new(Method::Post, &format!("https://localhost:{port}/submit"))
            .unwrap()
            .header("Content-Type", "application/json")
            .unwrap()
            .body(PAYLOAD.to_vec());

        let response = client.send(request).await.unwrap();
        assert_eq!(response.status(), 204);
        assert_eq!(received.lock().await.as_slice(), PAYLOAD);
    }

    /// Body used by [`request_body_is_transmitted`].
    const PAYLOAD: &[u8] = br#"{"phase":"2a","ok":1}"#;

    #[tokio::test]
    async fn unreachable_endpoint_is_classified_as_connect() {
        // Bind then drop, so the port is almost certainly unbound and the
        // connection is refused rather than timing out.
        let (listener, port) = bind_local().await;
        drop(listener);

        let client = build_client(HttpClientConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap();

        let error = client.send(request).await.unwrap_err();
        assert!(
            matches!(error, HttpError::Connect { .. }),
            "a refused connection should classify as Connect, got {error:?}"
        );
    }

    #[tokio::test]
    async fn untrusted_certificate_is_rejected() {
        // The client is given no extra roots, so the self-signed server
        // certificate must not be accepted. This is the check that would silently
        // stop mattering if verification were ever disabled.
        let (_cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve(
            listener,
            server_config,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );

        let client = build_client(HttpClientConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap();

        assert!(
            client.send(request).await.is_err(),
            "an untrusted self-signed certificate must not be accepted"
        );
    }

    #[tokio::test]
    async fn redirect_is_returned_not_followed() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        // A Location that would fail outright if dialled, so a followed redirect
        // shows up as an error rather than a silently different success.
        serve(
            listener,
            server_config,
            "HTTP/1.1 302 Found\r\nLocation: https://nonexistent.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );

        let client = client_trusting(cert_pem);
        let request =
            HttpRequest::new(Method::Get, &format!("https://localhost:{port}/redirect")).unwrap();

        let response = client.send(request).await.unwrap();
        assert_eq!(response.status(), 302);
        assert_eq!(
            response.header_str("location"),
            Some("https://nonexistent.invalid/")
        );
    }

    #[tokio::test]
    async fn whole_request_deadline_fires() {
        let (cert_pem, _server_config) = tls_material();
        let (listener, port) = bind_local().await;

        // Accept the TCP connection and then go silent, so the TLS handshake
        // never completes and the request can only end by deadline.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });

        // connect_timeout deliberately far longer than request_timeout: the
        // deadline is then the only thing that can fire, so `Timeout` is asserted
        // exactly rather than as one of several acceptable errors.
        let client = build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            request_timeout: Duration::from_millis(250),
            connect_timeout: Duration::from_secs(30),
            ..Default::default()
        })
        .unwrap();

        let request =
            HttpRequest::new(Method::Get, &format!("https://localhost:{port}/hang")).unwrap();

        let error = client.send(request).await.unwrap_err();
        assert!(
            matches!(error, HttpError::Timeout { .. }),
            "expected a deadline error, got {error:?}"
        );
    }

    #[tokio::test]
    async fn queued_request_deadline_counts_queue_time() {
        // One permit, two requests, and a server that answers slowly. The second
        // request spends its whole deadline queued and must still time out —
        // this is the property that stops an unbounded backlog forming.
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    read_request_head(&mut tls).await;
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let client = Arc::new(
            build_client(HttpClientConfig {
                extra_root_certificates: vec![cert_pem],
                max_concurrent_requests: 1,
                request_timeout: Duration::from_millis(300),
                connect_timeout: Duration::from_secs(30),
                ..Default::default()
            })
            .unwrap(),
        );

        let url = format!("https://localhost:{port}/slow");
        let first = tokio::spawn({
            let client = Arc::clone(&client);
            let url = url.clone();
            async move {
                client
                    .send(HttpRequest::new(Method::Get, &url).unwrap())
                    .await
            }
        });
        // Let the first request take the only permit before the second queues.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = client
            .send(HttpRequest::new(Method::Get, &url).unwrap())
            .await;

        let error = second.unwrap_err();
        assert!(
            matches!(error, HttpError::Timeout { .. }),
            "a queued request must time out on the shared deadline, got {error:?}"
        );
        first.abort();
    }

    #[tokio::test]
    async fn concurrency_is_bounded_at_the_configured_limit() {
        const LIMIT: usize = 2;
        const REQUESTS: usize = 6;

        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        {
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let in_flight = Arc::clone(&in_flight);
                    let peak = Arc::clone(&peak);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        read_request_head(&mut tls).await;
                        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        // Hold the request open so overlap is observable at all.
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
        }

        let client = Arc::new(
            build_client(HttpClientConfig {
                extra_root_certificates: vec![cert_pem],
                max_concurrent_requests: LIMIT,
                request_timeout: Duration::from_secs(20),
                ..Default::default()
            })
            .unwrap(),
        );

        let mut handles = Vec::new();
        for _ in 0..REQUESTS {
            let client = Arc::clone(&client);
            let url = format!("https://localhost:{port}/test");
            handles.push(tokio::spawn(async move {
                client
                    .send(HttpRequest::new(Method::Get, &url).unwrap())
                    .await
                    .unwrap()
                    .status()
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap(), 200);
        }

        // Equality, not `<=`: `<=` also passes if the requests never overlapped
        // at all, which would prove nothing about the semaphore.
        assert_eq!(
            peak.load(Ordering::SeqCst),
            LIMIT,
            "peak concurrency should reach the limit and never exceed it"
        );
    }

    #[test]
    fn plaintext_url_rejected() {
        let error = HttpRequest::new(Method::Get, "http://example.com/").unwrap_err();
        assert!(matches!(error, HttpError::InsecureScheme { .. }));
        assert!(error.to_string().contains("only https://"));
    }

    #[test]
    fn non_http_scheme_rejected() {
        let error = HttpRequest::new(Method::Get, "file:///etc/passwd").unwrap_err();
        assert!(matches!(error, HttpError::InsecureScheme { .. }));
    }

    #[test]
    fn hostless_url_rejected() {
        // `url` rejects an empty host for special schemes, so these land in
        // InvalidUrl rather than MissingHost. Asserted so the behaviour is
        // recorded rather than assumed.
        //
        // Note "https:///path" is deliberately NOT here: `url` parses it as host
        // "path", not as a hostless URL. Measured, not assumed.
        for candidate in ["https:", "https://"] {
            let error = HttpRequest::new(Method::Get, candidate).unwrap_err();
            assert!(
                matches!(
                    error,
                    HttpError::InvalidUrl { .. } | HttpError::MissingHost { .. }
                ),
                "{candidate} should be rejected for having no host, got {error:?}"
            );
        }
    }

    #[test]
    fn url_with_embedded_credentials_rejected_without_echoing_them() {
        let error = HttpRequest::new(Method::Get, &format!("https://user:{CANARY}@example.com/"))
            .unwrap_err();
        assert!(matches!(error, HttpError::UrlHasEmbeddedCredentials { .. }));
        let rendered = error.to_string();
        assert!(!rendered.contains(CANARY), "password leaked: {rendered}");
        assert!(!rendered.contains("user"), "username leaked: {rendered}");
        assert!(rendered.contains("example.com"));
    }

    /// No rejection path may echo a URL password, whichever check fires.
    ///
    /// The userinfo check originally ran *after* the scheme and host checks, so
    /// `http://user:pass@host/` was rejected as an insecure scheme with the full
    /// URL — password included — in the message.
    #[test]
    fn no_url_rejection_path_echoes_embedded_credentials() {
        let candidates = [
            format!("http://user:{CANARY}@example.com/"), // insecure scheme
            format!("ftp://user:{CANARY}@example.com/"),  // other scheme
            format!("https://user:{CANARY}@example.com/"), // https, userinfo only
            format!("https://user:{CANARY}@exa mple.com/"), // unparseable
            format!("http://user:{CANARY}@[bad/"),        // unparseable, insecure
            format!("https://{CANARY}@example.com/"),     // username only, no password
            // One missing colon, so there is no "://" delimiter for an authority
            // to start after. The first version of the redaction helper returned
            // this verbatim and leaked the password.
            format!("https//user:{CANARY}@example.com"),
            format!("{CANARY}@example.com"), // no scheme at all
            format!("https:/user:{CANARY}@example.com"), // single slash
            // Unparseable *and* fragment-bearing: no '@', no '?' to cut at.
            format!("https://exa mple.com/#access_token={CANARY}"),
            format!("https://exa mple.com/?api_key={CANARY}"),
            // A bare query token: the credential is the query *key*.
            format!("https://exa mple.com/?{CANARY}"),
            // An '@' inside the query, which defeated an earlier userinfo scan.
            format!("https://exa mple.com/?email=user@example.com&api_key={CANARY}"),
        ];

        for candidate in candidates {
            let error = HttpRequest::new(Method::Get, &candidate).unwrap_err();
            let rendered = error.to_string();
            assert!(
                !rendered.contains(CANARY),
                "credential leaked via {error:?}: {rendered}"
            );
        }
    }

    #[test]
    fn safe_url_from_parsed_drops_userinfo_query_and_fragment() {
        let url =
            reqwest::Url::parse("https://user:pw@example.com/a/b?api_key=SEKRIT&page=2#tok=SEKRIT")
                .unwrap();
        let rendered = SafeUrl::from_parsed(&url).to_string();

        assert!(!rendered.contains("SEKRIT"), "{rendered}");
        assert!(!rendered.contains("pw"), "{rendered}");
        assert!(!rendered.contains("user"), "{rendered}");
        // Query keys go too: an API taking a bare token parses the credential
        // *as* the key.
        assert!(!rendered.contains("api_key"), "{rendered}");
        assert!(rendered.contains("example.com/a/b"), "{rendered}");
        assert!(rendered.contains("?[redacted]"), "{rendered}");
        assert!(rendered.contains("#[redacted]"), "{rendered}");

        // A bare query token is a key with an empty value.
        let bare = reqwest::Url::parse("https://example.com/?SEKRIT").unwrap();
        let rendered = SafeUrl::from_parsed(&bare).to_string();
        assert!(
            !rendered.contains("SEKRIT"),
            "bare query token leaked: {rendered}"
        );

        // An '@' in the path is not userinfo and must survive untouched.
        let plain = reqwest::Url::parse("https://example.com/mail@host").unwrap();
        assert_eq!(
            SafeUrl::from_parsed(&plain).as_str(),
            "https://example.com/mail@host"
        );
    }

    #[test]
    fn safe_url_from_unparsed_cuts_the_tail_before_scanning_for_userinfo() {
        // The ordering bug: an '@' inside the query would anchor the userinfo
        // scan past the '?', leaving everything after it exposed.
        let rendered =
            SafeUrl::from_unparsed("https://exa mple.com/?email=user@example.com&api_key=SEKRIT")
                .to_string();
        assert!(
            !rendered.contains("SEKRIT"),
            "query survived the '@' scan: {rendered}"
        );

        assert_eq!(
            SafeUrl::from_unparsed("https//user:secret@example.com").as_str(),
            "[redacted]@example.com"
        );
        assert_eq!(
            SafeUrl::from_unparsed("https//host?api_key=SEKRIT").as_str(),
            "https//host[redacted]"
        );
        // Fragment credentials — the OAuth implicit flow.
        assert_eq!(
            SafeUrl::from_unparsed("https://exa mple.com/#access_token=SEKRIT").as_str(),
            "https://exa mple.com/[redacted]"
        );
        assert_eq!(
            SafeUrl::from_unparsed("no-at-sign-here").as_str(),
            "no-at-sign-here"
        );
    }

    #[test]
    fn request_debug_omits_body_and_header_values() {
        let secret = secret_holding(CANARY);
        let request = HttpRequest::new(Method::Post, "https://example.com/token")
            .unwrap()
            .bearer_auth(&secret)
            .unwrap()
            .header("X-Trace", "trace-value-visible")
            .unwrap()
            .body(format!(r#"{{"client_secret":"{CANARY}"}}"#).into_bytes());

        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains(CANARY),
            "body or header leaked via Debug: {rendered}"
        );
        assert!(
            !rendered.contains("trace-value-visible"),
            "header value leaked via Debug: {rendered}"
        );
        // Metadata still has to be useful for debugging.
        assert!(rendered.contains("authorization"));
        assert!(rendered.contains("x-trace"));
        assert!(rendered.contains("body_bytes"));
        assert!(rendered.contains("POST"));
    }

    #[test]
    fn malformed_der_inside_valid_pem_names_its_index() {
        // Valid PEM framing and valid base64, but the payload is not a
        // certificate. `reqwest::Certificate::from_der` accepts this, so without
        // local X.509 parsing it would fail later without an index.
        let junk_der = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n";
        let (good_pem, _) = tls_material();

        let error = build_client(HttpClientConfig {
            extra_root_certificates: vec![good_pem, junk_der.to_owned()],
            ..Default::default()
        })
        .unwrap_err();

        assert!(
            matches!(error, HttpError::InvalidRootCertificate { index: 1, .. }),
            "malformed DER should be attributed to entry 1, got {error:?}"
        );
    }

    /// A credential in the query string must not reach any live-send error.
    ///
    /// reqwest's own `Display` appends the raw URL — query included — so this
    /// covers the path where the leak came from the dependency rather than from
    /// this crate's own formatting.
    #[tokio::test]
    async fn send_errors_do_not_leak_query_credentials() {
        // Bind then drop so the connection is refused: a Connect error, which
        // carries reqwest's URL.
        let (listener, port) = bind_local().await;
        drop(listener);

        let client = build_client(HttpClientConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(
            Method::Get,
            &format!("https://localhost:{port}/v1/resource?api_key={CANARY}#frag={CANARY}"),
        )
        .unwrap();

        let error = client.send(request).await.unwrap_err();
        let rendered = error.to_string();
        assert!(
            !rendered.contains(CANARY),
            "query or fragment credential leaked: {rendered}"
        );
        // Still has to say where it was going.
        assert!(rendered.contains("localhost"), "{rendered}");
    }

    #[tokio::test]
    async fn timeout_error_does_not_leak_query_credentials() {
        let (cert_pem, _server_config) = tls_material();
        let (listener, port) = bind_local().await;
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });

        let client = build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            request_timeout: Duration::from_millis(250),
            connect_timeout: Duration::from_secs(30),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(
            Method::Get,
            &format!("https://localhost:{port}/hang?token={CANARY}"),
        )
        .unwrap();

        let error = client.send(request).await.unwrap_err();
        assert!(matches!(error, HttpError::Timeout { .. }), "{error:?}");
        assert!(
            !error.to_string().contains(CANARY),
            "credential leaked: {error}"
        );
    }

    #[test]
    fn request_debug_does_not_leak_query_credentials() {
        let request = HttpRequest::new(
            Method::Get,
            &format!("https://example.com/v1?api_key={CANARY}"),
        )
        .unwrap();
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }

    #[test]
    fn concurrency_above_the_semaphore_bound_is_rejected() {
        // `Semaphore::new` panics above this, so validation has to catch it —
        // an operator typo must not crash service startup.
        let error = build_client(HttpClientConfig {
            max_concurrent_requests: usize::MAX,
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            matches!(error, HttpError::ConfigValidation { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("max_concurrent_requests"));

        // The bound itself must still be accepted.
        assert!(
            build_client(HttpClientConfig {
                max_concurrent_requests: Semaphore::MAX_PERMITS,
                ..Default::default()
            })
            .is_ok()
        );
    }

    /// A transport failure must name its actual cause.
    ///
    /// Without the source chain every failure renders as "error sending
    /// request", so DNS, refused connections and TLS rejections are
    /// indistinguishable in an operator's logs.
    #[tokio::test]
    async fn connect_error_reports_the_underlying_cause() {
        let (listener, port) = bind_local().await;
        drop(listener);

        let client = build_client(HttpClientConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap();

        let error = client.send(request).await.unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.to_lowercase().contains("refused"),
            "the refusal should reach the operator, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn untrusted_certificate_error_names_the_certificate() {
        let (_cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve(
            listener,
            server_config,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );

        let client = build_client(HttpClientConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();
        let request = HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap();

        let rendered = client.send(request).await.unwrap_err().to_string();
        let lowered = rendered.to_lowercase();
        assert!(
            lowered.contains("certificate") || lowered.contains("tls") || lowered.contains("cert"),
            "a TLS rejection should say so, got: {rendered}"
        );
    }

    /// A caller-supplied `Content-Length` corrupts the connection.
    ///
    /// hyper's HTTP/1 encoder panics in debug builds when it disagrees with the
    /// body, and in release builds desynchronises a pooled connection that a
    /// later request will reuse.
    /// A body inside the limit must round-trip byte-exactly.
    #[tokio::test]
    async fn body_under_the_limit_round_trips() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        serve(
            listener,
            server_config,
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
            1,
        );

        let client = client_trusting(cert_pem);
        let response = client
            .send(HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"hello world");
    }

    /// The core acceptance criterion: a chunked response declares no length, so
    /// the running total is the only thing that can bound it.
    ///
    /// The server streams **forever**. That is what makes this decisive rather
    /// than a race: an implementation that buffered the body and measured
    /// afterwards could never return at all, so the 5-second test-side timeout
    /// below fails it. The client's own deadline is set to 60s precisely so that
    /// it cannot be what rescues the test — only the streaming limit can.
    #[tokio::test]
    async fn endless_chunked_body_is_stopped_by_the_streaming_limit() {
        const LIMIT: usize = 4096;

        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            read_request_head(&mut tls).await;
            // No Content-Length: the peer never says how much is coming.
            if tls
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let payload = vec![b'x'; 256];
            let header = format!("{:x}\r\n", payload.len());
            loop {
                if tls.write_all(header.as_bytes()).await.is_err()
                    || tls.write_all(&payload).await.is_err()
                    || tls.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
        });

        let client = build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            max_response_bytes: LIMIT,
            // Deliberately far longer than the test's own timeout.
            request_timeout: Duration::from_secs(60),
            ..Default::default()
        })
        .unwrap();

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            client.send(
                HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap(),
            ),
        )
        .await
        .expect("send did not return — the body was being buffered, not bounded while streaming");

        let error = outcome.unwrap_err();
        assert!(
            matches!(error, HttpError::ResponseTooLarge { limit: LIMIT, .. }),
            "expected a size rejection, got {error:?}"
        );
    }

    /// An honest oversized `Content-Length` is rejected without reading a body.
    #[tokio::test]
    async fn oversized_content_length_is_rejected_before_reading() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;
        let body_written = Arc::new(AtomicUsize::new(0));

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        {
            let body_written = Arc::clone(&body_written);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                read_request_head(&mut tls).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                // Give the client a moment to reject on the header alone.
                tokio::time::sleep(Duration::from_millis(150)).await;
                let payload = vec![b'y'; 1024 * 1024];
                if tls.write_all(&payload).await.is_ok() {
                    body_written.store(payload.len(), Ordering::SeqCst);
                }
            });
        }

        let client = build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            max_response_bytes: 4096,
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .unwrap();

        let error = client
            .send(HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, HttpError::ResponseTooLarge { .. }),
            "got {error:?}"
        );
    }

    /// A body trickled forever must hit the whole-request deadline.
    ///
    /// If the body read sat outside the deadline, this would hang rather than
    /// fail — the slow-loris case.
    #[tokio::test]
    async fn trickled_body_hits_the_deadline() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            read_request_head(&mut tls).await;
            let _ = tls
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            // One byte at a time, forever, never sending the terminating chunk.
            loop {
                if tls.write_all(b"1\r\nz\r\n").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let client = build_client(HttpClientConfig {
            extra_root_certificates: vec![cert_pem],
            max_response_bytes: 1024 * 1024,
            request_timeout: Duration::from_millis(400),
            connect_timeout: Duration::from_secs(30),
            ..Default::default()
        })
        .unwrap();

        let error = client
            .send(HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, HttpError::Timeout { .. }),
            "a trickled body must hit the deadline, got {error:?}"
        );
    }

    /// The concurrency permit must be held until the body is read.
    ///
    /// Releasing it when the headers arrive would let any number of body reads
    /// run at once, which is the interesting half of the limit.
    #[tokio::test]
    async fn permit_is_held_until_the_body_is_read() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        let in_body_phase = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        {
            let in_body_phase = Arc::clone(&in_body_phase);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let in_body_phase = Arc::clone(&in_body_phase);
                    let peak = Arc::clone(&peak);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        read_request_head(&mut tls).await;
                        // Headers first, body later: the window in which a
                        // prematurely released permit would show up.
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                            .await;
                        let current = in_body_phase.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        let _ = tls.write_all(b"done").await;
                        in_body_phase.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
        }

        let client = Arc::new(
            build_client(HttpClientConfig {
                extra_root_certificates: vec![cert_pem],
                max_concurrent_requests: 1,
                request_timeout: Duration::from_secs(20),
                ..Default::default()
            })
            .unwrap(),
        );

        let mut handles = Vec::new();
        for _ in 0..3 {
            let client = Arc::clone(&client);
            let url = format!("https://localhost:{port}/");
            handles.push(tokio::spawn(async move {
                client
                    .send(HttpRequest::new(Method::Get, &url).unwrap())
                    .await
                    .unwrap()
                    .body()
                    .to_vec()
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap(), b"done");
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "a second body read overlapped the first — the permit was released at the headers"
        );
    }

    /// #177: a legal non-UTF-8 header value must survive byte-exactly.
    #[tokio::test]
    async fn non_utf8_header_value_survives_intact() {
        let (cert_pem, server_config) = tls_material();
        let (listener, port) = bind_local().await;

        // obs-text (0x80-0xFF) is legal in a field value. An opaque ETag is the
        // realistic case; a caller echoes it into If-Match.
        let raw = b"HTTP/1.1 200 OK\r\nETag: \"\xC3\x28\xFF\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            read_request_head(&mut tls).await;
            let _ = tls.write_all(raw).await;
            let _ = tls.flush().await;
        });

        let client = client_trusting(cert_pem);
        let response = client
            .send(HttpRequest::new(Method::Get, &format!("https://localhost:{port}/")).unwrap())
            .await
            .unwrap();

        let etag = response.header("etag").expect("ETag should be present");
        assert_eq!(
            etag, b"\"\xC3\x28\xFF\"",
            "the bytes must survive; lossy conversion would replace them with U+FFFD"
        );
        // It is not UTF-8, so the string accessor declines rather than corrupting.
        assert_eq!(response.header_str("etag"), None);
    }

    #[test]
    fn zero_max_response_bytes_is_rejected() {
        let error = build_client(HttpClientConfig {
            max_response_bytes: 0,
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            matches!(error, HttpError::ConfigValidation { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("max_response_bytes"));
    }

    #[test]
    fn framing_headers_are_rejected() {
        for name in ["Content-Length", "content-length", "Transfer-Encoding"] {
            let error = HttpRequest::new(Method::Post, "https://example.com/")
                .unwrap()
                .header(name, "999999")
                .unwrap_err();
            assert!(
                matches!(error, HttpError::FramingHeaderNotAllowed { .. }),
                "{name} should be rejected, got {error:?}"
            );
        }

        // A secret header must not be a way around it either.
        let secret = secret_holding("12345");
        let error = HttpRequest::new(Method::Post, "https://example.com/")
            .unwrap()
            .secret_header("Content-Length", &secret)
            .unwrap_err();
        assert!(matches!(error, HttpError::FramingHeaderNotAllowed { .. }));

        // Ordinary headers still work.
        assert!(
            HttpRequest::new(Method::Post, "https://example.com/")
                .unwrap()
                .header("Content-Type", "application/json")
                .is_ok()
        );
    }

    #[test]
    fn invalid_header_name_rejected_at_construction() {
        let error = HttpRequest::new(Method::Get, "https://example.com/")
            .unwrap()
            .header("Not A Header", "value")
            .unwrap_err();
        assert!(matches!(error, HttpError::InvalidHeaderName { .. }));
        assert!(error.to_string().contains("Not A Header"));
    }

    #[test]
    fn secret_header_error_does_not_contain_the_secret() {
        // An interior newline is invalid in a header value. `load_from_file`
        // strips at most one *trailing* newline, so this one survives to be
        // rejected by HeaderValue.
        let secret = secret_holding(&format!("{CANARY}\nsecond-line"));
        let error = HttpRequest::new(Method::Get, "https://example.com/")
            .unwrap()
            .secret_header("X-API-Key", &secret)
            .unwrap_err();

        assert!(matches!(error, HttpError::InvalidHeaderValue { .. }));
        let rendered = error.to_string();
        assert!(!rendered.contains(CANARY), "secret leaked: {rendered}");
        assert!(
            !rendered.contains("second-line"),
            "secret leaked: {rendered}"
        );
        assert!(rendered.contains("X-API-Key"));
    }

    #[test]
    fn bearer_auth_error_does_not_contain_the_token() {
        let token = secret_holding(&format!("{CANARY}\nsecond-line"));
        let error = HttpRequest::new(Method::Get, "https://example.com/")
            .unwrap()
            .bearer_auth(&token)
            .unwrap_err();

        let rendered = error.to_string();
        assert!(!rendered.contains(CANARY), "token leaked: {rendered}");
        assert!(rendered.contains("authorization"));
    }

    #[test]
    fn secret_header_value_is_marked_sensitive() {
        let secret = secret_holding(CANARY);
        let request = HttpRequest::new(Method::Get, "https://example.com/")
            .unwrap()
            .secret_header("X-API-Key", &secret)
            .unwrap()
            .bearer_auth(&secret)
            .unwrap()
            .header("Accept", "application/json")
            .unwrap();

        for (name, value) in &request.headers {
            let sensitive_expected = name != "accept";
            assert_eq!(
                value.is_sensitive(),
                sensitive_expected,
                "{name} sensitivity flag is wrong"
            );
        }

        // `HeaderValue`'s own Debug prints `Sensitive` in place of the bytes, so
        // debugging a request cannot spill the credential either.
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains(CANARY),
            "secret leaked via Debug: {rendered}"
        );
    }

    #[test]
    fn config_validation_rejects_zero_values() {
        let cases: [(&str, HttpClientConfig); 5] = [
            (
                "connect_timeout",
                HttpClientConfig {
                    connect_timeout: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "request_timeout",
                HttpClientConfig {
                    request_timeout: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "pool_idle_timeout",
                HttpClientConfig {
                    pool_idle_timeout: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "max_concurrent_requests",
                HttpClientConfig {
                    max_concurrent_requests: 0,
                    ..Default::default()
                },
            ),
            (
                "pool_max_idle_per_host",
                HttpClientConfig {
                    pool_max_idle_per_host: 0,
                    ..Default::default()
                },
            ),
        ];

        for (field, config) in cases {
            let error = build_client(config).unwrap_err();
            assert!(
                matches!(error, HttpError::ConfigValidation { .. }),
                "{field} should fail validation, got {error:?}"
            );
            assert!(
                error.to_string().contains(field),
                "the error should name {field}: {error}"
            );
        }
    }

    #[test]
    fn default_config_is_accepted() {
        assert!(build_client(HttpClientConfig::default()).is_ok());
    }

    /// Bad PEM must fail at construction, not at the first request.
    ///
    /// `reqwest::Certificate::from_pem` accepts these without complaint on
    /// reqwest 0.13, which is why the crate parses PEM itself. If that upstream
    /// behaviour ever changes this test still holds; if the local parsing is
    /// removed, it fails.
    #[test]
    fn unusable_root_certificate_rejected_at_construction() {
        let cases = [
            ("not a certificate", "plain text"),
            ("", "empty string"),
            (
                "-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n",
                "PEM framing with junk payload",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
                "a key rather than a certificate",
            ),
        ];

        for (pem, description) in cases {
            let error = build_client(HttpClientConfig {
                extra_root_certificates: vec![pem.to_owned()],
                ..Default::default()
            })
            .unwrap_err();
            assert!(
                matches!(error, HttpError::InvalidRootCertificate { index: 0, .. }),
                "{description} should be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn root_certificate_bundle_loads_every_entry() {
        // Two concatenated certificates: a bundle must not be truncated to its
        // first entry, which would silently narrow the operator's trust.
        let (first_pem, _) = tls_material();
        let (second_pem, _) = tls_material();
        let bundle = format!("{first_pem}{second_pem}");
        assert!(
            build_client(HttpClientConfig {
                extra_root_certificates: vec![bundle],
                ..Default::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn invalid_root_certificate_error_names_its_position() {
        let (good_pem, _) = tls_material();
        let error = build_client(HttpClientConfig {
            extra_root_certificates: vec![good_pem, "junk".to_owned()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(
            error,
            HttpError::InvalidRootCertificate { index: 1, .. }
        ));
        assert!(error.to_string().contains("extra_root_certificates[1]"));
    }

    #[test]
    fn response_debug_shows_header_names_not_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_str(&format!("session={CANARY}")).unwrap(),
        );
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let response = HttpResponse {
            status: 200,
            headers,
            body: format!("{{\"token\":\"{CANARY}\"}}").into_bytes(),
        };
        let rendered = format!("{response:?}");
        assert!(rendered.contains("set-cookie"));
        assert!(rendered.contains("content-type"));
        assert!(
            !rendered.contains(CANARY),
            "header value leaked: {rendered}"
        );
        assert!(!rendered.contains("application/json"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let response = HttpResponse {
            status: 200,
            headers,
            body: Vec::new(),
        };
        assert_eq!(
            response.header_str("Content-Type"),
            Some("application/json")
        );
        assert_eq!(
            response.header_str("CONTENT-TYPE"),
            Some("application/json")
        );
        assert_eq!(
            response.header("Content-Type"),
            Some(&b"application/json"[..])
        );
        assert_eq!(response.header("missing"), None);
    }
}
