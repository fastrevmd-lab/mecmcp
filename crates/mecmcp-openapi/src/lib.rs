//! Vendor-neutral URL path expansion and bounded pagination.
//!
//! Two small pieces, both about not trusting a value that reaches a URL.
//!
//! ## Reject rather than repair
//!
//! Neither half sanitises. A silently rewritten value is a value the caller did
//! not send, and a caller that believes it asked for one thing and got another
//! is worse off than one handed an error. This programme has paid four times for
//! substitutions that looked total and were not — see the note on
//! [`page`] — so nothing here clamps, truncates, or "fixes" its input.
//!
//! Percent-encoding is the single exception, and it is not a rewrite: it is the
//! defined wire representation of a segment.

use std::fmt::Write as _;

/// Characters that may appear unescaped in a path segment.
///
/// RFC 3986 `unreserved`, and nothing else. Every sub-delimiter is encoded even
/// though some are technically legal in a segment, because a value carrying `;`
/// or `=` raw is far more likely to be an injection attempt than a deliberate
/// matrix parameter, and encoding it still round-trips to the same value.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// A path template could not be expanded.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// A parameter value would span more than one path segment.
    ///
    /// Reported for a literal `/` and for any percent-encoded form of one. An
    /// extra segment does not decorate a request, it addresses a different
    /// endpoint.
    #[error("parameter '{name}' would span more than one path segment")]
    SegmentBreak {
        /// The offending parameter.
        name: String,
    },
    /// A parameter value would start a query or fragment.
    #[error("parameter '{name}' would start a query or fragment")]
    QueryOrFragment {
        /// The offending parameter.
        name: String,
    },
    /// A parameter value navigates the hierarchy.
    #[error("parameter '{name}' is a relative path component")]
    RelativeComponent {
        /// The offending parameter.
        name: String,
    },
    /// A parameter value is empty, which would collapse a segment.
    #[error("parameter '{name}' is empty; the segment would collapse")]
    Empty {
        /// The offending parameter.
        name: String,
    },
    /// A parameter value contains a control byte.
    #[error("parameter '{name}' contains a control character")]
    ControlCharacter {
        /// The offending parameter.
        name: String,
    },
    /// The template still holds an unfilled placeholder.
    ///
    /// A leftover brace reaching a live URL is how a caller ends up requesting
    /// `/devices/%7BdeviceId%7D` and getting a 404 that names nothing useful.
    #[error("template placeholder '{{{name}}}' was not supplied")]
    MissingParameter {
        /// The placeholder left unfilled.
        name: String,
    },
    /// A parameter was supplied that the template does not mention.
    ///
    /// Almost always a typo, and silently dropping it would send a request to a
    /// less specific endpoint than the caller intended.
    #[error("parameter '{name}' does not appear in the template")]
    UnknownParameter {
        /// The unused parameter.
        name: String,
    },
    /// The template's braces are unbalanced.
    #[error("template has an unterminated '{{' placeholder")]
    MalformedTemplate,
}

/// Expand `{placeholder}` parameters into a path template.
///
/// Each value occupies exactly one segment. Anything that would change the
/// shape of the request — an extra segment, a relative component, a query, a
/// fragment — is an error rather than something to be escaped away, because a
/// caller passing `a/b` for a device identifier has a bug worth hearing about.
///
/// Values are percent-encoded to RFC 3986 `unreserved`. That is a
/// representation change, not a rewrite: the segment decodes to exactly what was
/// passed in.
///
/// # Errors
/// Returns [`PathError`] if a value would break out of its segment, if a
/// placeholder is unfilled, or if a supplied parameter is not in the template.
///
/// # Examples
/// ```
/// use mecmcp_openapi::expand_path;
///
/// let path = expand_path("/v1/devices/{id}/policies", &[("id", "fw-01")])?;
/// assert_eq!(path, "/v1/devices/fw-01/policies");
///
/// // A value that would add a segment is refused, not escaped away.
/// assert!(expand_path("/v1/devices/{id}", &[("id", "a/b")]).is_err());
/// # Ok::<(), mecmcp_openapi::PathError>(())
/// ```
pub fn expand_path(template: &str, params: &[(&str, &str)]) -> Result<String, PathError> {
    let mut out = String::with_capacity(template.len());
    let mut used = vec![false; params.len()];
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        // A `}` in the literal text before a placeholder is unmatched.
        if rest[..open].contains('}') {
            return Err(PathError::MalformedTemplate);
        }
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(PathError::MalformedTemplate);
        };
        let name = &after[..close];

        let index = params
            .iter()
            .position(|(candidate, _)| *candidate == name)
            .ok_or_else(|| PathError::MissingParameter {
                name: name.to_owned(),
            })?;
        used[index] = true;

        out.push_str(&encode_segment(name, params[index].1)?);
        rest = &after[close + 1..];
    }
    // ... and so is one in the tail. `/v1/devices/{id}}` and `/v1/devices/id}`
    // both used to sail through and put a stray brace on the wire.
    if rest.contains('}') {
        return Err(PathError::MalformedTemplate);
    }
    out.push_str(rest);

    // A parameter the template never mentions is a typo, and dropping it
    // silently would address a less specific endpoint than intended.
    if let Some(position) = used.iter().position(|seen| !seen) {
        return Err(PathError::UnknownParameter {
            name: params[position].0.to_owned(),
        });
    }

    Ok(out)
}

/// Validate one parameter value and render it as a single segment.
fn encode_segment(name: &str, value: &str) -> Result<String, PathError> {
    if value.is_empty() {
        return Err(PathError::Empty {
            name: name.to_owned(),
        });
    }
    if value == "." || value == ".." {
        return Err(PathError::RelativeComponent {
            name: name.to_owned(),
        });
    }

    for byte in value.bytes() {
        match byte {
            b'/' | b'\\' => {
                return Err(PathError::SegmentBreak {
                    name: name.to_owned(),
                });
            }
            b'?' | b'#' => {
                return Err(PathError::QueryOrFragment {
                    name: name.to_owned(),
                });
            }
            _ if byte.is_ascii_control() => {
                return Err(PathError::ControlCharacter {
                    name: name.to_owned(),
                });
            }
            _ => {}
        }
    }

    // Raw bytes are not enough. An earlier version of this comment asserted that
    // "no decoding happens downstream that this function did not produce" — an
    // assumption about other people's infrastructure, stated as fact. It is
    // wrong wherever an ingress proxy decodes and then the application decodes
    // again: `%2f` leaves here as `%252f`, becomes `%2f` after the first decode,
    // and `/` after the second. The parameter alters the path structure after
    // all.
    //
    // So the value is decoded repeatedly until it stops changing, and rejected
    // if any intermediate form is structural. That covers arbitrary decode
    // depth instead of assuming one.
    if let Some(error) = structural_after_decoding(name, value) {
        return Err(error);
    }

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            // Infallible: writing to a String cannot fail.
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    Ok(encoded)
}

/// Bytes that change a URL's structure rather than its content.
fn is_structural(byte: u8) -> bool {
    matches!(byte, b'/' | b'\\' | b'?' | b'#') || byte.is_ascii_control()
}

/// Detect a value that becomes structural once something downstream decodes it.
///
/// Decoding is applied repeatedly, because a request can pass through more than
/// one decoder — a proxy and then the application is the ordinary case. Bounded
/// at four rounds, which is far past any real topology and stops a crafted input
/// from spinning here.
fn structural_after_decoding(name: &str, value: &str) -> Option<PathError> {
    const MAX_DECODE_ROUNDS: usize = 4;

    let mut current = value.to_owned();
    for _ in 0..MAX_DECODE_ROUNDS {
        let decoded = percent_decode_lossy(&current);
        if decoded == current {
            return None;
        }
        if decoded.bytes().any(is_structural) {
            return Some(PathError::SegmentBreak {
                name: name.to_owned(),
            });
        }
        if decoded == "." || decoded == ".." {
            return Some(PathError::RelativeComponent {
                name: name.to_owned(),
            });
        }
        current = decoded;
    }
    // Still changing after four rounds: too many layers to reason about.
    Some(PathError::SegmentBreak {
        name: name.to_owned(),
    })
}

/// Percent-decode one round, leaving invalid escapes as literal text.
///
/// Lossy on purpose: the question is only "could this become structural", and a
/// malformed escape that a lenient decoder would pass through must be examined
/// as that decoder would see it.
fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = &bytes[index + 1..index + 3];
            if let Some(byte) = std::str::from_utf8(pair)
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Bounds accepted by [`page`].
#[derive(Debug, Clone, Copy)]
pub struct PageLimits {
    /// Largest page size a caller may request.
    pub max_size: u32,
    /// Largest offset a caller may request.
    ///
    /// Deep-offset scans are how a read endpoint becomes a denial of service:
    /// most backends walk to the offset before returning anything.
    pub max_from: u32,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            max_size: 1000,
            max_from: 100_000,
        }
    }
}

/// A validated pagination window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    /// Offset of the first item.
    pub from: u32,
    /// Number of items requested.
    pub size: u32,
}

/// A pagination request that was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PageError {
    /// `size` was zero.
    ///
    /// Named explicitly in #90's acceptance criteria. Several APIs read 0 as
    /// "no limit", which turns a paging bug into a full-table read.
    #[error("page size must be at least 1; 0 is not 'unbounded' here")]
    ZeroSize,
    /// `size` exceeded the configured maximum.
    #[error("page size {requested} exceeds the maximum of {maximum}")]
    SizeTooLarge {
        /// What was asked for.
        requested: u64,
        /// What is allowed.
        maximum: u32,
    },
    /// `from` exceeded the configured maximum.
    #[error("page offset {requested} exceeds the maximum of {maximum}")]
    FromTooLarge {
        /// What was asked for.
        requested: u64,
        /// What is allowed.
        maximum: u32,
    },
    /// `from + size` would overflow the window.
    #[error("page window {from}+{size} overflows")]
    WindowOverflow {
        /// The offset.
        from: u64,
        /// The size.
        size: u64,
    },
}

/// Validate a pagination request.
///
/// Takes `u64` and returns `u32` so the narrowing is explicit and checked. A
/// caller reading `from`/`size` out of JSON has a `u64` in hand; an `as` cast at
/// that call site is where the value silently wraps.
///
/// **Nothing is clamped.** An oversized request is refused, not quietly
/// shrunk — a caller that believes it received 10 000 rows and actually received
/// 100 will page from the wrong offset and skip the difference without ever
/// seeing an error. That failure is invisible in exactly the way the four
/// numeric-range defects already found in this programme were invisible.
///
/// # Errors
/// Returns [`PageError`] for a zero size, a size or offset above `limits`, or a
/// window that overflows.
///
/// # Examples
/// ```
/// use mecmcp_openapi::{page, PageLimits};
///
/// let window = page(0, 50, PageLimits::default())?;
/// assert_eq!(window.size, 50);
///
/// // Zero is refused rather than read as "everything".
/// assert!(page(0, 0, PageLimits::default()).is_err());
/// # Ok::<(), mecmcp_openapi::PageError>(())
/// ```
pub fn page(from: u64, size: u64, limits: PageLimits) -> Result<Page, PageError> {
    if size == 0 {
        return Err(PageError::ZeroSize);
    }
    if size > u64::from(limits.max_size) {
        return Err(PageError::SizeTooLarge {
            requested: size,
            maximum: limits.max_size,
        });
    }
    if from > u64::from(limits.max_from) {
        return Err(PageError::FromTooLarge {
            requested: from,
            maximum: limits.max_from,
        });
    }
    // Checked in `u64`, where the operands already live, so the sum cannot wrap
    // before it is examined. Both are within `u32` by the checks above, so this
    // is defence against a future limits change rather than a live hazard.
    // The exclusive end must fit the output width, not merely the input width.
    // With `PageLimits` set to `u32::MAX`, `from + size` is representable in
    // `u64` but not in `u32`, and a caller computing its next offset then wraps
    // in release or panics in debug.
    let end = from.checked_add(size);
    if end.is_none_or(|end| end > u64::from(u32::MAX)) {
        return Err(PageError::WindowOverflow { from, size });
    }

    // Infallible after the bounds checks; `try_from` rather than `as` so a
    // future change to the limits cannot silently truncate instead.
    let from = u32::try_from(from).map_err(|_| PageError::FromTooLarge {
        requested: from,
        maximum: limits.max_from,
    })?;
    let size = u32::try_from(size).map_err(|_| PageError::SizeTooLarge {
        requested: size,
        maximum: limits.max_size,
    })?;
    Ok(Page { from, size })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn expands_a_plain_template() {
        assert_eq!(
            expand_path("/v1/devices/{id}/policies", &[("id", "fw-01")]).unwrap(),
            "/v1/devices/fw-01/policies"
        );
    }

    #[test]
    fn a_template_without_placeholders_is_unchanged() {
        assert_eq!(expand_path("/v1/health", &[]).unwrap(), "/v1/health");
    }

    #[test]
    fn expands_several_placeholders() {
        assert_eq!(
            expand_path(
                "/v1/devices/{device}/policies/{policy}",
                &[("device", "fw-01"), ("policy", "p-9")]
            )
            .unwrap(),
            "/v1/devices/fw-01/policies/p-9"
        );
    }

    /// Every shape that would change the request, one case per row of #192.
    #[test]
    fn a_value_can_never_escape_its_segment() {
        let hostile = [
            ("a/b", PathError::SegmentBreak { name: "id".into() }),
            ("a\\b", PathError::SegmentBreak { name: "id".into() }),
            ("..", PathError::RelativeComponent { name: "id".into() }),
            (".", PathError::RelativeComponent { name: "id".into() }),
            ("?x=1", PathError::QueryOrFragment { name: "id".into() }),
            ("#frag", PathError::QueryOrFragment { name: "id".into() }),
            ("", PathError::Empty { name: "id".into() }),
            ("a\0b", PathError::ControlCharacter { name: "id".into() }),
            ("a\nb", PathError::ControlCharacter { name: "id".into() }),
            ("a\rb", PathError::ControlCharacter { name: "id".into() }),
        ];

        for (value, expected) in hostile {
            let result = expand_path("/v1/devices/{id}", &[("id", value)]);
            assert_eq!(
                result,
                Err(expected),
                "value {value:?} was not refused correctly"
            );
        }
    }

    /// An encoded separator is refused, at any decode depth.
    ///
    /// The first version of this crate encoded `%2f` to `%252f` and reasoned
    /// that one downstream decode yields the literal text `%2f`. That assumed
    /// exactly one decoder. With an ingress proxy decoding and then the
    /// application decoding, `%252f` becomes `%2f` becomes `/` — and the
    /// parameter changes the path after all.
    #[test]
    fn encoded_separators_are_refused_at_any_decode_depth() {
        let escapes = [
            "%2f", "%2F", // one decode away from '/'
            "%252f", "%252F",   // two decodes away
            "%25252f", // three
            "%5c", "%5C", // backslash
            "%3f", // query
            "%23", // fragment
            "%00", // NUL
        ];

        for value in escapes {
            assert!(
                expand_path("/v1/devices/{id}", &[("id", value)]).is_err(),
                "{value} was accepted; it decodes to a structural character"
            );
        }
    }

    /// `%2e%2e` decodes to `..`, which climbs the hierarchy.
    #[test]
    fn encoded_dot_segments_are_refused() {
        for value in ["%2e%2e", "%2E%2E", "%252e%252e"] {
            assert!(
                expand_path("/v1/a/{id}/b", &[("id", value)]).is_err(),
                "{value} was accepted; it decodes to a relative component"
            );
        }
    }

    /// A literal `%` that never becomes structural is still allowed.
    ///
    /// The check is about what a value decodes *to*, not about banning a
    /// character outright — over-rejecting is its own kind of wrong.
    #[test]
    fn a_harmless_percent_is_still_accepted() {
        let path = expand_path("/v1/a/{id}", &[("id", "100%25done")]).unwrap();
        assert!(path.starts_with("/v1/a/"), "got {path}");
        assert_eq!(path.matches('/').count(), 3);
    }

    #[test]
    fn reserved_characters_are_percent_encoded() {
        let path = expand_path("/v1/q/{id}", &[("id", "a b&c=d;e+f")]).unwrap();
        assert_eq!(path, "/v1/q/a%20b%26c%3Dd%3Be%2Bf");
        // Nothing structural survives.
        assert_eq!(path.matches('/').count(), 3);
        assert!(!path.contains('&') && !path.contains('='));
    }

    #[test]
    fn non_ascii_is_encoded_as_utf8_bytes() {
        let path = expand_path("/v1/n/{id}", &[("id", "café")]).unwrap();
        assert_eq!(path, "/v1/n/caf%C3%A9");
    }

    #[test]
    fn an_unfilled_placeholder_is_an_error() {
        assert_eq!(
            expand_path("/v1/devices/{id}", &[]),
            Err(PathError::MissingParameter { name: "id".into() })
        );
    }

    #[test]
    fn an_unknown_parameter_is_an_error() {
        assert_eq!(
            expand_path("/v1/health", &[("id", "fw-01")]),
            Err(PathError::UnknownParameter { name: "id".into() })
        );
    }

    #[test]
    fn an_unterminated_placeholder_is_an_error() {
        assert_eq!(
            expand_path("/v1/devices/{id", &[("id", "fw-01")]),
            Err(PathError::MalformedTemplate)
        );
    }

    /// The structural invariant, over a broad set of hostile values: the result
    /// must have the template's segment count, and no query or fragment.
    #[test]
    fn expansion_preserves_the_templates_shape() {
        let template = "/v1/a/{id}/b";
        let expected_segments = template.matches('/').count();

        let values = [
            "ok", "a b", "a%2fb", "a%b", "a;b", "a=b", "a&b", "a@b", "a:b", "a[b]", "a|b", "a~b",
            "a.b", "a..b", "...", "a\"b", "a'b", "a<b>", "a{b}", "%00", "%2e%2e", "café", "🔒",
        ];

        for value in values {
            let Ok(path) = expand_path(template, &[("id", value)]) else {
                continue; // refusal is always an acceptable outcome
            };
            assert_eq!(
                path.matches('/').count(),
                expected_segments,
                "value {value:?} changed the segment count: {path}"
            );
            assert!(!path.contains('?'), "value {value:?} added a query: {path}");
            assert!(
                !path.contains('#'),
                "value {value:?} added a fragment: {path}"
            );
            assert!(
                path.starts_with("/v1/a/") && path.ends_with("/b"),
                "got {path}"
            );
        }
    }

    #[test]
    fn a_legitimate_value_round_trips() {
        // Percent-encoding is a representation change, so decoding returns the
        // original value exactly.
        let value = "fw 01/x"; // refused, so use a legal one below
        assert!(expand_path("/v1/a/{id}", &[("id", value)]).is_err());

        let legal = "fw 01+beta";
        let path = expand_path("/v1/a/{id}", &[("id", legal)]).unwrap();
        let segment = path.rsplit('/').next().unwrap();
        assert_eq!(percent_decode(segment), legal);
    }

    /// Minimal decoder, for round-trip assertions only.
    fn percent_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn an_unmatched_closing_brace_is_an_error() {
        for template in ["/v1/devices/{id}}", "/v1/devices/id}", "/v1/}/{id}", "}"] {
            assert_eq!(
                expand_path(template, &[("id", "fw-01")]),
                Err(PathError::MalformedTemplate),
                "template {template:?} was accepted"
            );
        }
    }

    /// The window's exclusive end must fit the output width.
    ///
    /// At `u32::MAX` limits, `from + size` is representable in `u64` but not in
    /// `u32`; a caller computing its next offset then wraps in release or panics
    /// in debug.
    #[test]
    fn a_window_whose_end_exceeds_u32_is_refused() {
        let limits = PageLimits {
            max_size: u32::MAX,
            max_from: u32::MAX,
        };

        let error = page(u64::from(u32::MAX), 1, limits).unwrap_err();
        assert_eq!(
            error,
            PageError::WindowOverflow {
                from: u64::from(u32::MAX),
                size: 1,
            }
        );

        // The largest representable window is still accepted.
        assert!(page(u64::from(u32::MAX) - 1, 1, limits).is_ok());
    }

    #[test]
    fn zero_size_is_refused() {
        assert_eq!(
            page(0, 0, PageLimits::default()),
            Err(PageError::ZeroSize),
            "0 must not be read as 'unbounded'"
        );
    }

    #[test]
    fn an_oversized_page_is_refused_not_clamped() {
        let limits = PageLimits {
            max_size: 100,
            max_from: 1000,
        };
        let error = page(0, 10_000, limits).unwrap_err();
        assert_eq!(
            error,
            PageError::SizeTooLarge {
                requested: 10_000,
                maximum: 100,
            }
        );
        // The point of refusing: a clamp would have returned 100 here and the
        // caller would page from the wrong offset for the rest of the scan.
        assert!(page(0, 100, limits).is_ok(), "the boundary itself is legal");
    }

    #[test]
    fn a_deep_offset_is_refused() {
        let limits = PageLimits {
            max_size: 100,
            max_from: 1000,
        };
        assert_eq!(
            page(1001, 10, limits).unwrap_err(),
            PageError::FromTooLarge {
                requested: 1001,
                maximum: 1000,
            }
        );
        assert!(
            page(1000, 10, limits).is_ok(),
            "the boundary itself is legal"
        );
    }

    /// Values beyond `u32` must be refused, never truncated.
    ///
    /// An `as` cast here would turn `u32::MAX as u64 + 1` into 0 — a page size
    /// of zero, or an offset that silently restarts the scan.
    #[test]
    fn values_beyond_u32_are_refused_not_truncated() {
        let limits = PageLimits::default();
        let beyond = u64::from(u32::MAX) + 1;

        assert!(matches!(
            page(0, beyond, limits).unwrap_err(),
            PageError::SizeTooLarge { .. }
        ));
        assert!(matches!(
            page(beyond, 10, limits).unwrap_err(),
            PageError::FromTooLarge { .. }
        ));
        assert!(matches!(
            page(u64::MAX, u64::MAX, limits).unwrap_err(),
            PageError::SizeTooLarge { .. }
        ));
    }

    #[test]
    fn a_valid_window_is_returned_unchanged() {
        let window = page(250, 50, PageLimits::default()).unwrap();
        assert_eq!(
            window,
            Page {
                from: 250,
                size: 50
            }
        );
    }

    #[test]
    fn default_limits_are_sane() {
        let limits = PageLimits::default();
        assert!(limits.max_size > 0);
        assert!(page(0, u64::from(limits.max_size), limits).is_ok());
        assert!(page(u64::from(limits.max_from), 1, limits).is_ok());
    }
}
