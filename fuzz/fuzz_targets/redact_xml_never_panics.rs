#![no_main]
//! `redact_xml_str` is the denylist-and-shape path for NETCONF replies and
//! XML REST responses -- device-controlled bytes, parsed with quick-xml and
//! rewritten before a model sees them. A panic here is reachable the same
//! way as the JSON and text paths.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = mecmcp_redact::redact_xml_str(data);
});
