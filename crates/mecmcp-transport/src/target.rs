//! Target-device extraction and per-target concurrency primitives.

use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Return sorted, unique, exact target device names from top-level `tools/call`
/// arguments. Invalid protocol input is left for rmcp to diagnose.
///
/// `target_keys` defines which argument field names are recognized as containing
/// device targets. Junos uses `["router", "router_name", "routers", "router_names"]`;
/// PAN-OS uses `["device", "devices"]`.
pub fn extract_targets(body: &[u8], target_keys: &[String]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };

    let mut targets = BTreeSet::new();
    match &value {
        Value::Array(requests) => {
            for request in requests {
                collect_request_targets(request, target_keys, &mut targets);
            }
        }
        request => collect_request_targets(request, target_keys, &mut targets),
    }
    targets.into_iter().collect()
}

fn collect_request_targets(
    request: &Value,
    target_keys: &[String],
    targets: &mut BTreeSet<String>,
) {
    let Some(request) = request.as_object() else {
        return;
    };
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return;
    }
    let Some(arguments) = request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("arguments"))
        .and_then(Value::as_object)
    else {
        return;
    };

    for key in target_keys {
        if let Some(value) = arguments.get(key.as_str()) {
            collect_field_targets(value, targets);
        }
    }
}

fn collect_field_targets(value: &Value, targets: &mut BTreeSet<String>) {
    match value {
        Value::String(target) => {
            targets.insert(target.clone());
        }
        Value::Array(target_list) => {
            targets.extend(
                target_list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
        }
        _ => {}
    }
}

/// Per-target concurrency limiter.
///
/// Tracks in-flight request counts per target device using weak references to
/// semaphores. Idle targets are automatically reclaimed when their semaphore's
/// strong count reaches zero.
#[derive(Clone)]
pub struct TargetLimiter {
    max: usize,
    semaphores: Arc<Mutex<HashMap<String, Weak<Semaphore>>>>,
    #[cfg(test)]
    registry_resolution_phases: Arc<AtomicUsize>,
}

impl TargetLimiter {
    /// Create a new target limiter with the given per-target concurrency cap.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            semaphores: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            registry_resolution_phases: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn resolve_semaphores(&self, targets: &[String]) -> Vec<Arc<Semaphore>> {
        #[cfg(test)]
        self.registry_resolution_phases
            .fetch_add(1, Ordering::Relaxed);
        let mut semaphores = self
            .semaphores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        semaphores.retain(|_, semaphore| semaphore.strong_count() > 0);

        let mut resolved = Vec::with_capacity(targets.len());
        for target in targets {
            if let Some(semaphore) = semaphores.get(target).and_then(Weak::upgrade) {
                resolved.push(semaphore);
                continue;
            }

            let semaphore = Arc::new(Semaphore::new(self.max.max(1)));
            semaphores.insert(target.clone(), Arc::downgrade(&semaphore));
            resolved.push(semaphore);
        }
        resolved
    }

    /// Try to acquire permits for all target devices atomically.
    ///
    /// Returns `Ok` with a vec of permits if all targets are under their limit,
    /// or `Err` with the first exhausted target's name if any limit is hit.
    /// On partial failure, all already-acquired permits are automatically dropped.
    pub fn try_acquire(&self, targets: &[String]) -> Result<Vec<OwnedSemaphorePermit>, String> {
        if self.max == 0 || targets.is_empty() {
            return Ok(Vec::new());
        }

        let semaphores = self.resolve_semaphores(targets);
        let mut permits = Vec::with_capacity(targets.len());
        for (target, semaphore) in targets.iter().zip(semaphores) {
            match semaphore.try_acquire_owned() {
                Ok(permit) => permits.push(permit),
                Err(_) => return Err(target.clone()),
            }
        }
        Ok(permits)
    }

    #[cfg(test)]
    fn registry_len(&self) -> usize {
        self.semaphores
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(test)]
    fn registry_resolution_phase_count(&self) -> usize {
        self.registry_resolution_phases.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{TargetLimiter, extract_targets};

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn keys(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn same_target_sheds_while_different_target_is_independent() {
        let limiter = TargetLimiter::new(1);
        let held = limiter.try_acquire(&names(&["t1"])).unwrap();

        assert_eq!(limiter.try_acquire(&names(&["t1"])).unwrap_err(), "t1");
        let other = limiter.try_acquire(&names(&["t2"])).unwrap();

        drop(other);
        drop(held);
        assert!(limiter.try_acquire(&names(&["t1"])).is_ok());
    }

    #[test]
    fn partial_multi_target_acquisition_rolls_back() {
        let limiter = TargetLimiter::new(1);
        let held_b = limiter.try_acquire(&names(&["b"])).unwrap();

        assert_eq!(limiter.try_acquire(&names(&["a", "b"])).unwrap_err(), "b");
        assert!(
            limiter.try_acquire(&names(&["a"])).is_ok(),
            "the failed batch must release its already-acquired a permit"
        );
        drop(held_b);
    }

    #[test]
    fn zero_disables_target_permits() {
        let limiter = TargetLimiter::new(0);
        assert!(limiter.try_acquire(&names(&["t1"])).unwrap().is_empty());
        assert!(limiter.try_acquire(&names(&["t1"])).unwrap().is_empty());
    }

    #[test]
    fn weak_registry_reclaims_idle_target_names() {
        let limiter = TargetLimiter::new(1);
        let held = limiter.try_acquire(&names(&["old"])).unwrap();
        assert_eq!(limiter.registry_len(), 1);
        drop(held);

        let replacement = limiter.try_acquire(&names(&["new"])).unwrap();
        assert_eq!(limiter.registry_len(), 1);
        drop(replacement);
    }

    #[test]
    fn high_cardinality_batch_resolves_registry_once() {
        let limiter = TargetLimiter::new(1);
        let targets = (0..256)
            .map(|index| format!("target-{index:03}"))
            .collect::<Vec<_>>();

        let permits = limiter.try_acquire(&targets).unwrap();

        assert_eq!(permits.len(), targets.len());
        assert_eq!(limiter.registry_resolution_phase_count(), 1);
    }

    #[test]
    fn junos_keys_extract_from_single_and_batched_calls() {
        let junos_keys = keys(&["router", "router_name", "routers", "router_names"]);
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"one","arguments":{"router":"r4"}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"two","arguments":{"router_name":"r3"}}},
            {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"three","arguments":{"routers":["r2","r1"]}}},
            {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"four","arguments":{"router_names":"r5"}}}
        ]"#;

        assert_eq!(
            extract_targets(body, &junos_keys),
            vec!["r1", "r2", "r3", "r4", "r5"]
        );
    }

    #[test]
    fn panos_keys_extract_from_single_and_batched_calls() {
        let panos_keys = keys(&["device", "devices"]);
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"one","arguments":{"device":"d3"}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"two","arguments":{"devices":["d1","d2"]}}}
        ]"#;

        assert_eq!(extract_targets(body, &panos_keys), vec!["d1", "d2", "d3"]);
    }

    #[test]
    fn cross_key_isolation_junos_ignores_panos_and_vice_versa() {
        let junos_keys = keys(&["router", "router_name", "routers", "router_names"]);
        let panos_keys = keys(&["device", "devices"]);
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"router":"r1","device":"d1"}}}"#;

        assert_eq!(extract_targets(body, &junos_keys), vec!["r1"]);
        assert_eq!(extract_targets(body, &panos_keys), vec!["d1"]);
    }

    #[test]
    fn deduplicates_exact_names_and_sorts_them() {
        let junos_keys = keys(&["router", "router_name", "routers", "router_names"]);
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"batch","arguments":{"router":"b","router_name":"a","routers":["b","a","c"]}}}"#;
        assert_eq!(extract_targets(body, &junos_keys), vec!["a", "b", "c"]);
    }

    #[test]
    fn ignores_non_tools_calls_nested_keys_invalid_types_and_malformed_json() {
        let junos_keys = keys(&["router", "router_name", "routers", "router_names"]);
        let non_tool = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"arguments":{"router":"r1"}}}"#;
        let nested = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"payload":{"router":"nested"},"router":17,"routers":[false,42]}}}"#;

        assert!(extract_targets(non_tool, &junos_keys).is_empty());
        assert!(extract_targets(nested, &junos_keys).is_empty());
        assert!(extract_targets(b"not-json", &junos_keys).is_empty());
    }

    #[test]
    fn preserves_exact_case_and_whitespace() {
        let junos_keys = keys(&["router", "router_name", "routers", "router_names"]);
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"routers":["SRX-1","srx-1"," srx-1 "]}}}"#;
        assert_eq!(
            extract_targets(body, &junos_keys),
            vec![" srx-1 ", "SRX-1", "srx-1"]
        );
    }
}
