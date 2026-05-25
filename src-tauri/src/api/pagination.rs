//! Shared pagination helpers.
//!
//! Routes that accept a client-supplied `limit` clamp it to a per-endpoint
//! maximum. The clamp itself is correct, but a silent clamp hides abuse
//! (a misbehaving client repeatedly asking for `?limit=99999999`) and
//! misleads well-behaved clients that don't know how much data they got.
//!
//! `clamp_with_log` emits an INFO-level tracing event when the clamp fires
//! and returns the effective limit. The caller is expected to surface the
//! effective limit in response metadata (e.g. an `X-Limit-Clamped` header
//! or a JSON field) if its API contract calls for it. Audit M-API-2.

/// Clamp a client-supplied limit into `[min, max]` and emit an `info!` event
/// when the requested value exceeds `max`. Returns the effective value.
pub fn clamp_with_log<T>(endpoint: &'static str, requested: T, min: T, max: T) -> T
where
    T: Copy + Ord + std::fmt::Display,
{
    if requested > max {
        tracing::info!(
            endpoint = endpoint,
            requested = %requested,
            effective = %max,
            "pagination limit clamped to endpoint maximum",
        );
        return max;
    }
    if requested < min {
        return min;
    }
    requested
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_above_max() {
        assert_eq!(clamp_with_log("test", 9999i64, 1, 200), 200);
    }

    #[test]
    fn passes_through_in_range() {
        assert_eq!(clamp_with_log("test", 50i64, 1, 200), 50);
    }

    #[test]
    fn clamps_below_min() {
        assert_eq!(clamp_with_log("test", -5i64, 1, 200), 1);
    }

    #[test]
    fn boundary_at_max_not_logged() {
        assert_eq!(clamp_with_log("test", 200i64, 1, 200), 200);
    }
}
