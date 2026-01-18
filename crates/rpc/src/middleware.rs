//! RPC server middleware for rate limiting, IP filtering, and request logging.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use governor::{Quota, RateLimiter};
use tracing::{debug, info, warn};

use crate::metrics;

/// Type alias for the governor rate limiter to reduce type complexity.
type GovernorLimiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// Per-IP rate limiter using the governor crate.
pub struct IpRateLimiter {
    /// Rate limiters keyed by IP address.
    limiters: RwLock<HashMap<IpAddr, Arc<GovernorLimiter>>>,
    /// Requests per second limit.
    rate_per_second: NonZeroU32,
    /// Burst size.
    burst_size: NonZeroU32,
}

impl IpRateLimiter {
    /// Create a new IP rate limiter.
    pub fn new(rate_per_second: u32, burst_size: u32) -> Self {
        let rate = NonZeroU32::new(rate_per_second).unwrap_or(NonZeroU32::new(1000).unwrap());
        let burst = NonZeroU32::new(burst_size).unwrap_or(NonZeroU32::new(100).unwrap());

        Self {
            limiters: RwLock::new(HashMap::new()),
            rate_per_second: rate,
            burst_size: burst,
        }
    }

    /// Check if a request from the given IP should be allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        // Get or create limiter for this IP
        let limiter = {
            let limiters = self.limiters.read().expect("RwLock poisoned");
            if let Some(limiter) = limiters.get(&ip) {
                Arc::clone(limiter)
            } else {
                drop(limiters);
                let mut limiters = self.limiters.write().expect("RwLock poisoned");
                // Double-check after acquiring write lock
                if let Some(limiter) = limiters.get(&ip) {
                    Arc::clone(limiter)
                } else {
                    let quota =
                        Quota::per_second(self.rate_per_second).allow_burst(self.burst_size);
                    let limiter = Arc::new(RateLimiter::direct(quota));
                    limiters.insert(ip, Arc::clone(&limiter));
                    limiter
                }
            }
        };

        match limiter.check() {
            Ok(_) => true,
            Err(_) => {
                debug!("Rate limit exceeded for IP: {}", ip);
                metrics::record_rate_limit_rejection();
                false
            }
        }
    }

    /// Clean up stale entries (IPs that haven't been seen for a while).
    /// This should be called periodically to prevent memory leaks.
    pub fn cleanup_stale_entries(&self) {
        let mut limiters = self.limiters.write().expect("RwLock poisoned");
        // Simple cleanup: remove entries with refcount == 1 (only our map holds them)
        limiters.retain(|_, limiter| Arc::strong_count(limiter) > 1);
    }
}

impl Default for IpRateLimiter {
    fn default() -> Self {
        Self::new(1000, 100)
    }
}

/// IP allowlist filter.
#[derive(Debug, Clone)]
pub struct IpAllowlist {
    /// Allowed IP addresses. None means all IPs are allowed.
    allowed_ips: Option<Vec<IpAddr>>,
}

impl IpAllowlist {
    /// Create a new IP allowlist.
    pub fn new(allowed_ips: Option<Vec<IpAddr>>) -> Self {
        Self { allowed_ips }
    }

    /// Check if an IP is allowed.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        match &self.allowed_ips {
            Some(allowed) => allowed.contains(ip),
            None => true, // No allowlist = all allowed
        }
    }

    /// Check if the allowlist is active (has entries).
    pub fn is_active(&self) -> bool {
        self.allowed_ips.is_some()
    }
}

impl Default for IpAllowlist {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Request timing information for logging.
pub struct RequestTiming {
    /// Request start time.
    start: Instant,
    /// RPC method name.
    method: String,
}

impl RequestTiming {
    /// Create a new request timing.
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            method: method.into(),
        }
    }

    /// Complete the request and log the result.
    pub fn complete(self, status: &str) {
        let duration = self.start.elapsed();
        let duration_secs = duration.as_secs_f64();

        info!(
            method = %self.method,
            status = %status,
            duration_ms = duration.as_millis(),
            "RPC request completed"
        );

        // Record metrics
        if status == "success" {
            metrics::record_request_success(&self.method, duration_secs);
        } else {
            metrics::record_request_error(&self.method, duration_secs);
        }
    }

    /// Get elapsed time without completing.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Combined middleware context for RPC requests.
pub struct RpcMiddleware {
    /// Rate limiter.
    pub rate_limiter: Arc<IpRateLimiter>,
    /// IP allowlist.
    pub allowlist: IpAllowlist,
}

impl RpcMiddleware {
    /// Create new RPC middleware with the given configuration.
    pub fn new(
        rate_limit_per_ip: u32,
        rate_limit_burst: u32,
        ip_allowlist: Option<Vec<IpAddr>>,
    ) -> Self {
        Self {
            rate_limiter: Arc::new(IpRateLimiter::new(rate_limit_per_ip, rate_limit_burst)),
            allowlist: IpAllowlist::new(ip_allowlist),
        }
    }

    /// Check if a request from the given IP should be processed.
    /// Returns Ok(()) if allowed, Err with reason if rejected.
    pub fn check_request(&self, ip: IpAddr) -> Result<(), &'static str> {
        // Check IP allowlist first
        if !self.allowlist.is_allowed(&ip) {
            warn!("Request from non-allowed IP rejected: {}", ip);
            return Err("IP not in allowlist");
        }

        // Check rate limit
        if !self.rate_limiter.check(ip) {
            return Err("Rate limit exceeded");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = IpRateLimiter::new(10, 5);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First burst should be allowed
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }

        // Additional requests may be rate limited depending on timing
        // This is a basic smoke test
    }

    #[test]
    fn test_ip_allowlist() {
        let allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let blocked_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // No allowlist = all allowed
        let allowlist = IpAllowlist::new(None);
        assert!(allowlist.is_allowed(&allowed_ip));
        assert!(allowlist.is_allowed(&blocked_ip));

        // With allowlist
        let allowlist = IpAllowlist::new(Some(vec![allowed_ip]));
        assert!(allowlist.is_allowed(&allowed_ip));
        assert!(!allowlist.is_allowed(&blocked_ip));
    }

    #[test]
    fn test_middleware() {
        let middleware = RpcMiddleware::new(1000, 100, None);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should be allowed
        assert!(middleware.check_request(ip).is_ok());
    }
}
