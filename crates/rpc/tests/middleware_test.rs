//! Integration tests for RPC middleware (rate limiting, IP allowlist).

use std::net::IpAddr;

use cipherbft_rpc::{IpAllowlist, IpRateLimiter, RpcMiddleware};

/// Test IP allowlist with no restrictions.
#[test]
fn test_allowlist_open() {
    let allowlist = IpAllowlist::new(None);

    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.1".parse().unwrap();

    assert!(allowlist.is_allowed(&ip1));
    assert!(allowlist.is_allowed(&ip2));
    assert!(!allowlist.is_active());
}

/// Test IP allowlist with specific IPs.
#[test]
fn test_allowlist_restricted() {
    let allowed_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let blocked_ip: IpAddr = "10.0.0.1".parse().unwrap();

    let allowlist = IpAllowlist::new(Some(vec![allowed_ip]));

    assert!(allowlist.is_allowed(&allowed_ip));
    assert!(!allowlist.is_allowed(&blocked_ip));
    assert!(allowlist.is_active());
}

/// Test rate limiter allows burst.
#[test]
fn test_rate_limiter_burst() {
    let limiter = IpRateLimiter::new(100, 10); // 100/sec, burst of 10
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    // First 10 requests should pass immediately (burst)
    for _ in 0..10 {
        assert!(limiter.check(ip));
    }

    // After burst, some requests may be rate limited
    // depending on timing
}

/// Test rate limiter isolates IPs.
#[test]
fn test_rate_limiter_per_ip() {
    let limiter = IpRateLimiter::new(100, 5);
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "192.168.1.2".parse().unwrap();

    // Exhaust burst for IP1
    for _ in 0..5 {
        assert!(limiter.check(ip1));
    }

    // IP2 should still have full burst
    for _ in 0..5 {
        assert!(limiter.check(ip2));
    }
}

/// Test RPC middleware combines allowlist and rate limiting.
#[test]
fn test_middleware_allowlist_check() {
    let allowed_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let blocked_ip: IpAddr = "10.0.0.1".parse().unwrap();

    let middleware = RpcMiddleware::new(1000, 100, Some(vec![allowed_ip]));

    // Allowed IP should pass
    assert!(middleware.check_request(allowed_ip).is_ok());

    // Blocked IP should fail
    let result = middleware.check_request(blocked_ip);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "IP not in allowlist");
}

/// Test RPC middleware with no allowlist.
#[test]
fn test_middleware_no_allowlist() {
    let middleware = RpcMiddleware::new(1000, 100, None);

    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.1".parse().unwrap();

    // Both IPs should pass
    assert!(middleware.check_request(ip1).is_ok());
    assert!(middleware.check_request(ip2).is_ok());
}

/// Test rate limiter default values.
#[test]
fn test_rate_limiter_default() {
    let limiter = IpRateLimiter::default();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    // Default should allow requests
    assert!(limiter.check(ip));
}
