//! Security Middleware for PoUW Oracle API
//!
//! Provides:
//! - API key authentication
//! - Rate limiting per IP
//! - Request validation and size limits
//! - Security headers
//! - Request logging with sanitization

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Security configuration for middleware
#[derive(Debug, Clone)]
pub struct SecurityMiddlewareConfig {
    /// Enable API key authentication
    pub enable_auth: bool,
    /// Valid API keys (in production, use secure storage)
    pub api_keys: Vec<String>,
    /// Rate limit: requests per minute per IP
    pub rate_limit_per_minute: u32,
    /// Maximum request body size in bytes
    pub max_request_size: usize,
    /// Enable request logging
    pub log_requests: bool,
    /// Sanitize sensitive data in logs
    pub sanitize_logs: bool,
    /// Paths that don't require authentication
    pub public_paths: Vec<String>,
}

impl Default for SecurityMiddlewareConfig {
    fn default() -> Self {
        Self {
            enable_auth: true,
            api_keys: Vec::new(),
            rate_limit_per_minute: 60,
            max_request_size: 1024 * 1024, // 1MB
            log_requests: true,
            sanitize_logs: true,
            public_paths: vec![
                "/health".to_string(),
                "/boinc/".to_string(), // BOINC proxy needs to be accessible
            ],
        }
    }
}

/// Rate limiter state - tracks requests per IP
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of IP -> (request count, window start)
    requests: DashMap<String, (u32, Instant)>,
    /// Requests allowed per window
    limit: u32,
    /// Window duration
    window: Duration,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests: DashMap::new(),
            limit: requests_per_minute,
            window: Duration::from_secs(60),
        }
    }

    /// Check if request is allowed and update counter
    /// Returns (allowed, remaining, reset_after_secs)
    pub fn check_request(&self, ip: &str) -> (bool, u32, u64) {
        let now = Instant::now();

        let mut entry = self.requests.entry(ip.to_string()).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        // Reset window if expired
        if now.duration_since(*window_start) >= self.window {
            *count = 0;
            *window_start = now;
        }

        let remaining = self.limit.saturating_sub(*count);
        let reset_after = self
            .window
            .checked_sub(now.duration_since(*window_start))
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if *count >= self.limit {
            return (false, 0, reset_after);
        }

        *count += 1;
        (true, remaining.saturating_sub(1), reset_after)
    }

    /// Clean up old entries (call periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.requests
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < self.window * 2);
    }
}

/// Shared state for security middleware
#[derive(Clone)]
pub struct SecurityState {
    pub config: SecurityMiddlewareConfig,
    pub rate_limiter: Arc<RateLimiter>,
}

impl SecurityState {
    pub fn new(config: SecurityMiddlewareConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_per_minute));
        Self {
            config,
            rate_limiter,
        }
    }
}

/// Extract client IP from request, handling proxies
fn get_client_ip(headers: &HeaderMap, addr: Option<&SocketAddr>) -> String {
    // Check X-Forwarded-For header (from reverse proxy)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // Take the first IP (original client)
            if let Some(ip) = value.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.trim().to_string();
        }
    }

    // Fall back to socket address
    addr.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Sanitize value for logging (mask sensitive data)
pub fn sanitize_for_log(value: &str) -> String {
    if value.len() <= 8 {
        return "*".repeat(value.len());
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}

/// Check if path is public (doesn't require auth)
fn is_public_path(path: &str, public_paths: &[String]) -> bool {
    public_paths.iter().any(|p| path.starts_with(p))
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<SecurityState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();

    // Skip auth for public paths
    if is_public_path(path, &state.config.public_paths) {
        return Ok(next.run(request).await);
    }

    // Skip auth if disabled
    if !state.config.enable_auth {
        return Ok(next.run(request).await);
    }

    // Check for API key in header
    let api_key = headers
        .get("x-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string());

    match api_key {
        Some(key) => {
            if state.config.api_keys.contains(&key) {
                debug!("API key authenticated for path: {}", path);
                Ok(next.run(request).await)
            } else {
                warn!("Invalid API key attempt for path: {}", path);
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => {
            warn!("Missing API key for path: {}", path);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(state): State<SecurityState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let client_ip = get_client_ip(&headers, Some(&addr));
    let (allowed, remaining, reset_after) = state.rate_limiter.check_request(&client_ip);

    if !allowed {
        warn!(
            "Rate limit exceeded for IP: {} on path: {}",
            client_ip,
            request.uri().path()
        );

        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        let headers = response.headers_mut();
        headers.insert(
            "X-RateLimit-Limit",
            HeaderValue::from(state.config.rate_limit_per_minute),
        );
        headers.insert("X-RateLimit-Remaining", HeaderValue::from(0u32));
        headers.insert("X-RateLimit-Reset", HeaderValue::from(reset_after));
        headers.insert("Retry-After", HeaderValue::from(reset_after));

        return Err(response);
    }

    let mut response = next.run(request).await;

    // Add rate limit headers to response
    let headers = response.headers_mut();
    headers.insert(
        "X-RateLimit-Limit",
        HeaderValue::from(state.config.rate_limit_per_minute),
    );
    headers.insert("X-RateLimit-Remaining", HeaderValue::from(remaining));
    headers.insert("X-RateLimit-Reset", HeaderValue::from(reset_after));

    Ok(response)
}

/// Security headers middleware
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent clickjacking
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // Enable XSS protection
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Strict Transport Security (HTTPS)
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Content Security Policy
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        ),
    );

    // Referrer Policy
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Cache control for API responses
    headers.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );

    // Remove server identification
    headers.remove("Server");

    response
}

/// Request logging middleware with sanitization
pub async fn logging_middleware(
    State(state): State<SecurityState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if !state.config.log_requests {
        return next.run(request).await;
    }

    let start = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let client_ip = get_client_ip(&headers, Some(&addr));

    // Sanitize IP if needed
    let log_ip = if state.config.sanitize_logs {
        sanitize_for_log(&client_ip)
    } else {
        client_ip.clone()
    };

    let response = next.run(request).await;
    let duration = start.elapsed();
    let status = response.status();

    // Log based on status code
    if status.is_server_error() {
        error!(
            method = %method,
            path = %path,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            client_ip = %log_ip,
            "Request failed"
        );
    } else if status.is_client_error() {
        warn!(
            method = %method,
            path = %path,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            client_ip = %log_ip,
            "Client error"
        );
    } else {
        info!(
            method = %method,
            path = %path,
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            client_ip = %log_ip,
            "Request completed"
        );
    }

    response
}

/// Request body size validation middleware
pub async fn body_size_middleware(
    State(state): State<SecurityState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check Content-Length header if present
    if let Some(content_length) = headers.get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > state.config.max_request_size {
                    warn!(
                        "Request body too large: {} bytes (max: {})",
                        length, state.config.max_request_size
                    );
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Validate request method
pub async fn method_validation_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method();
    let path = request.uri().path();

    // Allow standard methods
    match method {
        &Method::GET
        | &Method::POST
        | &Method::PUT
        | &Method::DELETE
        | &Method::PATCH
        | &Method::HEAD
        | &Method::OPTIONS => Ok(next.run(request).await),
        _ => {
            warn!("Invalid HTTP method: {} for path: {}", method, path);
            Err(StatusCode::METHOD_NOT_ALLOWED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(3);

        // First 3 requests should be allowed
        assert!(limiter.check_request("127.0.0.1").0);
        assert!(limiter.check_request("127.0.0.1").0);
        assert!(limiter.check_request("127.0.0.1").0);

        // 4th request should be denied
        let (allowed, remaining, _) = limiter.check_request("127.0.0.1");
        assert!(!allowed);
        assert_eq!(remaining, 0);

        // Different IP should still be allowed
        assert!(limiter.check_request("192.168.1.1").0);
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("short"), "*****");
        assert_eq!(sanitize_for_log("abcdefghij"), "abcd...ghij");
        // 13 chars: show first 4 and last 4 with ... in between
        let result = sanitize_for_log("192.168.1.100");
        assert!(result.starts_with("192."));
        assert!(result.ends_with(".100"));
        assert!(result.contains("..."));
    }

    #[test]
    fn test_is_public_path() {
        let public = vec!["/health".to_string(), "/boinc/".to_string()];

        assert!(is_public_path("/health", &public));
        assert!(is_public_path("/boinc/cgi", &public));
        assert!(!is_public_path("/api/stats", &public));
        assert!(!is_public_path("/miner/job", &public));
    }
}
