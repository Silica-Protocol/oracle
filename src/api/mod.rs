//! HTTP API endpoints for the PoUW Oracle
//!
//! Provides REST APIs for:
//! - Oracle API (work verification, proof generation, challenges)
//! - Web interface (human-readable endpoints)
//! - Miner integration (work submission/verification)
//! - Secure HTTP client for external calls
//! - Security middleware (auth, rate limiting, headers)

pub mod http;
pub mod middleware;
pub mod miner;
pub mod oracle;
pub mod web;

pub use http::{HttpSecurityConfig, SecureHttpClient};
pub use middleware::{
    RateLimiter, SecurityMiddlewareConfig, SecurityState, auth_middleware, body_size_middleware,
    logging_middleware, method_validation_middleware, rate_limit_middleware,
    security_headers_middleware,
};
pub use miner::{MinerApiState, create_router as create_miner_router};
pub use oracle::{OracleApiState, create_router as create_oracle_router};
pub use web::{WebApiState, create_router as create_web_router};
