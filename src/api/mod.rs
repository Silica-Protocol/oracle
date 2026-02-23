//! HTTP API endpoints for the PoUW Oracle
//!
//! - Security middleware (auth, rate limiting, headers)

pub mod http;
pub mod middleware;
pub mod miner;
pub mod nuw;
pub mod oracle;
pub mod protocol;
pub mod reputation;
pub mod web;

pub use http::{HttpSecurityConfig, SecureHttpClient};
pub use middleware::{
    auth_middleware, body_size_middleware, security_headers_middleware, SecurityMiddlewareConfig,
    SecurityState,
};
pub use miner::{MinerApiState, create_router as create_miner_router};
pub use nuw::{NuwApiState, create_router as create_nuw_router};
pub use oracle::{OracleApiState, create_router as create_oracle_router};
pub use protocol::{ProtocolApiState, create_protocol_router};
pub use reputation::{ReputationApiState, create_reputation_router};
pub use web::{WebApiState, create_router as create_web_router};
