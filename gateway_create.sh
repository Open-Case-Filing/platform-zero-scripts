#!/bin/bash

# Exit on any error
set -e

echo "🚀 Setting up JWT API Gateway project..."

# Create new Cargo project
cargo new api-gateway
cd api-gateway

# Create necessary directories
mkdir -p src/{handlers,middleware,routes}

# Create .env file
cat > .env << EOL
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_AUTH_URL=https://your-oauth-provider/auth
OAUTH_TOKEN_URL=https://your-oauth-provider/token
OAUTH_REDIRECT_URL=http://localhost:8080/auth/callback
JWT_SECRET=your-secret-key
EOL

# Create Cargo.toml
cat > Cargo.toml << EOL
[package]
name = "api-gateway"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1.0", features = ["full"] }
hyper = { version = "1.0", features = ["full"] }
tower = { version = "0.4", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "trace", "auth"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
jsonwebtoken = "9.2"
reqwest = { version = "0.11", features = ["json"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "1.0"
dotenvy = "0.15"
oauth2 = "4.4"
bytes = "1.5"
chrono = "0.4"
EOL

# Update main.rs with correct middleware usage
cat > src/main.rs << 'EOL'
use axum::{
    routing::get,
    Router,
    Extension,
    middleware::from_fn,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

mod auth;
mod error;
mod handlers;
mod middleware;
mod routes;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize OAuth client
    let oauth_client = auth::init_oauth_client();

    // Create public routes (no auth needed)
    let public_routes = Router::new()
        .route("/health", get(routes::health_check))
        .route("/auth/login", get(handlers::auth::login))
        .route("/auth/callback", get(handlers::auth::oauth_callback));

    // Create protected routes (auth required)
    let protected_routes = Router::new()
        .nest("/api", routes::api_routes())
        .layer(from_fn(middleware::auth::auth_middleware));

    // Combine routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(Extension(oauth_client))
        .layer(CorsLayer::permissive());

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Gateway listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

EOL

# Create auth.rs
cat > src/auth.rs << 'EOL'
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use oauth2::{
    basic::BasicClient,
    AuthUrl,
    ClientId,
    ClientSecret,
    RedirectUrl,
    TokenUrl,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (user ID)
    pub exp: i64,     // Expiration time
    pub iat: i64,     // Issued at
}

impl Claims {
    pub fn new(user_id: String) -> Self {
        let now = Utc::now();
        Claims {
            sub: user_id,
            iat: now.timestamp(),
            exp: (now + Duration::hours(24)).timestamp(),
        }
    }
}

pub fn create_jwt(user_id: String) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims::new(user_id);
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes())
    )
}

pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    )
    .map(|data| data.claims)
}

pub fn init_oauth_client() -> BasicClient {
    let client_id = ClientId::new(
        std::env::var("OAUTH_CLIENT_ID").expect("Missing OAUTH_CLIENT_ID")
    );
    let client_secret = ClientSecret::new(
        std::env::var("OAUTH_CLIENT_SECRET").expect("Missing OAUTH_CLIENT_SECRET")
    );
    let auth_url = AuthUrl::new(
        std::env::var("OAUTH_AUTH_URL").expect("Missing OAUTH_AUTH_URL")
    ).expect("Invalid auth URL");
    let token_url = TokenUrl::new(
        std::env::var("OAUTH_TOKEN_URL").expect("Missing OAUTH_TOKEN_URL")
    ).expect("Invalid token URL");

    BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url)
    )
    .set_redirect_uri(
        RedirectUrl::new(std::env::var("OAUTH_REDIRECT_URL").expect("Missing OAUTH_REDIRECT_URL"))
            .expect("Invalid redirect URL")
    )
}
EOL

# Create error.rs
cat > src/error.rs << 'EOL'
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

EOL

# Create handlers/mod.rs
cat > src/handlers/mod.rs << 'EOL'
pub mod auth;
EOL

# Create handlers/auth.rs
cat > src/handlers/auth.rs << 'EOL'
use axum::{
    response::{Redirect, Json},
    extract::{Extension, Query},
    http::StatusCode,
};
use oauth2::{
    AuthorizationCode,
    TokenResponse,
    reqwest::async_http_client,
    basic::BasicClient,
};
use serde_json::json;
use std::collections::HashMap;
use crate::auth;

pub async fn login(
    Extension(oauth_client): Extension<BasicClient>
) -> Redirect {
    let (auth_url, _csrf_token) = oauth_client
        .authorize_url(oauth2::CsrfToken::new_random)
        .url();

    Redirect::to(auth_url.as_str())
}

pub async fn oauth_callback(
    Extension(oauth_client): Extension<BasicClient>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let code = params
        .get("code")
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Exchange code for token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(async_http_client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // In a real application, you would:
    // 1. Get user info from OAuth provider
    // 2. Create or update user in your database
    // For this example, we'll use the token's subject as the user ID
    let user_id = token.access_token().secret().clone();

    // Create JWT
    let jwt = auth::create_jwt(user_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "token": jwt
        }))
    ))
}

EOL

# Create middleware/mod.rs
cat > src/middleware/mod.rs << 'EOL'
pub mod auth;
EOL

# Create middleware/auth.rs with fixed middleware implementation
cat > src/middleware/auth.rs << 'EOL'
use axum::{
    middleware::Next,
    response::{Response, IntoResponse},
    http::{Request, StatusCode},
    body::Body,
    Json,
};
use serde_json::json;
use crate::auth;

pub async fn auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for login and callback routes
    if request.uri().path().starts_with("/auth/") {
        return next.run(request).await;
    }

    // Get JWT from header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));

    match auth_header {
        Some(token) => {
            // Validate JWT
            match auth::validate_jwt(token) {
                Ok(_) => next.run(request).await,
                Err(_) => (
                    StatusCode::UNAUTHORIZED,
                    [("content-type", "application/json")],
                    Json(json!({
                        "error": "Invalid or expired token",
                        "message": "Please provide a valid authentication token"
                    }))
                ).into_response()
            }
        },
        None => (
            StatusCode::UNAUTHORIZED,
            [("content-type", "application/json")],
            Json(json!({
                "error": "Missing authentication",
                "message": "Please provide a Bearer token in the Authorization header"
            }))
        ).into_response()
    }
}
EOL

cat > src/routes/mod.rs << 'EOL'
use axum::{
    Router,
    body::Bytes,
    http::{StatusCode, Method, HeaderMap},
    response::IntoResponse,
    Json,
};
use hyper::Uri;
use serde_json::json;
use std::convert::TryFrom;

pub async fn health_check() -> impl IntoResponse {
    let client = reqwest::Client::new();

    match client.get("http://localhost:3000/health").send().await {
        Ok(res) => {
            let text = res.text().await.unwrap_or_default();
            println!("Health check response: {}", text);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                text
            ).into_response()
        }
        Err(e) => {
            println!("Health check error: {}", e);
            Json(json!({
                "status": "error",
                "message": "Could not connect to resource API"
            })).into_response()
        }
    }
}

pub fn api_routes() -> Router {
    Router::new()
        .fallback(proxy_request)
}

async fn proxy_request(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Bytes>,
) -> impl IntoResponse {
    let path = uri.path();
    println!("📥 Received request: {} {}", method, path);

    // Ensure path starts with /api prefix
    let target_path = if path.starts_with("/v1") {
        format!("/api{}", path)
    } else {
        path.to_string()
    };

    let target_url = format!("http://localhost:3000{}", target_path);
    println!("🔄 Forwarding to: {}", target_url);

    let client = reqwest::Client::new();

    let mut proxy_req = client
        .request(reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET), &target_url);

    // Forward headers excluding host
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if name.as_str() != "host" {
            if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(header_value) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    println!("🔄 Forwarding header: {} = {:?}", name, value);
                    req_headers.insert(header_name, header_value);
                }
            }
        }
    }
    proxy_req = proxy_req.headers(req_headers);

    // Forward body if present
    if let Some(body) = body {
        proxy_req = proxy_req.body(body);
    }

    match proxy_req.send().await {
        Ok(res) => {
            let status = StatusCode::try_from(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            println!("📤 Upstream status: {}", status);

            let headers = res.headers().clone();
            let body = res.text().await.unwrap_or_default();
            println!("📤 Upstream response: {}", body);

            let mut response = axum::response::Response::builder()
                .status(status)
                .header("content-type", "application/json");

            // Forward response headers
            for (name, value) in headers.iter() {
                if name != "content-type" {  // Skip content-type as we set it above
                    if let Ok(header_value) = axum::http::HeaderValue::from_bytes(value.as_bytes()) {
                        response = response.header(name.as_str(), header_value);
                    }
                }
            }

            response
                .body(axum::body::Body::from(body))
                .unwrap_or_else(|e| {
                    println!("❌ Error building response: {}", e);
                    (
                        StatusCode::BAD_GATEWAY,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        json!({
                            "error": "Failed to process upstream response",
                            "message": e.to_string()
                        }).to_string()
                    ).into_response()
                })
        }
        Err(e) => {
            println!("❌ Proxy error: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                json!({
                    "error": "Failed to proxy request",
                    "message": e.to_string()
                }).to_string()
            ).into_response()
        }
    }
}

EOL

# Initialize git repository
git init
echo "target/" > .gitignore
echo ".env" >> .gitignore
echo "Cargo.lock" >> .gitignore

echo "✨ Setup complete! Next steps:"
echo "1. Update the OAuth credentials and JWT secret in .env"
echo "2. Build the project: cargo build"
echo "3. Run the gateway: cargo run"
echo ""
echo "🔑 Test endpoints:"
echo "Login:    curl http://localhost:8080/auth/login"
echo "Resource: curl http://localhost:8080/api/resources -H 'Authorization: Bearer your-jwt-token'"
