#!/bin/bash

# Exit on any error
set -e

echo "🔍 Checking if nerdctl is installed..."
if ! command -v nerdctl &> /dev/null; then
    echo "❌ nerdctl is not installed. Please install it first."
    exit 1
fi

# Database configuration
DB_NAME="api_platform"
DB_USER="postgres"
DB_PASSWORD="postgres"
DB_PORT="5432"
CONTAINER_NAME="api-platform-db"

# Stop and remove existing container if it exists
echo "🧹 Cleaning up existing container if any..."
nerdctl stop $CONTAINER_NAME 2>/dev/null || true
nerdctl rm $CONTAINER_NAME 2>/dev/null || true

# Start PostgreSQL container
echo "🐘 Starting PostgreSQL container..."
nerdctl run --name $CONTAINER_NAME \
    -e POSTGRES_DB=$DB_NAME \
    -e POSTGRES_USER=$DB_USER \
    -e POSTGRES_PASSWORD=$DB_PASSWORD \
    -p $DB_PORT:5432 \
    -d postgres:15

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Create new Cargo project
echo "🦀 Creating new Rust project..."
cargo new api-platform
cd api-platform

# Create necessary directories
mkdir -p src/{handlers,models,db}
mkdir -p migrations

# Create .env file
cat > .env << EOL
DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}
EOL

# Create Cargo.toml with dependencies
# Create Cargo.toml with dependencies
cat > Cargo.toml << EOL
[package]
name = "api-platform"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1.0", features = ["full"] }
sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres", "json", "chrono"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tower-http = { version = "0.5", features = ["cors", "trace"] }
dotenvy = "0.15"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "1.0"
chrono = { version = "0.4", features = ["serde"] }
hyper = { version = "1.0", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
tower = "0.4"
EOL

# Update main.rs
cat > src/main.rs << EOL
use axum::{
    routing::{get, post},
    Router,
    Extension,
};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use std::net::SocketAddr;

mod error;
mod handlers;
mod models;
mod db;

use crate::error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate the database");

    // Build our application with routes
    let app = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/api/v1/resources", get(handlers::list_resources))
        .route("/api/v1/resources", post(handlers::create_resource))
        .layer(Extension(pool))
        .layer(CorsLayer::permissive());

    // Run our application
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
EOL



# Create error.rs
cat > src/error.rs << EOL
use axum::{
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Not found")]
    NotFound,
    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AppError::Database(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}
EOL

# Create models.rs
cat > src/models.rs << EOL
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Resource {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateResource {
    pub name: String,
    pub description: Option<String>,
}
EOL

cat > src/handlers.rs << 'EOL'
use axum::{
    extract::Extension,
    Json,
    http::StatusCode,
};
use sqlx::PgPool;
use serde_json::json;
use crate::{models::{Resource, CreateResource}, error::AppError};

#[axum::debug_handler]
pub async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({
        "status": "up",
        "message": "Service is healthy"
    })))
}

#[axum::debug_handler]
pub async fn list_resources(
    Extension(pool): Extension<PgPool>
) -> Result<Json<Vec<Resource>>, AppError> {
    let resources = sqlx::query_as!(
        Resource,
        "SELECT * FROM resources ORDER BY created_at DESC"
    )
    .fetch_all(&pool)
    .await?;

    Ok(Json(resources))
}

#[axum::debug_handler]
pub async fn create_resource(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateResource>,
) -> Result<(StatusCode, Json<Resource>), AppError> {
    let resource = sqlx::query_as!(
        Resource,
        "INSERT INTO resources (name, description) VALUES ($1, $2) RETURNING id, name, description, created_at, updated_at",
        payload.name,
        payload.description
    )
    .fetch_one(&pool)
    .await?;

    Ok((StatusCode::CREATED, Json(resource)))
}
EOL

# Create migration file
cat > migrations/20240206000000_create_resources.sql << EOL
CREATE TABLE IF NOT EXISTS resources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS \$\$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
\$\$ language 'plpgsql';

CREATE TRIGGER update_resources_updated_at
    BEFORE UPDATE ON resources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
EOL

# Create empty db.rs
touch src/db.rs

# Initialize git repository
git init
echo "target/" > .gitignore
echo ".env" >> .gitignore

# Install sqlx-cli if not already installed
echo "🔧 Installing sqlx-cli..."
cargo install sqlx-cli --no-default-features --features postgres

# Wait a bit more to ensure PostgreSQL is ready
echo "⏳ Ensuring database is ready..."
sleep 5
# Run the migrations
echo "🔄 Running database migrations..."
cargo sqlx migrate run

echo "✨ Project setup complete! The API is ready to be started."
echo ""
echo "📝 Quick reference:"
echo "1. PostgreSQL container name: $CONTAINER_NAME"
echo "2. Database credentials:"
echo "   - Database: $DB_NAME"
echo "   - User: $DB_USER"
echo "   - Password: $DB_PASSWORD"
echo "   - Port: $DB_PORT"
echo ""
echo "🚀 Change into api-platform directory"
echo "   cd api-platform"
echo "🚀 To start the API server:"
echo "   cargo run"
echo ""
echo "🧪 To test the API:"
echo "curl http://localhost:3000/health"
echo ""
echo "💡 To stop the database:"
echo "nerdctl stop $CONTAINER_NAME"
echo ""
echo "🗑️  To remove the database container:"
echo "nerdctl rm $CONTAINER_NAME"
