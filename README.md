# Platform Zero o.O 🚀

A modern, secure microservices platform featuring a Rust-based API Gateway and Resource API service.

## Architecture Overview 🏗️

- **API Gateway**: Auth-enabled reverse proxy service
- **Resource API**: CRUD-based resource management service
- **Database**: PostgreSQL for data persistence

## Prerequisites 🛠️

- Rust (latest stable)
- Docker/nerdctl
- PostgreSQL 15
- SQLx CLI

## Quick Start 🏃‍♂️

1. **Clone the repository**
```bash
git clone git@github.com:Open-Case-Filing/platform-zero.git
cd platform-zero
```

2. **Set up execution permissions**
```bash
chmod +x api_create.sh
chmod +x gateway_create.sh
```

3. **Initialize services**
```bash
./api_create.sh   # Creates and sets up the Resource API
./gateway_create.sh   # Creates and sets up the API Gateway
```

## Service Details 📋

### Resource API (Port 3000)

- **Health Check**: `GET /health`
- **List Resources**: `GET /api/v1/resources`
- **Create Resource**: `POST /api/v1/resources`

### API Gateway (Port 8080)

- **Health Check**: `GET /health`
- **Auth Endpoints**:
  - Login: `GET /auth/login`
  - OAuth Callback: `GET /auth/callback`
- **Protected Routes**: All `/api/*` routes require JWT authentication

## Configuration ⚙️

### Gateway Configuration
Create a `.env` file with:
>> Use okta or any other OAuth provider. I've tested with Okta.
```env
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_AUTH_URL=https://your-oauth-provider/auth
OAUTH_TOKEN_URL=https://your-oauth-provider/token
OAUTH_REDIRECT_URL=http://localhost:8080/auth/callback
JWT_SECRET=your-secret-key
```

### API Configuration
Database configuration is handled automatically through the setup script.

## Development 👨‍💻

### Running the Services

1. **Start the Resource API**:
```bash
cd api-platform
cargo run
```

2. **Start the Gateway**:
```bash
cd api-gateway
cargo run
```

### Testing the Setup

1. **Health Check**:
```bash
curl http://localhost:8080/health
```

2. **Protected Resource Access**:
```bash
# Get JWT token through OAuth flow
curl http://localhost:8080/auth/login

# Access protected resource
curl http://localhost:8080/api/v1/resources \
  -H "Authorization: Bearer your-jwt-token"
```

## Add Roles and Permissions 🛡️
1. Rename .env copy to .env and fill in the details from auth0.
2. node auth0-setup.js
3. Roles and Permissions will now be available in the Auth0 dashboard.

## Contributing 🤝

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Support 💬

For support, please open an issue in the repository.
