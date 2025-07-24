# Dummy API with Insecure JWT

⚠️ **WARNING: This API uses INTENTIONALLY INSECURE JWT implementation for testing purposes only!**

## Features

- 10 HTTP endpoints (8 GET, 2 POST)
- JWT authentication with extensive PII in tokens
- 2-minute token expiration
- All endpoints except /auth require valid JWT

## Security Issues (Intentional for Testing)

- JWT Secret: `123456789` (weak and hardcoded)
- Algorithm: HS256
- Token contains extensive PII including:
  - SSN, Credit Card, Phone, Address
  - Date of Birth, Driver's License, Passport
  - Bank Account, Medical ID, Tax ID
  - And more sensitive information

## Installation

```bash
npm install
```

## Running the Server

```bash
npm start
# or for development with auto-restart
npm run dev
```

Server runs on: http://localhost:3000

## Test Credentials

- Username: `alice` / Password: `password123` (admin role)
- Username: `bob` / Password: `secret456` (user role)

## API Endpoints

### Authentication

#### POST /auth
Login endpoint that returns an insecure JWT token.

**Request:**
```json
{
  "username": "alice",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 120,
  "token_type": "Bearer",
  "user_info": {
    "username": "alice",
    "name": "Alice Robertson",
    "role": "admin"
  }
}
```

### Protected Endpoints (Require JWT)

All protected endpoints require the JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

#### GET /users
Returns a list of dummy users.

#### GET /stats
Returns system statistics and API metrics.

#### POST /submit-data
Submit data to the API.

**Request:**
```json
{
  "data": "Your data here"
}
```

#### GET /devices
Returns a list of IoT devices with status.

#### GET /alerts
Returns active system alerts.

#### GET /weather
Returns weather data for multiple cities.

#### POST /log
Log events to the system.

**Request:**
```json
{
  "level": "info",
  "message": "Test log message",
  "context": { "additional": "data" }
}
```

#### GET /products
Returns product catalog with pricing.

#### GET /orders
Returns order history for the authenticated user.

## JWT Token Structure

The JWT token includes these claims (INSECURE - for testing only):

```json
{
  "sub": "987654321",
  "user_id": "987654321",
  "name": "Alice Robertson",
  "email": "alice.robertson@example.com",
  "ssn": "987-65-4321",
  "credit_card": "4111-1111-1111-1111",
  "phone": "+1-555-123-4567",
  "address": "456 Main St, Springfield, USA",
  "dob": "1985-03-12",
  "role": "admin",
  "drivers_license": "DL-123456789",
  "passport": "P-987654321",
  "bank_account": "1234567890",
  "medical_id": "MED-2023-456",
  "tax_id": "TIN-98-7654321",
  "login_time": "2025-07-19T14:30:00Z",
  "iat": 1737296400,
  "exp": 1737296520
}
```

## Example Usage

### 1. Login
```bash
curl -X POST http://localhost:3000/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

### 2. Access Protected Endpoint
```bash
curl -X GET http://localhost:3000/users \
  -H "Authorization: Bearer <your-jwt-token>"
```

## ⚠️ Security Notice

This API is intentionally insecure and should NEVER be used in production. It's designed for:
- Testing JWT vulnerabilities
- Security training
- Development and testing purposes only

The JWT contains extensive PII and uses a weak secret key that would be trivial to crack.
