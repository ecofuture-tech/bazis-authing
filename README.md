# Bazis Authing

[![PyPI version](https://img.shields.io/pypi/v/bazis-authing.svg)](https://pypi.org/project/bazis-authing/)
[![Python Versions](https://img.shields.io/pypi/pyversions/bazis-authing.svg)](https://pypi.org/project/bazis-authing/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Extension package for Bazis providing a flexible authentication system with support for various login methods.

## Quick Start

```bash
# Install the package
uv add bazis-authing

# Configure in settings.py
BAZIS_AUTH_KINDS = [
    'bazis.contrib.authing.password',  # Username/password authentication
]

# Register routes in main router.py
from bazis.core.routing import BazisRouter

router = BazisRouter(prefix='/api/v1')
router.register('bazis.contrib.authing.router')
```

## Table of Contents

- [Description](#description)
- [Requirements](#requirements)
- [Installation](#installation)
- [Core Components](#core-components)
  - [/auth/ Endpoint](#auth-endpoint)
  - [Authentication Methods](#authentication-methods)
  - [AuthStore](#authstore)
- [Usage](#usage)
  - [Project Setup](#project-setup)
  - [Basic Password Authentication](#basic-password-authentication)
  - [Getting JWT Token](#getting-jwt-token)
- [How It Works](#how-it-works)
- [Examples](#examples)
- [Extension](#extension)
- [License](#license)
- [Links](#links)

## Description

**Bazis Authing** is an extension package for the Bazis framework that provides a flexible and extensible authentication system. The package includes:

- **Universal `/auth/` endpoint** — central point for checking authentication status and getting available login methods
- **Built-in password authentication** — ready-to-use module for username/password authentication
- **AuthStore** — cookie-based authentication state storage system
- **Support for multiple authentication methods** — easily add OAuth, SAML, LDAP, and other providers
- **JWT integration** — automatic JWT token generation after successful authentication

**This package requires `bazis` and `bazis-users` packages to be installed.**

## Requirements

- **Python**: 3.12+
- **bazis**: latest version
- **bazis-users**: latest version
- **PostgreSQL**: 12+
- **Redis**: For caching

## Installation

### Using uv (recommended)

```bash
uv add bazis-authing
```

### Using pip

```bash
pip install bazis-authing
```

## Core Components

### /auth/ Endpoint

Central endpoint for authentication operations.

**URL**: `GET /api/v1/authing/auth/`

**Purpose**:
- Check current authentication status
- Get list of available login methods
- Get JWT token for authenticated users

**Behavior**:

1. **If user is NOT authenticated** → returns 401 error with list of available login methods:

```json
{
  "errors": [
    {
      "status": 401,
      "code": "UNAUTHORIZED",
      "title": "User is not authorized.",
      "detail": "User is not authorized.",
      "meta": {
        "actions": [
          {
            "code": "password",
            "name": "Login/Password",
            "url": "/api/v1/authing/password/",
            "method": "POST"
          }
        ],
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      }
    }
  ]
}
```

2. **If user is authenticated** → returns user data and JWT token:

```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user1",
  "first_name": "John",
  "last_name": "Doe",
  "email": "user1@example.com",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "logout_actions": [
    {
      "url": "/api/v1/authing/logout/",
      "method": "POST"
    }
  ]
}
```

### Authentication Methods

#### Password Authentication

Built-in module for username and password authentication.

**Module code**: `password`

**Endpoints**:

1. **POST /api/v1/authing/password/** — web authentication with redirect
   - Accepts username and password
   - On successful authentication, sets cookie and redirects to `/auth/`
   - On failed authentication, returns error

2. **POST /api/v1/authing/password/token/** — get JWT token for Swagger/API
   - Accepts `username` and `password` via `OAuth2PasswordRequestForm`
   - Returns JWT token directly without cookie
   - Used for authentication in Swagger UI

**Request schema** (POST /password/):
```json
{
  "username": "user1",
  "password": "password123"
}
```

**Response schema** (POST /password/token/):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### AuthStore

Cookie-based authentication state storage system.

**Location**: `bazis.contrib.authing.service.AuthStore`

**Purpose**:
- Store temporary authentication data in encrypted cookie
- Track multi-step authentication progress
- Pass errors between requests

**Main methods**:

- `login(user, request, auth_type)` — registers successful user authentication
- `set_error(code, detail)` — saves authentication error
- `data_reset()` — clears storage
- `response_set_cookie(response)` — adds cookie to response

**AuthStoreTokenRequired**:

Dependency for endpoints requiring authentication token in cookie:

```python
from bazis.contrib.authing.service import AuthStoreTokenRequired
from fastapi import Depends

@router.post('/password/')
def password_auth(auth_store: AuthStoreTokenRequired = Depends()):
    # auth_store guaranteed to contain valid token
    pass
```

## Usage

### Project Setup

**1. Add to settings.py**:

```python
# settings.py

# List of available authentication methods
BAZIS_AUTH_KINDS = [
    'bazis.contrib.authing.password',  # Username/password
    # Add other methods here
]
```

**2. Register routes**:

```python
# router.py
from bazis.core.routing import BazisRouter

router = BazisRouter(prefix='/api/v1')

# Register authentication routes
router.register('bazis.contrib.authing.router')
```

### Basic Password Authentication

#### Typical web authentication flow:

**Step 1**: Client requests authentication status:

```bash
GET /api/v1/authing/auth/
```

**Response** (if not authenticated):
```json
{
  "errors": [
    {
      "status": 401,
      "code": "UNAUTHORIZED",
      "meta": {
        "actions": [
          {
            "code": "password",
            "name": "Login/Password",
            "url": "/api/v1/authing/password/",
            "method": "POST"
          }
        ],
        "token": "auth_token_here"
      }
    }
  ]
}
```

**Step 2**: Client performs authentication:

```bash
POST /api/v1/authing/password/
Cookie: bazis_auth=auth_token_here
Content-Type: application/json

{
  "username": "user1",
  "password": "password123"
}
```

**Response** (successful authentication):
```
HTTP 303 See Other
Location: /api/v1/authing/auth/?token=updated_token
Set-Cookie: bazis_auth=updated_token; Path=/; HttpOnly
```

**Step 3**: Client follows redirect and gets user data:

```bash
GET /api/v1/authing/auth/?token=updated_token
Cookie: bazis_auth=updated_token
```

**Response**:
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user1",
  "email": "user1@example.com",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Getting JWT Token

For direct JWT token retrieval (e.g., for mobile apps or Swagger):

```bash
POST /api/v1/authing/password/token/
Content-Type: application/x-www-form-urlencoded

username=user1&password=password123
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

This token can be used in the `Authorization: Bearer <token>` header for all subsequent requests.

## How It Works

### System Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 1. GET /auth/ (no cookie)
       ▼
┌─────────────────────┐
│  /auth/ endpoint    │◄─── Checks user status
└──────┬──────────────┘
       │
       │ 2. Returns 401 + available actions
       ▼
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 3. POST /password/ (with credentials)
       ▼
┌─────────────────────┐
│ Password endpoint   │◄─── Authenticates user
└──────┬──────────────┘
       │
       │ 4. Sets cookie + redirects to /auth/
       ▼
┌─────────────────────┐
│  /auth/ endpoint    │◄─── Returns user data + JWT
└──────┬──────────────┘
       │
       │ 5. Returns user + token
       ▼
┌─────────────┐
│   Client    │
└─────────────┘
```

### Authentication Process

1. **Initialization**:
   - Client requests `/auth/` without cookie
   - System creates temporary token and returns it in meta
   - Client saves this token

2. **Authentication**:
   - Client sends credentials with token in cookie
   - System validates credentials via Django `authenticate()`
   - On success — saves `user_id` in AuthStore
   - Sets updated cookie and redirects

3. **Token Retrieval**:
   - Client requests `/auth/` with cookie
   - System extracts `user_id` from AuthStore
   - Generates JWT token via `user.jwt_build()`
   - Returns user data and token

### Security

- **HttpOnly cookie** — protection against XSS attacks
- **Temporary tokens** — limited lifetime for auth cookie
- **Encrypted storage** — cookie data is encrypted
- **JWT tokens** — for further API operations

## Examples

### Client Application Usage Example

```javascript
// JavaScript client for authentication

class AuthClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.authToken = null;
    this.jwtToken = null;
  }

  async checkAuth() {
    const response = await fetch(`${this.baseUrl}/authing/auth/`, {
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      this.jwtToken = data.token;
      return { authenticated: true, user: data };
    }

    const error = await response.json();
    this.authToken = error.errors[0].meta.token;
    return {
      authenticated: false,
      actions: error.errors[0].meta.actions
    };
  }

  async loginWithPassword(username, password) {
    const response = await fetch(`${this.baseUrl}/authing/password/`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `bazis_auth=${this.authToken}`
      },
      body: JSON.stringify({ username, password }),
      redirect: 'follow'
    });

    if (response.ok) {
      return await this.checkAuth();
    }

    throw new Error('Authentication failed');
  }

  async apiRequest(url, options = {}) {
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.jwtToken}`
      }
    });
  }
}

// Usage
const auth = new AuthClient('https://api.example.com/api/v1');

// Check authentication status
const status = await auth.checkAuth();

if (!status.authenticated) {
  // Perform login
  await auth.loginWithPassword('user1', 'password123');
}

// Now you can make requests to protected endpoints
const response = await auth.apiRequest('/api/v1/protected/resource/');
```

### Authentication Testing

```python
import pytest
from bazis_test_utils.utils import get_api_client
from bazis.contrib.users import get_user_model

User = get_user_model()

@pytest.mark.django_db(transaction=True)
def test_password_authentication_flow(sample_app):
    # Create user
    user = User.objects.create_user(
        'testuser',
        email='test@example.com',
        password='testpass123'
    )

    # Step 1: Get status (not authenticated)
    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    assert response.status_code == 400
    
    data = response.json()
    assert 'errors' in data
    error = data['errors'][0]
    assert error['code'] == 'UNAUTHORIZED'
    
    auth_token = error['meta']['token']
    actions = error['meta']['actions']
    
    # Check available login methods
    assert len(actions) == 1
    assert actions[0]['code'] == 'password'

    # Step 2: Perform authentication
    response = get_api_client(sample_app, auth_token).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'testuser',
            'password': 'testpass123',
        },
    )
    assert response.status_code == 200

    # Step 3: Verify received data
    data = response.json()
    assert data['user_id'] == str(user.id)
    assert data['username'] == 'testuser'
    assert data['email'] == 'test@example.com'
    assert 'token' in data  # JWT token

    # Step 4: Test invalid credentials
    response = get_api_client(sample_app, auth_token).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'testuser',
            'password': 'wrongpassword',
        },
    )
    assert response.status_code == 400
```

## Extension

### Adding New Authentication Method

You can add your own authentication method (OAuth, SAML, LDAP, etc.):

**1. Create a module** (e.g., `myapp/auth_oauth.py`):

```python
from bazis.core.routing import BazisRouter
from django.utils.translation import gettext_lazy as _

AUTH_CODE = 'oauth'

router = BazisRouter(prefix='/oauth', tags=[_('OAuth Authentication')])

def get_login_action():
    """Returns login method information for /auth/"""
    return {
        'code': AUTH_CODE,
        'name': 'OAuth Login',
        'url': '/api/v1/authing/oauth/',
        'method': 'GET',
    }

def get_logout_actions():
    """Returns logout actions (optional)"""
    return {
        'url': '/api/v1/authing/oauth/logout/',
        'method': 'POST',
    }

@router.get('/')
def oauth_login():
    # OAuth authentication logic
    pass
```

**2. Add to settings.py**:

```python
BAZIS_AUTH_KINDS = [
    'bazis.contrib.authing.password',
    'myapp.auth_oauth',  # Your module
]
```

**3. Register routes**:

```python
# myapp/router.py
from bazis.core.routing import BazisRouter
from . import auth_oauth

router = BazisRouter()
router.include_router(auth_oauth.router)
```

Now your authentication method will automatically appear in the list of available methods in `/auth/`!

## License

Apache License 2.0

See [LICENSE](LICENSE) file for details.

## Links

- [Bazis Documentation](https://github.com/ecofuture-tech/bazis) — main repository
- [Bazis Users](https://github.com/ecofuture-tech/bazis-users) — user management package
- [Bazis Authing Repository](https://github.com/ecofuture-tech/bazis-authing) — package repository
- [Issue Tracker](https://github.com/ecofuture-tech/bazis-authing/issues) — report bugs or request features

## Support

If you have questions or issues:
- Check [Bazis documentation](https://github.com/ecofuture-tech/bazis)
- Search [existing issues](https://github.com/ecofuture-tech/bazis-authing/issues)
- Create a [new issue](https://github.com/ecofuture-tech/bazis-authing/issues/new) with detailed information

---

Made with ❤️ by Bazis team