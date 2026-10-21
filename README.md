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
    'bazis.contrib.authing.services.password',  # Username/password authentication
]

# Register routes in main router.py
from bazis.core.routing import BazisRouter

router = BazisRouter(prefix='/api/v1')
from bazis.contrib.authing.routes import router as authing_router
from bazis.contrib.authing.services.password.router import router as password_router

router.register(prefix='/authing', arg=authing_router)
# the router of every service in BAZIS_AUTH_KINDS
router.register(prefix='/authing', arg=password_router)
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
- **AuthStore** — the state of a sign-in, kept in the cache under a store token
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
- Get JWT token for authenticated users (a signed-in authorization store gives it once:
  the store is deleted, the next request with its token is not authenticated)

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

2. **POST /api/v1/authing/password/token/** — deprecated, removed in 3.0: the token
   endpoint of bazis-users (`POST BAZIS_OPENAPI_TOKEN_URL`, which Swagger UI uses) under
   this path
   - Accepts `username` and `password` via `OAuth2PasswordRequestForm`
   - Returns JWT token directly without cookie

**Request schema** (POST /password/):
```json
{
  "username": "user1",
  "password": "password123"
}
```

The token endpoint answers `{"access_token": "...", "token_type": "bearer"}`.

#### Google Authentication

**Module code**: `google` (`bazis.contrib.authing.services.google`, register its router).
Settings: `BAZIS_G_AUTH_CLIENT_ID`, `BAZIS_G_AUTH_CLIENT_SECRET`, optional
`BAZIS_G_AUTH_REDIRECT_URI` (dynamic, edited in the admin).

**Endpoints**:

1. **POST /api/v1/authing/google-auth-init/** — starts a sign-in in a browser (the login
   action, `method: POST`). With the store token as the bearer token; answers
   `{"ticket": "...", "url": "/api/v1/authing/google-auth-init/?ticket=..."}` and sets the
   cookie `__Host-bazis_google_init` that binds the ticket to this browser (HttpOnly,
   Secure, SameSite=Lax, `Path=/`, 60 seconds; the prefix `__Host-` makes sure that no
   other origin set it). With `BAZIS_AUTH_COOKIE_SECURE` off (development over HTTP) it is
   `bazis_google_init` without Secure. A new POST in the same browser replaces the cookie:
   the earlier ticket is refused
2. **GET /api/v1/authing/google-auth-init/?ticket=...** — the window opens the `url` of the
   answer in the same browser within 60 seconds and is redirected to Google. The ticket is
   used once and only with its cookie: otherwise 400
3. **GET /api/v1/authing/google-auth-callback/** — Google returns the window here: the store
   is signed in, the page asks the user to return to the application. The client that
   holds the store token asks `GET /auth/` until the store is signed in or has an error
4. **POST /api/v1/authing/google-auth-verify/** — the tokens a client received from a
   Google SDK (mobile), JSON `{"id_token", "access_token"}`, with the store token; 303 to
   `/auth/` as the password login

**Clients** (a web application): on the click, open the window at once
(`window.open('', ...)`: a browser blocks a window that a click does not open), then
`POST` the init with `Authorization: Bearer <store token>` and `credentials: 'include'`
(the answer sets the binding cookie), set the location of the window to the `url` of the
answer and ask `GET /auth/` with the store token until the store is signed in; close the
window on an error. The binding cookie is SameSite=Lax: the page must be same-site with
the API (e.g. `app.site.com` and `api.site.com`, or a proxy), and a cross-origin API needs
CORS with credentials.

### AuthStore

The state of a sign-in: the data lives in the default cache (`auth_store_<key>`), the
client holds only the store token (a JWT signed with `SECRET_KEY`, with the random key as
`sub` and no expiration), as the bearer token, the cookie or the query parameter
`BAZIS_AUTH_COOKIE_NAME`.

**Location**: `bazis.contrib.authing.service.AuthStore`

**Purpose**:
- Store temporary authentication data in the cache
- Track multi-step authentication progress
- Pass errors between requests

**Main methods**:

- `login(user, request, auth_type)` — registers successful user authentication
- `set_error(code, detail)` — saves authentication error
- `data_reset()` — clears storage
- `redirect_to_auth()` — the answer of a login: 303 to `/auth/` with the cookie, without
  the store token in the URL
- `response_set_cookie(response)` — adds the store cookie to a response (HttpOnly,
  SameSite=Lax, Secure unless `BAZIS_AUTH_COOKIE_SECURE` is off, for the lifetime of the
  store)
- `as_cookie()` — the same cookie as a `JsonApiCookie`, for
  `JsonApiBazisException(errors, cookies=[...])`
- `claim()` — the signed-in user id, once (deletes the store); used by `/auth/`

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
    'bazis.contrib.authing.services.password',  # Username/password
    # Add other methods here
]
```

**2. Register routes**:

```python
# router.py
from bazis.core.routing import BazisRouter

router = BazisRouter(prefix='/api/v1')

# Register authentication routes
from bazis.contrib.authing.routes import router as authing_router
from bazis.contrib.authing.services.password.router import router as password_router

router.register(prefix='/authing', arg=authing_router)
# the router of every service in BAZIS_AUTH_KINDS
router.register(prefix='/authing', arg=password_router)
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
Authorization: Bearer auth_token_here
Content-Type: application/json

{
  "username": "user1",
  "password": "password123"
}
```

**Response** (successful authentication):
```
HTTP 303 See Other
Location: /api/v1/authing/auth/
Set-Cookie: bazis_auth=auth_token_here; HttpOnly; Max-Age=60; Path=/; SameSite=lax; Secure
```

**Step 3**: Client follows redirect with the same token and gets user data (once: the
store is deleted, a new login needs a new store):

```bash
GET /api/v1/authing/auth/
Authorization: Bearer auth_token_here
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

For direct JWT token retrieval (e.g., for mobile apps or Swagger), the token endpoint of
bazis-users (`BAZIS_OPENAPI_TOKEN_URL`, default `/api/openapi-token/`):

```bash
POST /api/openapi-token/
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

### Logout

```bash
POST /api/v1/authing/logout/
Authorization: Bearer auth_token_here
```

Deletes the authorization stores of the request (bearer token, cookie or query parameter)
and the `bazis_auth` cookie; answers 204 and is idempotent. The session JWT is stateless:
the client drops it.

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

- **Single-use store** — `/auth/` gives the session of a signed-in store once
- **Temporary tokens** — a store lives `BAZIS_AUTH_COOKIE_LIFETIME` seconds (default 600),
  a signed-in one `BAZIS_AUTH_CLAIM_LIFETIME` (default 60); the cookie lives as long
- **Cookie attributes** — HttpOnly, SameSite=Lax, Secure (`BAZIS_AUTH_COOKIE_SECURE=false`
  for development over plain HTTP)
- **No tokens in URLs** — the login redirects, the Google window and the Google state do
  not carry the store token
- **Login CSRF of the Google window** — a URL that starts a sign-in of a store works only
  in the browser that asked for it: the ticket of `POST /google-auth-init/` is one-time,
  lives 60 seconds and needs the HttpOnly `__Host-` cookie that the POST set. So an
  attacker cannot send a victim a link that signs the attacker's store in with the
  victim's Google account (a victim who already consented in Google returns without a
  prompt) and take the session
- **Residual risks** — with `BAZIS_AUTH_COOKIE_SECURE=false` the binding cookie has no
  `__Host-` prefix, and a sibling subdomain or a network attacker can plant it. The binding
  does not protect against a script on a same-site page that can send credentialed
  requests (an XSS on `app.site.com` can run the flow itself). The store cookie
  (`BAZIS_AUTH_COOKIE_NAME`) has no prefix either and can be planted the same way (known,
  not changed in this release)
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
    """Returns logout actions (optional): a list of actions"""
    return [
        {
            'url': '/api/v1/authing/oauth/logout/',
            'method': 'POST',
        },
    ]

@router.get('/')
def oauth_login():
    # OAuth authentication logic
    pass
```

**2. Add to settings.py**:

```python
BAZIS_AUTH_KINDS = [
    'bazis.contrib.authing.services.password',
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