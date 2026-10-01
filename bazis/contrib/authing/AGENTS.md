# bazis-authing — guide for AI agents

Sign-in flows for Bazis on top of bazis-users: login by password and by Google OAuth,
collected in an authorization store and exchanged for a session JWT by `GET /auth/`.
Use it when clients (web, mobile) sign in interactively; bazis-users alone only has the
token endpoint `BAZIS_OPENAPI_TOKEN_URL`.

## Setup

```python
# router.py of the project (paths below are relative to this router)
router = BazisRouter(prefix='/api/v1')
router.register('/authing', 'bazis.contrib.authing.router')                    # /auth/
router.register('/authing', 'bazis.contrib.authing.services.password.router')  # /password/
router.register('/authing', 'bazis.contrib.authing.services.google.router')    # Google
```

- `BS_INSTALLED_APPS` includes `bazis.contrib.authing` (it registers the system checks;
  the package has no models). If `BS_BAZIS_APPS` (or `BS_BAZIS_CONFIG_APPS`) is set, it
  must list `bazis.contrib.authing` and, for Google, `bazis.contrib.authing.services.google`:
  only the settings of the listed modules are loaded.
- `BS_BAZIS_AUTH_KINDS='["bazis.contrib.authing.services.password",
  "bazis.contrib.authing.services.google"]'`: the services `/auth/` offers (default: password
  only). Register the router of every listed service (`authing.E001`); a module that does not
  import is skipped silently (`authing.W001`).
- `BS_BAZIS_AUTH_COOKIE_LIFETIME` (default 600): seconds the store data lives in the cache.
  The store is in the Django default cache (`auth_store_<key>`): every process must share it
  (Redis).
- `BS_AUTHENTICATION_BACKENDS` (default `["django.contrib.auth.backends.ModelBackend"]`):
  used by the password login.
- Google: dynamic settings (Constance, stored in the database, edited in the admin)
  `BAZIS_G_AUTH_CLIENT_ID`, `BAZIS_G_AUTH_CLIENT_SECRET`, optional
  `BAZIS_G_AUTH_REDIRECT_URI` (default `HOST_URL` + the path of `/google-auth-callback/`:
  set `BS_HOST_URL`). Register that redirect URI in the Google OAuth client. The OAuth
  client is built once per process: restart after changing these settings.

## Flows

1. `GET /auth/` without a session: HTTP 400 with an error `status: 401`,
   `code: UNAUTHORIZED`, `meta.actions` (the login actions: `code`, `name`, `url`,
   `method`) and `meta.token` (the store token, also set as the cookie
   `BAZIS_AUTH_COOKIE_NAME`, default `bazis_auth`). Failed attempts of this store follow
   as errors with `status: 422` (`USERNAME_PASSWORD_ERROR`, `GOOGLE_AUTH_ERROR`).
2. Sign in with the store token (cookie, `Authorization: Bearer` or the query parameter
   `BAZIS_AUTH_COOKIE_NAME`; missing or expired: 401):
   - `POST /password/` JSON `{"username", "password"}`;
   - Google in a browser: open `GET /google-auth-init/?bazis_auth=<store token>`; Google
     returns to `/google-auth-callback/`;
   - Google SDK (mobile): `POST /google-auth-verify/` JSON `{"id_token", "access_token"}`.
   Each answers 303 to `/auth/?bazis_auth=<store token>` (and sets the cookie).
3. `GET /auth/` with a signed-in store or a valid session token: 200
   `{user_id, username, first_name, last_name, email, token, logout_actions}`; `token` is
   the session JWT of bazis-users (with `auth_type`). Send it as `Authorization: Bearer`.
- `POST /password/token/` (OAuth2 password form) returns
  `{"access_token", "token_type": "bearer"}` directly, without the store.

## Security properties

- The store token is a JWT with only `sub` (a random key), no `exp`: bazis-users treats it
  as anonymous on HTTP, bazis-ws rejects it; a session token is never accepted as a store
  token. Until the store expires, `GET /auth/` with it returns a new session token: on
  logout drop the store cookie as well as the session token.
- Google: the ID token is verified (signature, issuer, audience, expiration) and identifies
  the account; the email must have `email_verified: true`. The user is found by email
  (case-insensitive) or created (`username` = Google `sub`, unusable password). An existing
  user with that email, staff included, is signed in; to restrict accounts change
  `google_get_user` (`bazis.contrib.authing.services.google.routes`).
- Inactive users cannot sign in (`ModelBackend`, `google_get_user`, and `/auth/` loads only
  active users from the store).
- Never log tokens or Google profile data.

## Own service

A module listed in `BAZIS_AUTH_KINDS` with `AUTH_CODE`, `get_login_action()` (optional
`get_logout_actions()`) and a router whose endpoint takes
`auth_store: AuthStoreTokenRequired = Depends()`, calls
`auth_store.login(user, request, AUTH_CODE)` (or `auth_store.set_error(code, detail)`) and
returns `auth_store.response_set_cookie(RedirectResponse(app.router.url_path_for('auth') +
f'?{auth_store.as_param}', status_code=303))` (`app` from `bazis.core.app`), as
`services/password/routes.py` does.
