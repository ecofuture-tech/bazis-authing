# Copyright 2026 EcoFuture Technology Services LLC and contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest
from bazis_test_utils.utils import get_api_client

from bazis.contrib.users import get_user_model


User = get_user_model()


@pytest.mark.django_db(transaction=True)
def test_password_auth(sample_app):
    user_1 = User.objects.create_user('user1', email='user1@site.com', password='weak_password_2')

    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    assert response.status_code == 400

    data = response.json()

    assert 'errors' in data
    assert len(data['errors']) == 1

    error = data['errors'][0]
    assert error['status'] == 401
    assert error['code'] == 'UNAUTHORIZED'

    assert error['meta']['actions'] == [
        {
            "code": "password",
            "name": "Login/Password",
            "url": "/api/v1/authing/password/",
            "method": "POST",
        },
    ]

    response = get_api_client(sample_app, error['meta']['token']).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'user1',
            'password': 'weak_password_2',
        },
    )
    assert response.status_code == 200

    data = response.json()

    assert data['user_id'] == str(user_1.id)
    assert data['username'] == 'user1'
    assert data['email'] == 'user1@site.com'

    # a failed login answers the errors of the store (a new store: the first one is spent)
    store = get_api_client(sample_app).get('/api/v1/authing/auth/').json()['errors'][0]['meta'][
        'token'
    ]
    response = get_api_client(sample_app, store).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'user1',
            'password': 'wrong_password',
        },
    )
    assert response.status_code == 400
    errors = response.json()['errors']
    assert [err['code'] for err in errors] == ['UNAUTHORIZED', 'USERNAME_PASSWORD_ERROR']
    # the store of a failed login stays: the client retries with it
    assert errors[0]['meta']['token'] == store


@pytest.mark.django_db(transaction=True)
def test_auth_with_foreign_token(sample_app):
    """
    A store token signed with another key (e.g. before SECRET_KEY rotation) is replaced by
    a new one instead of failing every request with 401.
    """
    import jwt

    foreign = jwt.encode({'sub': 'store'}, 'x' * 40, algorithm='HS256')

    response = get_api_client(sample_app).get(f'/api/v1/authing/auth/?bazis_auth={foreign}')
    assert response.status_code == 400
    error = response.json()['errors'][0]
    assert error['code'] == 'UNAUTHORIZED'
    assert error['meta']['token'] != foreign

    # the store is required by the login routes
    response = get_api_client(sample_app, foreign).post(
        '/api/v1/authing/password/', json_data={'username': 'user', 'password': 'password'}
    )
    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_auth_errors_accumulate(sample_app):
    from bazis.contrib.authing.service import AuthStore

    store = AuthStore(token_param=None, token_cookie=None, token_header=None)
    store.set_error('FIRST', 'first')
    store.set_error('SECOND', 'second')
    assert [err.code for err in store.errors] == ['FIRST', 'SECOND']


@pytest.mark.django_db(transaction=True)
def test_google_user_requires_verified_email():
    from bazis.contrib.authing.services.google.routes import GoogleAuthError, google_get_user

    victim = User.objects.create_user('victim', email='victim@site.com', password='weak_password_1')
    claims = {'sub': '1234567890', 'email': 'Victim@site.com', 'given_name': 'Mallory'}

    for email_verified in (None, False, 'true'):
        with pytest.raises(GoogleAuthError):
            google_get_user(claims | {'email_verified': email_verified})

    # a verified email signs in the user with this email
    assert google_get_user(claims | {'email_verified': True}) == victim

    victim.is_active = False
    victim.save()
    with pytest.raises(GoogleAuthError):
        google_get_user(claims | {'email_verified': True})

    # a new verified account creates a user
    user = google_get_user(
        {'sub': '42', 'email': 'new@site.com', 'email_verified': True, 'name': 'New'}
    )
    assert user.username == '42'
    assert user.first_name == 'New'
    assert not user.has_usable_password()


@pytest.mark.django_db(transaction=True)
def test_google_sign_in(sample_app, monkeypatch):
    """
    The sign-in through Google with a mocked OAuth client: the ID token identifies the user,
    the userinfo of another account does not change it.
    """
    from urllib.parse import parse_qs, urlsplit

    from bazis.contrib.authing.service import AuthStoreTokenRequired
    from bazis.contrib.authing.services.google import routes as google_routes

    class FakeGoogle:
        async def parse_id_token(self, token, nonce, claims_options=None):
            assert token['id_token'] == 'id-token'
            return {'sub': '1001', 'email': 'g@site.com', 'email_verified': True}

        async def userinfo(self, token):
            # the access token of another account
            return {'sub': '2002', 'email': 'other@site.com', 'given_name': 'Other'}

    class FakeOAuth:
        google = FakeGoogle()

    monkeypatch.setattr(google_routes, 'get_oauth', lambda: FakeOAuth())

    store_token = get_api_client(sample_app).get('/api/v1/authing/auth/').json()['errors'][0][
        'meta'
    ]['token']
    auth_store = AuthStoreTokenRequired(token_param=store_token)

    response = google_routes.google_create_user(
        None, auth_store, {'id_token': 'id-token', 'access_token': 'access-token'}
    )
    assert response.status_code == 303
    location = urlsplit(response.headers['location'])
    assert location.path == '/api/v1/authing/auth/'

    # the store token is not in the URL: the client that holds it asks for the session
    assert store_token not in response.headers['location']
    assert parse_qs(location.query) == {}

    response = get_api_client(sample_app, store_token).get('/api/v1/authing/auth/')
    assert response.status_code == 200
    data = response.json()
    assert data['username'] == '1001'
    assert data['email'] == 'g@site.com'
    assert data['first_name'] == ''


@pytest.mark.django_db(transaction=True)
def test_google_verify_tokens_in_body(sample_app, monkeypatch):
    from fastapi import FastAPI

    from bazis.contrib.authing.services.google import routes as google_routes

    received = {}

    def fake_create_user(request, auth_store, google_token=None):
        received.update(google_token)
        return {'ok': True}

    monkeypatch.setattr(google_routes, 'google_create_user', fake_create_user)
    app = FastAPI()
    app.include_router(google_routes.router)
    store_token = get_api_client(sample_app).get('/api/v1/authing/auth/').json()['errors'][0][
        'meta'
    ]['token']
    client = get_api_client(app, store_token)

    response = client.post(
        '/google-auth-verify/', json_data={'id_token': 'id', 'access_token': 'access'}
    )
    assert response.status_code == 200, response.text
    assert received == {'id_token': 'id', 'access_token': 'access'}

    received.clear()
    response = client.post('/google-auth-verify/', params={'id_token': 'id2', 'access_token': 'a2'})
    assert response.status_code == 200
    assert received == {'id_token': 'id2', 'access_token': 'a2'}

    assert client.post('/google-auth-verify/').status_code == 400


@pytest.mark.django_db(transaction=True)
def test_session_token_is_not_a_store_token(sample_app):
    from bazis.contrib.authing.service import AuthToken
    from bazis.core.errors import JsonApi401Exception

    user = User.objects.create_user('user1', password='weak_password_1')
    assert AuthToken.parse(user.jwt_build()) is None
    with pytest.raises(JsonApi401Exception):
        AuthToken.parse(user.jwt_build(), required=True)
    store = AuthToken.new()
    assert AuthToken.parse(store.value).key == store.key


def new_store(sample_app) -> str:
    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    assert response.status_code == 400
    return response.json()['errors'][0]['meta']['token']


def password_login(sample_app, store: str, password='weak_password_1'):
    """POST /password/ without following the redirect: the store is signed in, not claimed."""
    from starlette.testclient import TestClient

    return TestClient(sample_app).post(
        '/api/v1/authing/password/',
        json={'username': 'user1', 'password': password},
        headers={'Authorization': f'Bearer {store}'},
        follow_redirects=False,
    )


def assert_not_authenticated(response, store: str):
    assert response.status_code == 400
    error = response.json()['errors'][0]
    assert error['code'] == 'UNAUTHORIZED'
    # a new store, not the spent one
    assert error['meta']['token'] != store


@pytest.mark.django_db(transaction=True)
def test_store_token_is_single_use(sample_app):
    """
    GET /auth/ gives the session of a signed-in store once: the store token, which travels
    in URLs and logs, does not give another session afterwards (Bearer, query or cookie).
    """
    User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    assert password_login(sample_app, store).status_code == 303

    response = get_api_client(sample_app, store).get('/api/v1/authing/auth/')
    assert response.status_code == 200
    assert response.json()['username'] == 'user1'
    session = response.json()['token']

    assert_not_authenticated(get_api_client(sample_app, store).get('/api/v1/authing/auth/'), store)
    assert_not_authenticated(
        get_api_client(sample_app).get('/api/v1/authing/auth/', params={'bazis_auth': store}),
        store,
    )
    # the spent store cannot be signed in again either
    assert password_login(sample_app, store).status_code == 401

    # the session token keeps working: /auth/ refreshes it every time
    for _ in range(2):
        response = get_api_client(sample_app, session).get('/api/v1/authing/auth/')
        assert response.status_code == 200
        assert response.json()['username'] == 'user1'


@pytest.mark.django_db(transaction=True)
def test_claim_of_an_inactive_user(sample_app):
    """A user deactivated before the claim: not authenticated, with a new store."""
    user = User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    assert password_login(sample_app, store).status_code == 303
    user.is_active = False
    user.save()

    response = get_api_client(sample_app, store).get('/api/v1/authing/auth/')
    assert_not_authenticated(response, store)
    new = response.json()['errors'][0]['meta']['token']
    # the new store works
    user.is_active = True
    user.save()
    assert password_login(sample_app, new).status_code == 303
    assert get_api_client(sample_app, new).get('/api/v1/authing/auth/').status_code == 200


@pytest.mark.django_db(transaction=True)
def test_store_claim_is_atomic(sample_app):
    """Two requests with the same signed-in store: only one of them gets the session."""
    from bazis.contrib.authing.service import AuthStore

    user = User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    assert password_login(sample_app, store).status_code == 303

    first = AuthStore(token_param=store, token_cookie=None, token_header=None)
    second = AuthStore(token_param=store, token_cookie=None, token_header=None)
    assert first.user_id == second.user_id == user.id
    assert first.claim() == user.id
    assert second.claim() is None
    # the store that lost the claim is a new one
    assert second.token.value != store


@pytest.mark.django_db(transaction=True)
def test_claim_deletes_the_store_cookie(sample_app):
    from starlette.testclient import TestClient

    User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    assert password_login(sample_app, store).status_code == 303

    response = TestClient(sample_app).get(
        '/api/v1/authing/auth/', headers={'Cookie': f'bazis_auth={store}'}
    )
    assert response.status_code == 200
    cookie = response.headers['set-cookie']
    assert cookie.startswith('bazis_auth=""') and 'Max-Age=0' in cookie


@pytest.mark.django_db(transaction=True)
def test_logout_clears_the_store(sample_app):
    """POST /logout/ deletes the store (a signed-in one is not claimed) and the cookie."""
    from starlette.testclient import TestClient

    User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    assert password_login(sample_app, store).status_code == 303

    client = TestClient(sample_app)
    for _ in range(2):  # idempotent
        response = client.post(
            '/api/v1/authing/logout/', headers={'Cookie': f'bazis_auth={store}'}
        )
        assert response.status_code == 204
        cookie = response.headers['set-cookie']
        assert cookie.startswith('bazis_auth=""') and 'Max-Age=0' in cookie

    assert_not_authenticated(get_api_client(sample_app, store).get('/api/v1/authing/auth/'), store)

    # the store token as the bearer token, and without any token
    store = new_store(sample_app)
    assert get_api_client(sample_app, store).post('/api/v1/authing/logout/').status_code == 204
    assert password_login(sample_app, store).status_code == 401
    assert get_api_client(sample_app).post('/api/v1/authing/logout/').status_code == 204


def cookie_attributes(header: str) -> dict:
    name, *attributes = (it.strip() for it in header.split(';'))
    return dict(it.partition('=')[::2] for it in attributes) | {'': name.partition('=')[0]}


@pytest.mark.django_db(transaction=True)
def test_store_cookie_attributes(sample_app, settings):
    """
    The store cookie lives as long as the store: BAZIS_AUTH_COOKIE_LIFETIME, then
    BAZIS_AUTH_CLAIM_LIFETIME once signed in; HttpOnly, SameSite=Lax, Secure unless
    BAZIS_AUTH_COOKIE_SECURE is off.
    """
    from django.core.cache import cache

    from bazis.contrib.authing.service import AuthToken

    User.objects.create_user('user1', password='weak_password_1')
    settings.BAZIS_AUTH_COOKIE_LIFETIME = 600
    settings.BAZIS_AUTH_CLAIM_LIFETIME = 30

    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    cookie = cookie_attributes(response.headers['set-cookie'])
    assert cookie[''] == 'bazis_auth'
    assert cookie['Max-Age'] == '600'
    assert 'HttpOnly' in cookie and 'Secure' in cookie
    assert cookie['SameSite'].lower() == 'lax'

    store = response.json()['errors'][0]['meta']['token']
    response = password_login(sample_app, store)
    cookie = cookie_attributes(response.headers['set-cookie'])
    assert cookie['Max-Age'] == '30'
    assert 'HttpOnly' in cookie and 'Secure' in cookie
    # the signed-in store waits for its claim only that long
    assert 0 < cache.ttl(f'auth_store_{AuthToken.parse(store).key}') <= 30

    settings.BAZIS_AUTH_COOKIE_SECURE = False
    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    cookie = cookie_attributes(response.headers['set-cookie'])
    assert 'Secure' not in cookie and 'HttpOnly' in cookie


@pytest.mark.django_db(transaction=True)
def test_password_redirect_without_store_token(sample_app):
    User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    response = password_login(sample_app, store)
    assert response.status_code == 303
    assert response.headers['location'] == '/api/v1/authing/auth/'


@pytest.mark.django_db(transaction=True)
def test_google_flow_keeps_the_store_token_out_of_urls(sample_app, monkeypatch, settings):
    """
    The store token is only in the URL of /google-auth-init/: the state sent to Google is
    another one-time value, and the callback ends the window without the token and without
    taking the session, which the client that holds the store asks for.
    """
    import asyncio

    from starlette.requests import Request
    from starlette.responses import RedirectResponse

    from bazis.contrib.authing.service import AuthStoreTokenRequired
    from bazis.contrib.authing.services.google import routes as google_routes

    sent = {}

    class FakeGoogle:
        async def authorize_redirect(self, request, redirect_uri, state=None):
            sent['state'] = state
            return RedirectResponse(f'https://accounts.google.com/?state={state}')

        async def authorize_access_token(self, request, claims_options=None):
            return {'id_token': 'id-token', 'access_token': 'access-token'}

        async def parse_id_token(self, token, nonce, claims_options=None):
            return {'sub': '1001', 'email': 'g@site.com', 'email_verified': True}

        async def userinfo(self, token):
            return {'sub': '1001'}

    class FakeOAuth:
        google = FakeGoogle()

    monkeypatch.setattr(google_routes, 'get_oauth', lambda: FakeOAuth())
    settings.BAZIS_G_AUTH_REDIRECT_URI = 'https://api.site.com/google-auth-callback/'

    store = new_store(sample_app)
    asyncio.run(
        google_routes.google_auth_init(None, AuthStoreTokenRequired(token_param=store))
    )
    state = sent['state']
    assert state and store not in state

    def callback(state):
        return google_routes.google_auth_callback(
            Request(
                {
                    'type': 'http',
                    'method': 'GET',
                    'path': '/google-auth-callback/',
                    'headers': [],
                    'query_string': f'state={state}&code=code'.encode(),
                }
            )
        )

    response = callback(state)
    assert response.status_code == 200
    assert 'location' not in response.headers
    assert store not in response.body.decode()

    # the state is used once
    with pytest.raises(Exception) as exc:
        callback(state)
    assert exc.value.status_code == 400

    response = get_api_client(sample_app, store).get('/api/v1/authing/auth/')
    assert response.status_code == 200
    assert response.json()['email'] == 'g@site.com'
    assert_not_authenticated(get_api_client(sample_app, store).get('/api/v1/authing/auth/'), store)
