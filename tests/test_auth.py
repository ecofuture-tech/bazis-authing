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
from bazis.contrib.users.service import RequestTokens


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

    store = AuthStore(RequestTokens())
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
    auth_store = AuthStoreTokenRequired(RequestTokens(param=store_token))

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

    first = AuthStore(RequestTokens(param=store))
    second = AuthStore(RequestTokens(param=store))
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
def test_auth_answer_of_an_anonymous_user(sample_app):
    """
    The answer of `GET /auth/` without a session: the error of the application with the
    store cookie and its attributes.
    """
    from starlette.testclient import TestClient

    response = TestClient(sample_app).get('/api/v1/authing/auth/')
    assert response.status_code == 400
    assert response.headers['content-type'] == 'application/json'
    errors = response.json()['errors']
    assert [(err['status'], err['code']) for err in errors] == [(401, 'UNAUTHORIZED')]
    store = errors[0]['meta']['token']
    assert response.headers.get_list('set-cookie') == [
        f'bazis_auth={store}; HttpOnly; Max-Age=60; Path=/; SameSite=lax; Secure'
    ]


@pytest.mark.django_db(transaction=True)
def test_password_redirect_without_store_token(sample_app):
    User.objects.create_user('user1', password='weak_password_1')
    store = new_store(sample_app)
    response = password_login(sample_app, store)
    assert response.status_code == 303
    assert response.headers['location'] == '/api/v1/authing/auth/'


GOOGLE_INIT_URL = '/api/v1/authing/google-auth-init/'


class FakeGoogle:
    """The Google client of authlib: the redirect to Google and a signed-in account."""

    def __init__(self):
        self.sent = {}

    async def authorize_redirect(self, request, redirect_uri, state=None):
        from starlette.responses import RedirectResponse

        self.sent['state'] = state
        return RedirectResponse(f'https://accounts.google.com/o/oauth2/auth?state={state}', 302)

    async def authorize_access_token(self, request, claims_options=None):
        return {'id_token': 'id-token', 'access_token': 'access-token'}

    async def parse_id_token(self, token, nonce, claims_options=None):
        return {'sub': '1001', 'email': 'g@site.com', 'email_verified': True}

    async def userinfo(self, token):
        return {'sub': '1001'}


@pytest.fixture
def google(sample_app, monkeypatch, settings):
    """
    The sample application with the Google router under its prefix (the sample does not
    register it), and a mocked Google client: `google.app`, `google.sent` (the state sent
    to Google).
    """
    from types import SimpleNamespace

    from fastapi import FastAPI

    import bazis.core.app
    from bazis.contrib.authing.services.google import routes as google_routes

    app = FastAPI(
        routes=list(sample_app.router.routes), exception_handlers=sample_app.exception_handlers
    )
    app.include_router(google_routes.router, prefix='/api/v1/authing')
    # url_path_for of the login action resolves in this application
    monkeypatch.setattr(bazis.core.app, 'app', app)
    fake = FakeGoogle()
    monkeypatch.setattr(google_routes, 'get_oauth', lambda: SimpleNamespace(google=fake))
    settings.BAZIS_G_AUTH_REDIRECT_URI = 'https://api.site.com/google-auth-callback/'
    return SimpleNamespace(app=app, sent=fake.sent)


BINDING_COOKIE = '__Host-bazis_google_init'


def browser(app, scheme='https'):
    """A browser (over HTTPS the cookies are Secure) that does not follow redirects."""
    from starlette.testclient import TestClient

    return TestClient(app, base_url=f'{scheme}://testserver', follow_redirects=False)


def google_init_ticket(client, store: str):
    response = client.post(GOOGLE_INIT_URL, headers={'Authorization': f'Bearer {store}'})
    assert response.status_code == 200, response.text
    return response


def google_state_store(state: str):
    from django.core.cache import cache

    from bazis.contrib.authing.services.google.routes import STATE_CACHE_PREFIX

    return cache.get(f'{STATE_CACHE_PREFIX}{state}')


@pytest.mark.django_db(transaction=True)
def test_google_init_ticket(sample_app, google, settings):
    """
    `POST /google-auth-init/` with the store token gives a one-time ticket for the URL of
    the window, and binds it to this browser with an HttpOnly `__Host-` cookie (no other
    origin can set it).
    """
    from django.core.cache import cache

    from bazis.contrib.authing.services.google.routes import TICKET_CACHE_PREFIX

    store = new_store(sample_app)
    response = google_init_ticket(browser(google.app), store)
    data = response.json()
    assert data == {'ticket': data['ticket'], 'url': f'{GOOGLE_INIT_URL}?ticket={data["ticket"]}'}
    assert store not in response.text
    assert 0 < cache.ttl(f'{TICKET_CACHE_PREFIX}{data["ticket"]}') <= 60

    cookie = cookie_attributes(response.headers['set-cookie'])
    assert cookie[''] == BINDING_COOKIE
    assert cookie['Path'] == '/' and 'Domain' not in cookie
    assert cookie['Max-Age'] == '60'
    assert cookie['SameSite'].lower() == 'lax'
    assert 'HttpOnly' in cookie and 'Secure' in cookie
    assert store not in response.headers['set-cookie']

    # development over HTTP: a cookie without Secure cannot have the prefix
    settings.BAZIS_AUTH_COOKIE_SECURE = False
    response = google_init_ticket(browser(google.app, 'http'), store)
    cookie = cookie_attributes(response.headers['set-cookie'])
    assert cookie[''] == 'bazis_google_init'
    assert cookie['Path'] == '/' and 'Secure' not in cookie

    # only the client that holds a store gets a ticket
    assert browser(google.app).post(GOOGLE_INIT_URL).status_code == 401


@pytest.mark.django_db(transaction=True)
def test_google_init_ticket_is_bound_to_the_browser(sample_app, google):
    """
    Login CSRF: an attacker mints a ticket for the attacker's store and sends the victim the
    URL. The browser of the victim has no binding cookie: 400, no sign-in is started. A
    wrong cookie and a used or expired ticket are refused with the same answer.
    """
    from django.core.cache import cache

    from bazis.contrib.authing.services.google.routes import TICKET_CACHE_PREFIX

    def refused(response):
        assert response.status_code == 400
        assert 'location' not in response.headers
        return response.json()

    attacker = browser(google.app)
    url = google_init_ticket(attacker, new_store(sample_app)).json()['url']
    answer = refused(browser(google.app).get(url))
    assert google.sent == {}

    url = google_init_ticket(attacker, new_store(sample_app)).json()['url']
    victim = browser(google.app)
    victim.cookies.set(BINDING_COOKIE, 'wrong')
    assert refused(victim.get(url)) == answer
    assert google.sent == {}

    # the ticket is used once: also the binding cookie is gone after its use
    client = browser(google.app)
    url = google_init_ticket(client, new_store(sample_app)).json()['url']
    assert client.get(url).status_code == 302
    google.sent.clear()
    assert refused(client.get(url)) == answer
    url = google_init_ticket(client, new_store(sample_app)).json()['url']
    cookie = client.cookies.get(BINDING_COOKIE)
    assert client.get(url).status_code == 302
    google.sent.clear()
    client.cookies.set(BINDING_COOKIE, cookie)
    assert refused(client.get(url)) == answer
    assert google.sent == {}

    # an expired ticket
    data = google_init_ticket(client, new_store(sample_app)).json()
    cache.delete(f'{TICKET_CACHE_PREFIX}{data["ticket"]}')
    assert refused(client.get(data['url'])) == answer
    assert google.sent == {}

    # the binding planted under the name without the prefix (by a sibling subdomain or over
    # plain HTTP, which cannot set a `__Host-` cookie) is not read
    data = google_init_ticket(attacker, new_store(sample_app)).json()
    binding = cache.get(f'{TICKET_CACHE_PREFIX}{data["ticket"]}')['binding']
    victim = browser(google.app)
    victim.cookies.set('bazis_google_init', binding)
    assert refused(victim.get(data['url'])) == answer
    assert google.sent == {}


@pytest.mark.django_db(transaction=True)
def test_google_init_ticket_is_used_once_by_concurrent_windows(sample_app, google, monkeypatch):
    """
    Concurrent windows with the cookie of the ticket: all of them read the ticket before any
    of them deletes it, and only the one whose deletion removed it is redirected to Google.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from django.core.cache import cache

    from bazis.contrib.authing.services.google import routes as google_routes

    windows = 5
    read_all = Barrier(windows)

    class ConcurrentCache:
        def __getattr__(self, name):
            return getattr(cache, name)

        def get(self, key, *args, **kwargs):
            value = cache.get(key, *args, **kwargs)
            if key.startswith(google_routes.TICKET_CACHE_PREFIX):
                read_all.wait(timeout=10)
            return value

    owner = browser(google.app)
    url = google_init_ticket(owner, new_store(sample_app)).json()['url']
    binding = owner.cookies.get(BINDING_COOKIE)
    monkeypatch.setattr(google_routes, 'cache', ConcurrentCache())

    def open_window(_):
        client = browser(google.app)
        client.cookies.set(BINDING_COOKIE, binding)
        return client.get(url).status_code

    with ThreadPoolExecutor(windows) as pool:
        statuses = sorted(pool.map(open_window, range(windows)))
    assert statuses == [302] + [400] * (windows - 1)


@pytest.mark.django_db(transaction=True)
def test_google_init_ticket_is_spent_by_a_wrong_cookie(sample_app, google):
    """
    The ticket is used up before the cookie is compared: after the URL was opened with a
    wrong cookie, it does not work in the browser that asked for it either.
    """
    owner = browser(google.app)
    url = google_init_ticket(owner, new_store(sample_app)).json()['url']
    other = browser(google.app)
    other.cookies.set(BINDING_COOKIE, 'wrong')
    assert other.get(url).status_code == 400
    assert owner.get(url).status_code == 400
    assert google.sent == {}


@pytest.mark.django_db(transaction=True)
def test_google_init_ticket_of_a_spent_store(sample_app, google):
    """The store of the ticket was deleted (logout, expired, spent) before the window opened."""
    store = new_store(sample_app)
    client = browser(google.app)
    url = google_init_ticket(client, store).json()['url']
    assert get_api_client(sample_app, store).post('/api/v1/authing/logout/').status_code == 204

    assert client.get(url).status_code == 401
    assert google.sent == {}


@pytest.mark.django_db(transaction=True)
def test_google_init_over_plain_http(sample_app, google, settings):
    """Development without BAZIS_AUTH_COOKIE_SECURE: the binding cookie has no prefix."""
    settings.BAZIS_AUTH_COOKIE_SECURE = False
    store = new_store(sample_app)
    client = browser(google.app, 'http')
    url = google_init_ticket(client, store).json()['url']
    assert client.cookies.get('bazis_google_init')
    assert client.get(url).status_code == 302
    assert google_state_store(google.sent['state']) == store


@pytest.mark.django_db(transaction=True)
def test_google_init_with_the_store_token_in_the_url(sample_app, google):
    """
    `GET /google-auth-init/?bazis_auth=<store>` (the init before 2.8) starts no sign-in: the
    window needs a ticket, which the login action tells the clients to get by POST.
    """
    from django.core.cache import cache

    from bazis.contrib.authing.services import google as google_service
    from bazis.contrib.authing.services.google.routes import STATE_CACHE_PREFIX

    assert google_service.get_login_action() == {
        'code': 'google', 'name': 'Google Authentication', 'url': GOOGLE_INIT_URL, 'method': 'POST'
    }
    store = new_store(sample_app)
    states = set(cache.keys(f'{STATE_CACHE_PREFIX}*'))
    response = browser(google.app).get(GOOGLE_INIT_URL, params={'bazis_auth': store})
    assert response.status_code == 422
    assert 'location' not in response.headers and 'set-cookie' not in response.headers
    assert google.sent == {}
    assert set(cache.keys(f'{STATE_CACHE_PREFIX}*')) == states


@pytest.mark.django_db(transaction=True)
def test_google_flow_keeps_the_store_token_out_of_urls(sample_app, google):
    """
    The store token is in no URL: the window opens the init with a ticket, the state sent
    to Google is another one-time value, and the callback ends the window without the token
    and without taking the session, which the client that holds the store asks for.
    """
    from starlette.requests import Request

    from bazis.contrib.authing.services.google import routes as google_routes

    store = new_store(sample_app)
    client = browser(google.app)
    url = google_init_ticket(client, store).json()['url']
    assert store not in url
    response = client.get(url)
    assert response.status_code == 302
    assert store not in response.headers['location'] and store not in response.text
    # the binding cookie is dropped
    cookie = cookie_attributes(response.headers['set-cookie'])
    assert cookie[''] == BINDING_COOKIE and cookie['Max-Age'] == '0'
    assert cookie['Path'] == '/' and 'Secure' in cookie
    state = google.sent['state']
    assert state and store not in state
    assert google_state_store(state) == store

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
    # a successful sign-in refreshes the store cookie of the window
    assert response.headers['set-cookie'].startswith('bazis_auth=')

    # the state is used once
    with pytest.raises(Exception) as exc:
        callback(state)
    assert exc.value.status_code == 400

    response = get_api_client(sample_app, store).get('/api/v1/authing/auth/')
    assert response.status_code == 200
    assert response.json()['email'] == 'g@site.com'
    assert_not_authenticated(get_api_client(sample_app, store).get('/api/v1/authing/auth/'), store)


@pytest.mark.django_db(transaction=True)
def test_forged_google_callback_sets_no_cookie(sample_app, monkeypatch):
    """
    A callback URL with the state of another browser (e.g. of an attacker's store): authlib
    rejects the state, which is not in the session of this browser, so the window gets no
    cookie of that store and the store is not signed in.
    """
    from starlette.requests import Request

    from bazis.contrib.authing.service import AuthStore
    from bazis.contrib.authing.services.google import routes as google_routes

    class MismatchingStateError(Exception):
        pass

    class FakeGoogle:
        async def authorize_access_token(self, request, claims_options=None):
            raise MismatchingStateError('state not in the session')

    class FakeOAuth:
        google = FakeGoogle()

    monkeypatch.setattr(google_routes, 'get_oauth', lambda: FakeOAuth())

    from django.core.cache import cache

    attacker_store = new_store(sample_app)
    state = 'forged-state'
    cache.set(f'{google_routes.STATE_CACHE_PREFIX}{state}', attacker_store, 60)

    response = google_routes.google_auth_callback(
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
    assert response.status_code == 200
    assert 'set-cookie' not in response.headers
    store = AuthStore(RequestTokens(param=attacker_store))
    assert store.user_id is None
    assert [err.code for err in store.errors] == ['GOOGLE_AUTH_ERROR']


@pytest.mark.django_db(transaction=True)
def test_the_token_endpoint_of_the_password_service(sample_app):
    """
    `POST /password/token/` is the token endpoint of bazis-users under the path of the
    password service (deprecated), with its operation id.
    """
    from starlette.testclient import TestClient

    User.objects.create_user('token_user', password='weak_password_1')
    client = TestClient(sample_app)
    url = '/api/v1/authing/password/token/'

    response = client.post(url, data={'username': 'token_user', 'password': 'weak_password_1'})
    assert response.status_code == 200
    assert response.json()['token_type'] == 'bearer'
    response = client.get('/api/v1/authing/auth/', headers={
        'Authorization': f'Bearer {response.json()["access_token"]}'
    })
    assert response.json()['username'] == 'token_user'

    response = client.post(url, data={'username': 'token_user', 'password': 'wrong'})
    assert response.status_code == 401

    operation = sample_app.openapi()['paths'][url]['post']
    assert operation['operationId'] == 'token_auth_api_v1_authing_password_token__post'
    assert operation['deprecated'] is True


@pytest.mark.django_db(transaction=True)
def test_the_logout_actions_of_the_service_of_the_session(sample_app, monkeypatch):
    """
    `GET /auth/` with a session gives the logout actions of the service it was signed in
    with (`get_logout_actions`, optional), else none.
    """
    from bazis.contrib.authing.services import password

    user = User.objects.create_user('logout_user', password='weak_password_1')
    client = get_api_client(sample_app, user.jwt_build(auth_type='password'))
    assert client.get('/api/v1/authing/auth/').json()['logout_actions'] is None

    actions = [{'url': '/api/v1/authing/password/logout/', 'method': 'POST'}]
    monkeypatch.setattr(password, 'get_logout_actions', lambda: actions, raising=False)
    assert client.get('/api/v1/authing/auth/').json()['logout_actions'] == actions
    client = get_api_client(sample_app, user.jwt_build(auth_type='google'))
    assert client.get('/api/v1/authing/auth/').json()['logout_actions'] is None


def test_get_token_header_is_kept_until_3_0():
    """
    The deprecated dependency still gives the bearer token of `Authorization` (projects
    read tokens of their own with it).
    """
    from fastapi import Depends, FastAPI

    from starlette.testclient import TestClient

    from bazis.contrib.authing.service import get_token_header

    app = FastAPI()

    @app.get('/probe/')
    def probe(token: str | None = Depends(get_token_header)):
        return {'token': token}

    client = TestClient(app)
    assert client.get('/probe/', headers={'Authorization': 'Bearer abc'}).json() == {'token': 'abc'}
    assert client.get('/probe/', headers={'Authorization': 'Basic abc'}).json() == {'token': None}
    assert client.get('/probe/').json() == {'token': None}
