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

    response = get_api_client(sample_app, error['meta']['token']).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'user1',
            'password': 'wrong_password',
        },
    )
    assert response.status_code == 400



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

    response = get_api_client(sample_app).get(
        '/api/v1/authing/auth/', params=parse_qs(location.query)
    )
    assert response.status_code == 200
    data = response.json()
    assert data['username'] == '1001'
    assert data['email'] == 'g@site.com'
    assert data['first_name'] == ''
