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


import logging
from html import escape
from secrets import token_hex

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.db.models import Q
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _

from fastapi import Body, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from pydantic import BaseModel

from asgiref.sync import async_to_sync, sync_to_async
from authlib.integrations.starlette_client import OAuth

from bazis.contrib.authing.service import AuthStoreTokenRequired
from bazis.core.routing import BazisRouter

from . import AUTH_CODE


logger = logging.getLogger(__name__)

User = get_user_model()


router = BazisRouter(tags=[_('Google Authentication')])

_oauth = None
def get_oauth():
    global _oauth
    if _oauth is None:
        _oauth = OAuth()
        _oauth.register(
            name='google',
            client_id=settings.BAZIS_G_AUTH_CLIENT_ID,
            client_secret=settings.BAZIS_G_AUTH_CLIENT_SECRET,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            access_token_url='https://accounts.google.com/o/oauth2/token',
            userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'},
        )
    return _oauth


claims_options = {
    'iss': {'values': ['accounts.google.com', 'https://accounts.google.com']}
}

# the OAuth state (one-time, in the cache) -> the store token: the store token is not sent
# to Google and does not come back in the URL of the callback
STATE_CACHE_PREFIX = 'auth_google_state_'


@router.get('/google-auth-init/')
async def google_auth_init(request: Request, auth_store: AuthStoreTokenRequired = Depends()):
    from bazis.core.app import app

    oauth_instance = await sync_to_async(get_oauth)()

    state = token_hex()
    await sync_to_async(cache.set)(
        f'{STATE_CACHE_PREFIX}{state}', auth_store.token.value, auth_store.lifetime
    )

    redirect_uri = settings.BAZIS_G_AUTH_REDIRECT_URI or (
        settings.HOST_URL + app.router.url_path_for('google_auth_callback')
    )
    return await oauth_instance.google.authorize_redirect(
        request,
        redirect_uri,
        state=state,
    )


CALLBACK_PAGE = (
    '<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>'
    '<body><p>{text}</p><script>window.close()</script></body></html>'
)


@router.get('/google-auth-callback/', response_class=HTMLResponse)
def google_auth_callback(request: Request):
    """
    Google returns the window here. The result of the sign-in goes to the store; the window
    gets a page without tokens: the client that holds the store token takes the session from
    the auth endpoint (the store gives it once, so the window does not take it).
    """
    state = request.query_params.get('state')
    if not state:
        raise HTTPException(status_code=400, detail="Missing state parameter")

    state_key = f'{STATE_CACHE_PREFIX}{state}'
    auth_store_value = cache.get(state_key)
    # the state is used once
    if not auth_store_value or not cache.delete(state_key):
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    auth_store = AuthStoreTokenRequired(token_param=auth_store_value)

    google_token = None
    try:
        oauth_instance = get_oauth()
        google_token = async_to_sync(oauth_instance.google.authorize_access_token)(
            request, claims_options=claims_options
        )
    except Exception:
        logger.exception('Google authentication: the access token was not received')
        auth_store.set_error('GOOGLE_AUTH_ERROR', 'Google authentication failed')
    google_sign_in(request, auth_store, google_token)

    page = CALLBACK_PAGE.format(
        title=escape(gettext('Google Authentication')),
        text=escape(gettext('The sign-in is finished: return to the application.')),
    )
    return auth_store.response_set_cookie(HTMLResponse(page))


class GoogleTokens(BaseModel):
    id_token: str
    access_token: str


@router.post('/google-auth-verify/')
def google_auth_verify(
    request: Request,
    auth_store: AuthStoreTokenRequired = Depends(),
    tokens: GoogleTokens | None = Body(default=None),
    id_token: str | None = Query(default=None, deprecated=True),
    access_token: str | None = Query(default=None, deprecated=True),
):
    """
    Signs in with the tokens a client received from Google itself (e.g. a mobile SDK).
    The tokens are expected in the body: in the query string they end up in access logs.
    """
    if tokens is None:
        if not id_token or not access_token:
            raise HTTPException(status_code=400, detail="Missing id_token or access_token")
        logger.warning('Google authentication: tokens passed in the query string (deprecated)')
        tokens = GoogleTokens(id_token=id_token, access_token=access_token)
    return google_create_user(request, auth_store, tokens.model_dump())


class GoogleAuthError(Exception):
    pass


def google_get_user(google_user: dict):
    """
    Returns the user of the verified Google account, created if needed. A user is found by
    email, so the email must be verified by Google: otherwise anybody could register a
    Google account with the email of a user and sign in as that user.
    """
    email = google_user.get('email')
    if not email or google_user.get('email_verified') is not True:
        raise GoogleAuthError('The email of the Google account is not verified')

    user = User.find_or_create(
        Q(email__iexact=email),
        dict(
            email=email,
            username=google_user.get('sub'),
            first_name=google_user.get('given_name') or google_user.get('name') or '',
            last_name=google_user.get('family_name') or '',
            # the user signs in through Google only
            password=make_password(None),
        ),
    )
    if not user.is_active:
        raise GoogleAuthError('The user is inactive')
    return user


def google_sign_in(request: Request, auth_store, google_token: dict = None):
    """Signs the store in with the Google tokens, or records the error of the sign-in."""
    if google_token:
        try:
            oauth_instance = get_oauth()

            # the ID token is verified (signature, issuer, audience, expiration): its claims
            # identify the user
            google_user = dict(
                async_to_sync(oauth_instance.google.parse_id_token)(
                    google_token, None, claims_options=claims_options
                )
            )
            # the profile of the userinfo endpoint only completes the names, and only if
            # the access token belongs to the same account
            google_user_info = async_to_sync(oauth_instance.google.userinfo)(token=google_token)
            if google_user_info.get('sub') == google_user.get('sub'):
                for key in ('name', 'given_name', 'family_name'):
                    google_user.setdefault(key, google_user_info.get(key))

            user = google_get_user(google_user)
        except GoogleAuthError as exc:
            logger.info('Google authentication rejected: %s', exc)
            auth_store.set_error('GOOGLE_AUTH_ERROR', str(exc))
        except Exception:
            logger.exception('Google authentication failed')
            auth_store.set_error('GOOGLE_AUTH_ERROR', 'Google authentication failed')
        else:
            auth_store.login(user, request, AUTH_CODE)


def google_create_user(request: Request, auth_store, google_token: dict = None):
    """Signs the store in with the Google tokens and answers 303 to the auth endpoint."""
    google_sign_in(request, auth_store, google_token)
    return auth_store.redirect_to_auth()