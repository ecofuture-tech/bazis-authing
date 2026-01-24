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


import traceback
from urllib.parse import parse_qs, urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from starlette.status import HTTP_303_SEE_OTHER

from asgiref.sync import async_to_sync, sync_to_async
from authlib.integrations.starlette_client import OAuth

from bazis.contrib.authing.service import AuthStoreTokenRequired
from bazis.core.routing import BazisRouter

from . import AUTH_CODE


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


@router.get('/google-auth-init/')
async def google_auth_init(request: Request, auth_store: AuthStoreTokenRequired = Depends()):
    from bazis.core import app

    oauth_instance = await sync_to_async(get_oauth)()

    state_params = {
        settings.BAZIS_AUTH_COOKIE_NAME: auth_store.token.value
    }

    redirect_uri = settings.HOST_URL + app.router.router.url_path_for('google_auth_callback')
    return await oauth_instance.google.authorize_redirect(
        request,
        redirect_uri,
        state=urlencode(state_params),
    )


@router.get('/google-auth-callback/')
def google_auth_callback(request: Request):
    # Restore state from callback
    state = request.query_params.get('state')
    if not state:
        raise HTTPException(status_code=400, detail="Missing state parameter")

    # Decode state and extract BAZIS_AUTH_COOKIE_NAME
    state_data = parse_qs(state)
    auth_store_value = state_data.get(settings.BAZIS_AUTH_COOKIE_NAME)
    if not auth_store_value:
        raise HTTPException(status_code=400, detail="Missing token value in state")
    auth_store_value = auth_store_value[0]

    auth_store = AuthStoreTokenRequired(token_param=auth_store_value)

    google_token = None
    try:
        oauth_instance = get_oauth()
        google_token = async_to_sync(oauth_instance.google.authorize_access_token)(
            request, claims_options=claims_options
        )
    except Exception as e:
        print(traceback.format_exc())
        auth_store.set_error('GOOGLE_AUTH_ERROR', f'Error: {e}')
    return google_create_user(request, auth_store, google_token)


@router.post('/google-auth-verify/')
def google_auth_verify(request: Request, id_token: str, access_token: str, auth_store: AuthStoreTokenRequired = Depends()):
    if not id_token or not access_token:
        raise HTTPException(status_code=400, detail="Missing id_token or access_token")
    return google_create_user(request, auth_store, {'id_token': id_token, 'access_token': access_token})


def google_create_user(request: Request, auth_store, google_token: dict = None):
    from bazis.core import app

    if google_token:
        try:
            oauth_instance = get_oauth()

            google_user = async_to_sync(oauth_instance.google.parse_id_token)(
                google_token, None, claims_options=claims_options
            )
            # Request to the Userinfo endpoint to get user data
            google_user_info = async_to_sync(oauth_instance.google.userinfo)(token=google_token)
            google_user |= google_user_info

            print('google_user_info:', google_user)

            user = User.find_or_create(
                Q(email=google_user['email']),
                dict(
                    email=google_user.get('email'),
                    username=google_user.get('sub'),
                    first_name=google_user.get('given_name') or google_user.get('name'),
                    last_name=google_user.get('family_name'),
                    password='',
                ),
            )
        except Exception as e:
            print(traceback.format_exc())
            auth_store.set_error('GOOGLE_AUTH_ERROR', f'Error: {e}')
        else:
            auth_store.login(user, request, AUTH_CODE)

    return auth_store.response_set_cookie(
        RedirectResponse(
            app.router.router.url_path_for('auth') + f'?{auth_store.as_param}',
            status_code=HTTP_303_SEE_OTHER,
        )
    )