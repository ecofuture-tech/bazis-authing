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

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.signals import user_logged_in
from django.utils.translation import gettext_lazy as _

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED

from bazis.contrib.authing.service import AuthStoreTokenRequired
from bazis.core.routing import BazisRouter

from . import AUTH_CODE
from .schemas import PasswordRequest, TokenResponse


User = get_user_model()

router = BazisRouter(prefix='/password', tags=[_('Authentication')])


@router.post('/')
def password_auth(request: Request, data: PasswordRequest, auth_store: AuthStoreTokenRequired = Depends()):
    from bazis.core.app import app
    # clear the storage
    auth_store.data_reset()
    if user := authenticate(username=data.username, password=data.password):
        auth_store.login(user, request, AUTH_CODE)
    else:
        auth_store.set_error('USERNAME_PASSWORD_ERROR', 'Credentials are invalid')
    return auth_store.response_set_cookie(
        RedirectResponse(app.router.url_path_for('auth') + f'?{auth_store.as_param}', status_code=HTTP_303_SEE_OTHER)
    )


@router.post('/token/', response_model=TokenResponse)
def token_auth(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    if not (user := authenticate(username=form_data.username, password=form_data.password)):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail='Credentials are invalid',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    return {
        'access_token': user.jwt_build(auth_type='password'),
        'token_type': 'bearer'
    }
