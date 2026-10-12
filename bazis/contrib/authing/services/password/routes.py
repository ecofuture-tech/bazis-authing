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
from django.utils.translation import gettext_lazy as _

from fastapi import Depends, Request

from starlette.status import HTTP_401_UNAUTHORIZED

from bazis.contrib.authing.service import AuthStoreTokenRequired
from bazis.contrib.users.schemas import TokenResponse
from bazis.contrib.users.token import token_auth
from bazis.core.errors import SchemaErrors
from bazis.core.routing import BazisRouter

from . import AUTH_CODE
from .schemas import PasswordRequest


User = get_user_model()

router = BazisRouter(prefix='/password', tags=[_('Authentication')])


@router.post('/')
def password_auth(request: Request, data: PasswordRequest, auth_store: AuthStoreTokenRequired = Depends()):
    # clear the storage
    auth_store.data_reset()
    if user := authenticate(username=data.username, password=data.password):
        auth_store.login(user, request, AUTH_CODE)
    else:
        auth_store.set_error('USERNAME_PASSWORD_ERROR', 'Credentials are invalid')
    return auth_store.redirect_to_auth()


# the token endpoint of bazis-users (POST BAZIS_OPENAPI_TOKEN_URL) under the path of the
# password service, for the clients written for bazis-authing < 2.7: remove in 3.0
router.post(
    '/token/',
    response_model=TokenResponse,
    responses={HTTP_401_UNAUTHORIZED: {'model': SchemaErrors}},
    deprecated=True,
)(token_auth)
