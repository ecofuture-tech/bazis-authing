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

from django.utils.translation import gettext as _

from fastapi import Depends, Request, Response

from starlette.status import (
    HTTP_100_CONTINUE,
    HTTP_204_NO_CONTENT,
    HTTP_401_UNAUTHORIZED,
    HTTP_422_UNPROCESSABLE_CONTENT,
)

from asgiref.sync import async_to_sync

from bazis.contrib.users import get_user_model
from bazis.contrib.users.service import (
    RequestTokens,
    get_request_tokens,
    get_user_from_token,
    get_user_optional,
    session_token_data,
)
from bazis.core.errors import JsonApi401Exception, JsonApiBazisError, JsonApiBazisException
from bazis.core.routing import BazisRouter

from .schemas import AuthResponse
from .service import AuthStore, auth_services


User = get_user_model()

router = BazisRouter(tags=[_('Authentication')])


def get_token_data_lenient(tokens: RequestTokens = Depends(get_request_tokens)) -> dict:
    """
    The token data for the authorization endpoint: an expired or invalid token (e.g. signed
    with a previous SECRET_KEY) means that the user is not authorized, so that the client
    receives the login actions and a new store token instead of 401.
    """
    try:
        return session_token_data(tokens.token)
    except JsonApi401Exception:
        return {}


def get_user_lenient(token_data: dict = Depends(get_token_data_lenient)):
    return get_user_optional(get_user_from_token(token_data))


@router.get('/auth/', response_model=AuthResponse)
def auth(
    request: Request,
    response: Response,
    auth_store: AuthStore = Depends(),
    user: User = Depends(get_user_lenient),
    token_data: dict = Depends(get_token_data_lenient),
):
    auth_type = token_data.get('auth_type')
    if user.is_anonymous:
        # the session of a signed-in store is given once: the store is spent
        if user_id := auth_store.claim():
            auth_type = auth_store.auth_type
            user = User.objects.filter(id=user_id, is_active=True).first()
            if user is None:
                auth_store.renew()
            elif auth_store.store_in_cookie:
                AuthStore.response_delete_cookie(response)

    services = auth_services()[0]

    if user and not user.is_anonymous:
        return AuthResponse(
            user_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            token=user.jwt_build(auth_type=auth_type),
            logout_actions=next(
                (
                    s.get_logout_actions()
                    for s in services
                    if s.AUTH_CODE == auth_type and hasattr(s, 'get_logout_actions')
                ),
                None,
            ),
        )

    errors = [
        JsonApiBazisError(
            _('User is not authorized.'),
            status=HTTP_401_UNAUTHORIZED,
            code='UNAUTHORIZED',
            title=_('User is not authorized.'),
            meta_data={
                'actions': [
                    s.get_login_action() for s in services if hasattr(s, 'get_login_action')
                ],
                'token': auth_store.token.value,
            },
        )
    ]

    if auth_store.actions:
        errors.append(
            JsonApiBazisError(
                auth_store.actions.name,
                status=HTTP_100_CONTINUE,
                code=auth_store.actions.code,
                title=_('Next action'),
                meta_data={
                    'actions': auth_store.actions.values,
                },
            )
        )

    if auth_store.errors:
        for err in auth_store.errors:
            errors.append(
                JsonApiBazisError(
                    err.detail,
                    status=HTTP_422_UNPROCESSABLE_CONTENT,
                    code=err.code,
                    title=_('Authentication error'),
                )
            )

    # the error answer of the application, with the attributes of the store cookie, which
    # the cookies of JsonApiBazisException do not have
    handler = request.app.exception_handlers[JsonApiBazisException]
    return auth_store.response_set_cookie(
        async_to_sync(handler)(request, JsonApiBazisException(errors))
    )


@router.post('/logout/', status_code=HTTP_204_NO_CONTENT, response_class=Response)
def auth_logout(tokens: RequestTokens = Depends(get_request_tokens)):
    """
    Deletes the authorization stores of the request (bearer token, cookie or query
    parameter) and the cookie `BAZIS_AUTH_COOKIE_NAME`. Idempotent. A session token is
    stateless: the client drops it.
    """
    for value in (tokens.param, tokens.header, tokens.cookie):
        AuthStore.discard(value)
    return AuthStore.response_delete_cookie(Response(status_code=HTTP_204_NO_CONTENT))
