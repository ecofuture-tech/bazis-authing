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

from django.conf import settings
from django.utils.translation import gettext as _

from fastapi import Depends

from starlette.status import HTTP_100_CONTINUE, HTTP_401_UNAUTHORIZED, HTTP_422_UNPROCESSABLE_ENTITY

from bazis.contrib.users import get_user_model
from bazis.contrib.users.service import get_token_data, get_user_optional
from bazis.core.errors import JsonApiBazisError, JsonApiBazisException
from bazis.core.routing import BazisRouter
from bazis.core.utils.imp import import_module

from .schemas import AuthResponse
from .service import AuthStore


User = get_user_model()

router = BazisRouter(tags=[_('Authentication')])


@router.get('/auth/', response_model=AuthResponse)
def auth(
    auth_store: AuthStore = Depends(),
    user: User = Depends(get_user_optional),
    token_data: dict = Depends(get_token_data),
):
    if user.is_anonymous:
        if user_id := auth_store.user_id:
            user = User.objects.filter(id=user_id).first()

    services = []
    for service_path in settings.BAZIS_AUTH_KINDS:
        try:
            services.append(import_module(service_path))
        except ImportError:
            pass

    if user and not user.is_anonymous:
        auth_type = auth_store.auth_type or token_data.get('auth_type')

        return AuthResponse(
            user_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            token=user.jwt_build(auth_type=auth_type),
            logout_actions=(
                [
                    s.get_logout_actions()
                    for s in services
                    if s.AUTH_CODE == auth_type and hasattr(s, 'get_logout_actions')
                ]
                + [None]
            )[0],
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
                    status=HTTP_422_UNPROCESSABLE_ENTITY,
                    code=err.code,
                    title=_('Authentication error'),
                )
            )

    raise JsonApiBazisException(errors, cookies=[auth_store.cookie])
