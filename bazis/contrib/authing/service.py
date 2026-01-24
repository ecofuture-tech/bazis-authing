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
from collections import UserDict
from dataclasses import asdict, dataclass
from secrets import token_hex

from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.core.cache import cache
from django.utils.functional import cached_property

from fastapi import Cookie, Depends, Header, Query
from fastapi.security.utils import get_authorization_scheme_param

from starlette.requests import Request

from jose import jwt

from bazis.contrib.users.service import get_anonymous_user_model, get_user_model
from bazis.core.errors import JsonApi401Exception
from bazis.core.utils.functools import CtxToggle


LOG = logging.getLogger()
User = get_user_model()
AnonymousUser = get_anonymous_user_model()


@dataclass
class AuthToken:
    key: str = None

    @classmethod
    def parse(cls, data, required=False):
        if not data:
            if required:
                raise JsonApi401Exception(detail='Token required')
            return None

        try:
            token_data = jwt.decode(
                data, settings.SECRET_KEY, algorithms=settings.BAZIS_JWT_SESSION_ALG
            )
        except Exception:
            raise JsonApi401Exception(detail='Token is invalid') from None

        return cls(
            key=token_data['sub'],
        )

    @classmethod
    def new(cls):
        return cls(
            key=token_hex(),
        )

    @cached_property
    def value(self):
        return jwt.encode(
            {
                'sub': self.key,
            },
            settings.SECRET_KEY,
            algorithm=settings.BAZIS_JWT_SESSION_ALG,
        )


@dataclass
class AuthActions:
    values: list
    code: str
    name: str


@dataclass
class AuthError:
    code: str
    detail: str


def get_token_header(authorization: str | None = Header(default=None, alias='Authorization')):
    scheme, param = get_authorization_scheme_param(authorization)
    if authorization and scheme.lower() == 'bearer':
        return param


class AuthStore(UserDict):
    token = None
    cache_prefix = 'auth_store_'
    token_required = False

    def __init__(
        self,
        token_param: str | None = Query(default=None, alias=settings.BAZIS_AUTH_COOKIE_NAME),
        token_cookie: str | None = Cookie(default=None, alias=settings.BAZIS_AUTH_COOKIE_NAME),
        token_header: str | None = Depends(get_token_header),
    ):
        super().__init__()
        self.push_toggle = CtxToggle()
        self.token = AuthToken.parse(
            token_param or token_header or token_cookie, required=self.token_required
        )

        if self.token:
            self.data = cache.get(f'{self.cache_prefix}{self.token.key}')
            if self.data is None:
                if self.token_required:
                    raise JsonApi401Exception(detail='Token has been expired')
                else:
                    self.token = None

        if not self.token:
            self.token = AuthToken.new()
            self.data_reset()

    @cached_property
    def cookie(self):
        # the authorization cookie is set indefinitely
        return settings.BAZIS_AUTH_COOKIE_NAME, self.token.value, 31536000

    @cached_property
    def as_param(self):
        return f'{settings.BAZIS_AUTH_COOKIE_NAME}={self.token.value}'

    def response_set_cookie(self, response):
        key, value, max_age = self.cookie
        # set the cookie
        response.set_cookie(key=key, value=value, max_age=max_age)
        return response

    def _push_data(self):
        if self.push_toggle.allow:
            cache.set(
                f'{self.cache_prefix}{self.token.key}',
                self.data,
                settings.BAZIS_AUTH_COOKIE_LIFETIME,
            )

    def data_reset(self):
        self.data = {}
        self._push_data()

    def __setitem__(self, k, v) -> None:
        super().__setitem__(k, v)
        self._push_data()

    def update(self, d, **kwargs) -> None:
        with self.push_toggle:
            super().update(d, **kwargs)
        self._push_data()

    def __delitem__(self, v) -> None:
        super().__delitem__(v)
        self._push_data()

    def clear(self) -> None:
        with self.push_toggle:
            super().clear()
        self._push_data()

    def login(self, user, request: Request, auth_type: str):
        user_logged_in.send(sender=user.__class__, request=request, user=user)
        self.data['_user_id'] = user.id
        self.data['_auth_type'] = auth_type
        self._push_data()

    @property
    def user_id(self):
        return self.data.get('_user_id')

    @property
    def auth_type(self):
        return self.data.get('_auth_type')

    @property
    def errors(self) -> list[AuthError]:
        if errors := self.data.get('_errors'):
            return [AuthError(**err) for err in errors]

    def set_error(self, code, detail=None):
        LOG.info('AuthStore set_error: %s, %s', code, detail)
        err = AuthError(code, detail)
        errors = self.data.get('errors', [])
        errors.append(asdict(err))
        self.data['_errors'] = errors
        self._push_data()

    @property
    def actions(self) -> AuthActions:
        if actions := self.data.get('_actions'):
            return AuthActions(**actions)

    def set_actions(self, values: list, code: str, name: str = None):
        self.data['_actions'] = asdict(AuthActions(values, code, name))
        self._push_data()


class AuthStoreTokenRequired(AuthStore):
    token_required = True
