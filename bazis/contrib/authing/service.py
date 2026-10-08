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
from fastapi.responses import RedirectResponse
from fastapi.security.utils import get_authorization_scheme_param

from starlette.requests import Request
from starlette.status import HTTP_303_SEE_OTHER

import jwt

from bazis.contrib.users.service import get_anonymous_user_model, get_user_model
from bazis.core.errors import JsonApi401Exception
from bazis.core.utils.functools import CtxToggle


LOG = logging.getLogger(__name__)
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
                data,
                settings.SECRET_KEY,
                algorithms=[settings.BAZIS_JWT_SESSION_ALG],
                options={'require': ['sub']},
            )
        except jwt.InvalidTokenError:
            token_data = None

        # a token with an expiration is a session token of bazis-users, not a store token
        if token_data is None or 'exp' in token_data:
            if required:
                raise JsonApi401Exception(detail='Token is invalid')
            # e.g. a cookie signed with a previous SECRET_KEY: a new store replaces it
            return None

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
    """
    The authorization store of a sign-in: its token (`AuthToken`) is given to the client,
    its data lives in the default cache. A store is single-use: `claim()` deletes the store
    that gives a session, so that its token, which travels in URLs, gives no other one.
    """

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
        # the cookie holds a store token (not a session token): dropped once it is spent
        self.store_in_cookie = AuthToken.parse(token_cookie) is not None
        self.token = AuthToken.parse(
            token_param or token_header or token_cookie, required=self.token_required
        )

        if self.token:
            self.data = cache.get(self.cache_key)
            if self.data is None:
                if self.token_required:
                    raise JsonApi401Exception(detail='Token has been expired')
                else:
                    self.token = None

        if not self.token:
            self.renew()

    @property
    def cache_key(self):
        return f'{self.cache_prefix}{self.token.key}'

    @property
    def lifetime(self) -> int:
        """
        Seconds the store lives: a signed-in store only waits for its session to be taken.
        """
        if self.user_id is None:
            return settings.BAZIS_AUTH_COOKIE_LIFETIME
        return settings.BAZIS_AUTH_CLAIM_LIFETIME

    @property
    def as_param(self):
        """
        Deprecated: the store token in a query string ends up in access logs. Kept for own
        services written for bazis-authing < 2.6 (use `redirect_to_auth()`); remove in 3.0.
        """
        return f'{settings.BAZIS_AUTH_COOKIE_NAME}={self.token.value}'

    @staticmethod
    def _cookie_attributes() -> dict:
        return {
            'path': '/',
            'httponly': True,
            'secure': settings.BAZIS_AUTH_COOKIE_SECURE,
            'samesite': 'lax',
        }

    def response_set_cookie(self, response):
        """Sets the store token as the cookie, for as long as the store lives."""
        response.set_cookie(
            key=settings.BAZIS_AUTH_COOKIE_NAME,
            value=self.token.value,
            max_age=self.lifetime,
            **self._cookie_attributes(),
        )
        return response

    @classmethod
    def response_delete_cookie(cls, response):
        response.delete_cookie(key=settings.BAZIS_AUTH_COOKIE_NAME, **cls._cookie_attributes())
        return response

    def redirect_to_auth(self):
        """
        The answer of a login: 303 to the auth endpoint, without the store token in the URL
        (the client follows it with the same bearer token or the cookie, which is set).
        """
        from bazis.core.app import app

        return self.response_set_cookie(
            RedirectResponse(app.router.url_path_for('auth'), status_code=HTTP_303_SEE_OTHER)
        )

    def renew(self):
        """Replaces the store with a new empty one."""
        self.token = AuthToken.new()
        self.data_reset()

    def claim(self):
        """
        The id of the signed-in user of the store, once: the store is deleted. The deletion
        in the cache is atomic, so of concurrent requests only one gets the id; the others
        get None and a new store.
        """
        if (user_id := self.user_id) is None:
            return None
        if cache.delete(self.cache_key):
            return user_id
        self.renew()
        return None

    @classmethod
    def discard(cls, token_value: str | None):
        """Deletes the store of the token, if it is a store token."""
        if token := AuthToken.parse(token_value):
            cache.delete(f'{cls.cache_prefix}{token.key}')

    def _push_data(self):
        if self.push_toggle.allow:
            cache.set(self.cache_key, self.data, self.lifetime)

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
        errors = self.data.get('_errors', [])
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
