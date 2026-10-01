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

"""
Django system checks of bazis-authing (see `manage.py bazis_doctor`).
"""

from importlib import import_module

from django.conf import settings
from django.core.checks import Error, Warning, register

from starlette.routing import NoMatchFound


def auth_services() -> tuple[list, list[str]]:
    """
    The modules of BAZIS_AUTH_KINDS that import, and the names of those that do not.
    """
    services, missing = [], []
    # the settings of the package are missing if BS_BAZIS_APPS does not list it
    for path in getattr(settings, 'BAZIS_AUTH_KINDS', []):
        try:
            services.append(import_module(path))
        except ImportError:
            missing.append(path)
    return services, missing


@register()
def check_auth_kinds(app_configs, **kwargs):
    """
    `GET /auth/` silently skips the modules of BAZIS_AUTH_KINDS that do not import, so a
    misspelled service offers no login.
    """
    return [
        Warning(
            f'The authorization service {path!r} of BAZIS_AUTH_KINDS cannot be imported.',
            hint=(
                'List the service modules, e.g. bazis.contrib.authing.services.password, '
                'bazis.contrib.authing.services.google.'
            ),
            id='authing.W001',
        )
        for path in auth_services()[1]
    ]


@register()
def check_auth_routes(app_configs, **kwargs):
    """
    `GET /auth/` builds the login action of every service of BAZIS_AUTH_KINDS from the
    route of the service: if its router is not registered, the endpoint fails for every
    anonymous user. Runs when the application is loaded (`manage.py bazis_doctor`).
    """
    from bazis.core.introspect import loaded_app

    if loaded_app() is None:
        return []

    messages = []
    for service in auth_services()[0]:
        if not hasattr(service, 'get_login_action'):
            continue
        try:
            service.get_login_action()
        except NoMatchFound:
            messages.append(
                Error(
                    f'The route of the authorization service {service.__name__} is not '
                    'registered, so GET /auth/ fails.',
                    hint=f'Register {service.__name__}.router in the router of the project.',
                    id='authing.E001',
                )
            )
    return messages
