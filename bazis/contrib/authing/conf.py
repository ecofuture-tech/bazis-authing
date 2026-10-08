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

from django.utils.translation import gettext_lazy as _

from pydantic import Field

from bazis.core.utils.schemas import BazisSettings


class Settings(BazisSettings):
    BAZIS_AUTH_COOKIE_LIFETIME: int = Field(600, title=_('Authorization cookie lifetime'))
    BAZIS_AUTH_CLAIM_LIFETIME: int = Field(
        60, title=_('Seconds a signed-in authorization store waits for its session to be taken')
    )
    BAZIS_AUTH_COOKIE_SECURE: bool = Field(
        True, title=_('Send the authorization cookie over HTTPS only')
    )
    BAZIS_AUTH_KINDS: list[str] = Field(
        [
            'bazis.contrib.authing.services.password',
        ],
        title=_('Authorization services'),
    )


settings = Settings()
