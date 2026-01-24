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
    BAZIS_G_AUTH_CLIENT_ID: str = Field('', title=_('Google client ID'), dynamic=True)
    BAZIS_G_AUTH_CLIENT_SECRET: str = Field('', title=_('Google client secret'), dynamic=True)
    BAZIS_G_AUTH_REDIRECT_URI: str = Field('', title=_('Google redirect URI'), dynamic=True)


settings = Settings()
