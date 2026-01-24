from django.utils.translation import gettext_lazy as _

from pydantic import Field

from bazis.core.utils.schemas import BazisSettings


class Settings(BazisSettings):
    BAZIS_G_AUTH_CLIENT_ID: str = Field('', title=_('Google client ID'), dynamic=True)
    BAZIS_G_AUTH_CLIENT_SECRET: str = Field('', title=_('Google client secret'), dynamic=True)
    BAZIS_G_AUTH_REDIRECT_URI: str = Field('', title=_('Google redirect URI'), dynamic=True)


settings = Settings()
