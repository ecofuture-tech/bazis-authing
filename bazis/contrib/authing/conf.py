from django.utils.translation import gettext_lazy as _

from pydantic import Field

from bazis.core.utils.schemas import BazisSettings


class Settings(BazisSettings):
    BAZIS_AUTH_COOKIE_LIFETIME: int = Field(600, title=_('Authorization cookie lifetime'))
    BAZIS_AUTH_KINDS: list[str] = Field(
        [
            'bazis.contrib.authing.services.password',
        ],
        title=_('Authorization services'),
    )
    AUTHENTICATION_BACKENDS: list[str] = Field(
        [
            'django.contrib.auth.backends.ModelBackend',
        ],
        title=_('Authentication backends'),
    )


settings = Settings()
