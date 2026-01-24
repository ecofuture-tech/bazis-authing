from django.utils.translation import gettext_lazy as _


AUTH_CODE = 'google'


def get_login_action():
    from bazis.core.app import app

    return {
        'code': AUTH_CODE,
        'name': _('Google Authentication'),
        'url': app.router.url_path_for('google_auth_init'),
        'method': 'GET',
    }
