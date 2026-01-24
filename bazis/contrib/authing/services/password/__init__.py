from django.utils.translation import gettext_lazy as _


AUTH_CODE = 'password'


def get_login_action():
    from bazis.core.app import app

    return {
        'code': AUTH_CODE,
        'name': _('Login/Password'),
        'url': app.router.url_path_for('password_auth'),
        'method': 'POST',
    }
