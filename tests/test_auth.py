import pytest
from bazis_test_utils.utils import get_api_client

from bazis.contrib.users import get_user_model


User = get_user_model()


@pytest.mark.django_db(transaction=True)
def test_password_auth(sample_app):
    user_1 = User.objects.create_user('user1', email='user1@site.com', password='weak_password_2')

    response = get_api_client(sample_app).get('/api/v1/authing/auth/')
    assert response.status_code == 400

    data = response.json()

    assert 'errors' in data
    assert len(data['errors']) == 1

    error = data['errors'][0]
    assert error['status'] == 401
    assert error['code'] == 'UNAUTHORIZED'

    assert error['meta']['actions'] == [
        {
            "code": "password",
            "name": "Login/Password",
            "url": "/api/v1/authing/password/",
            "method": "POST",
        },
    ]

    response = get_api_client(sample_app, error['meta']['token']).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'user1',
            'password': 'weak_password_2',
        },
    )
    assert response.status_code == 200

    data = response.json()

    assert data['user_id'] == str(user_1.id)
    assert data['username'] == 'user1'
    assert data['email'] == 'user1@site.com'

    response = get_api_client(sample_app, error['meta']['token']).post(
        '/api/v1/authing/password/',
        json_data={
            'username': 'user1',
            'password': 'wrong_password',
        },
    )
    assert response.status_code == 400

