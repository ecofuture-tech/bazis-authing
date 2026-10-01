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

import pytest

from bazis.contrib.authing.checks import check_auth_kinds, check_auth_routes
from bazis.core.introspect import validate_manifest


def test_manifest_is_valid():
    assert validate_manifest('bazis.contrib.authing') == []


def test_auth_kinds_check(settings):
    assert check_auth_kinds(None) == []
    settings.BAZIS_AUTH_KINDS = ['bazis.contrib.authing.password']
    assert [it.id for it in check_auth_kinds(None)] == ['authing.W001']


@pytest.mark.django_db
def test_auth_routes_check(sample_app, settings):
    # the sample registers the password router, not the Google one
    assert check_auth_routes(None) == []
    settings.BAZIS_AUTH_KINDS = [
        'bazis.contrib.authing.services.password',
        'bazis.contrib.authing.services.google',
    ]
    assert [it.id for it in check_auth_routes(None)] == ['authing.E001']
