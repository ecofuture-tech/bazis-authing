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

from bazis.contrib.authing.conf import Settings


def test_conf_does_not_declare_django_settings():
    """
    The conf modules of all installed Bazis packages are loaded in every project, so
    bazis-authing must not declare Django settings (the core declares
    AUTHENTICATION_BACKENDS).
    """
    assert 'AUTHENTICATION_BACKENDS' not in Settings.model_fields
    assert 'BAZIS_AUTH_KINDS' in Settings.model_fields
