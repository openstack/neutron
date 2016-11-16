# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib.api import extensions as api_extensions

from neutron.api import extensions


_ALIAS = 'sorting'


class Sorting(api_extensions.ExtensionDescriptor):
    """Fake extension that indicates that sorting is enabled."""

    extensions.register_custom_supported_check(
        _ALIAS, lambda: True, plugin_agnostic=True
    )

    @classmethod
    def get_name(cls):
        return "Sorting support"

    @classmethod
    def get_alias(cls):
        return _ALIAS

    @classmethod
    def get_description(cls):
        return "Extension that indicates that sorting is enabled."

    @classmethod
    def get_updated(cls):
        return "2016-06-12T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        return []

    def get_extended_resources(self, version):
        return {}
