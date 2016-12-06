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


_ALIAS = 'project-id'


class Project_id(api_extensions.ExtensionDescriptor):
    """Extension that indicates that project_id is enabled.

    This extension indicates that the Keystone V3 'project_id' field
    is supported in the API.
    """

    extensions.register_custom_supported_check(
        _ALIAS, lambda: True, plugin_agnostic=True
    )

    @classmethod
    def get_name(cls):
        return "project_id field enabled"

    @classmethod
    def get_alias(cls):
        return _ALIAS

    @classmethod
    def get_description(cls):
        return "Extension that indicates that project_id field is enabled."

    @classmethod
    def get_updated(cls):
        return "2016-09-09T09:09:09-09:09"

    @classmethod
    def get_resources(cls):
        return []

    def get_extended_resources(self, version):
        return {}
