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


class Revisionifmatch(api_extensions.ExtensionDescriptor):
    """Indicate that If-Match constraints on revision_number are supported."""

    @classmethod
    def get_name(cls):
        return "If-Match constraints based on revision_number"

    @classmethod
    def get_alias(cls):
        return 'revision-if-match'

    @classmethod
    def get_description(cls):
        return ("Extension indicating that If-Match based on revision_number "
                "is supported.")

    @classmethod
    def get_updated(cls):
        return "2016-12-11T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        return []

    def get_extended_resources(self, version):
        return {}
