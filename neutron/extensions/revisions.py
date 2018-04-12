#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.api import extensions

from neutron.extensions import stdattrs_common


REVISION = 'revision_number'
REVISION_BODY = {
    REVISION: {'allow_post': False, 'allow_put': False,
               'is_visible': True, 'default': None, 'is_filter': True},
}


class Revisions(extensions.ExtensionDescriptor):
    """Extension to expose revision number of standard attr resources."""

    @classmethod
    def get_name(cls):
        return "Resource revision numbers"

    @classmethod
    def get_alias(cls):
        return "standard-attr-revisions"

    @classmethod
    def get_description(cls):
        return ("This extension will display the revision number of neutron "
                "resources.")

    @classmethod
    def get_updated(cls):
        return "2016-04-11T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version != "2.0":
            return {}
        return stdattrs_common.stdattrs_extended_resources(REVISION_BODY)
