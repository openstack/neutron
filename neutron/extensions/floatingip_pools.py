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

import abc
import itertools

from neutron_lib.api.definitions import floatingip_pools as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants
import six

from neutron.api.v2 import resource_helper


class Floatingip_pools(api_extensions.APIExtensionDescriptor):
    """Neutron floating IP pool api extension."""

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, itertools.chain(apidef.RESOURCE_ATTRIBUTE_MAP))

        resources = resource_helper.build_resource_info(
                                                plural_mappings,
                                                apidef.RESOURCE_ATTRIBUTE_MAP,
                                                constants.L3,
                                                translate_name=True,
                                                allow_bulk=True)

        return resources


@six.add_metaclass(abc.ABCMeta)
class FloatingIPPoolPluginBase(object):

    @abc.abstractmethod
    def get_floatingip_pools(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        """List all floating ip pools."""
        pass
