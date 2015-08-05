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

import collections

from oslo_log import log as logging

from neutron.api.rpc.callbacks import resources
from neutron.callbacks import exceptions

LOG = logging.getLogger(__name__)


class ResourcesCallbacksManager(object):
    """A callback system that allows information providers in a loose manner.
    """

    def __init__(self):
        self.clear()

    def register(self, callback, resource_type):
        """Register a callback for a resource type.

        Only one callback can be registered for a resource type.

        :param callback: the callback. It must raise or return NeutronObject.
        :param resource_type: must be a valid resource type.
        """
        LOG.debug("register: %(callback)s %(resource_type)s",
                  {'callback': callback, 'resource_type': resource_type})
        if not resources.is_valid_resource_type(resource_type):
            raise exceptions.Invalid(element='resource', value=resource_type)

        self._callbacks[resource_type] = callback

    def unregister(self, resource_type):
        """Unregister callback from the registry.

        :param resource: must be a valid resource type.
        """
        LOG.debug("Unregister: %s", resource_type)
        if not resources.is_valid_resource_type(resource_type):
            raise exceptions.Invalid(element='resource', value=resource_type)
        self._callbacks[resource_type] = None

    def clear(self):
        """Brings the manager to a clean state."""
        self._callbacks = collections.defaultdict(dict)

    def get_callback(self, resource_type):
        """Return the callback if found, None otherwise.

        :param resource_type: must be a valid resource type.
        """
        if not resources.is_valid_resource_type(resource_type):
            raise exceptions.Invalid(element='resource', value=resource_type)

        return self._callbacks[resource_type]
