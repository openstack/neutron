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

    def register(self, callback, resource):
        """register callback for a resource .

        One callback can be register to a resource

        :param callback: the callback. It must raise or return a dict.
        :param resource: the resource. It must be a valid resource.
        """
        LOG.debug("register: %(callback)s %(resource)s",
                  {'callback': callback, 'resource': resource})
        if resource not in resources.VALID:
            raise exceptions.Invalid(element='resource', value=resource)

        self._callbacks[resource] = callback

    def unregister(self, resource):
        """Unregister callback from the registry.

        :param callback: the callback.
        :param resource: the resource.
        """
        LOG.debug("Unregister: %(resource)s",
                  {'resource': resource})
        if resource not in resources.VALID:
            raise exceptions.Invalid(element='resource', value=resource)
        self._callbacks[resource] = None

    def clear(self):
        """Brings the manager to a clean slate."""
        self._callbacks = collections.defaultdict(dict)

    def get_callback(self, resource):
        """Return the callback if found, None otherwise.

        :param resource: the resource. It must be a valid resource.
        """
        if resource not in resources.VALID:
            raise exceptions.Invalid(element='resource', value=resource)

        return self._callbacks[resource]
