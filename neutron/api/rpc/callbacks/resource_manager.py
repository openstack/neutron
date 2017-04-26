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
import collections

from neutron_lib.callbacks import exceptions
from oslo_log import log as logging
import six

from neutron.api.rpc.callbacks import exceptions as rpc_exc
from neutron.api.rpc.callbacks import resources

LOG = logging.getLogger(__name__)

# TODO(QoS): split the registry/resources_rpc modules into two separate things:
# one for pull and one for push APIs


def _validate_resource_type(resource_type):
    if not resources.is_valid_resource_type(resource_type):
        raise exceptions.Invalid(element='resource', value=resource_type)


@six.add_metaclass(abc.ABCMeta)
class ResourceCallbacksManager(object):
    """A callback system that allows information providers in a loose manner.
    """

    # This hook is to allow tests to get new objects for the class
    _singleton = True

    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            return super(ResourceCallbacksManager, cls).__new__(cls)

        if not hasattr(cls, '_instance'):
            cls._instance = super(ResourceCallbacksManager, cls).__new__(cls)
        return cls._instance

    @abc.abstractmethod
    def _add_callback(self, callback, resource_type):
        pass

    @abc.abstractmethod
    def _delete_callback(self, callback, resource_type):
        pass

    def register(self, callback, resource_type):
        """Register a callback for a resource type.

        :param callback: the callback. It must raise or return NeutronObject.
        :param resource_type: must be a valid resource type.
        """
        LOG.debug("Registering callback for %s", resource_type)
        _validate_resource_type(resource_type)
        self._add_callback(callback, resource_type)

    def unregister(self, callback, resource_type):
        """Unregister callback from the registry.

        :param callback: the callback.
        :param resource_type: must be a valid resource type.
        """
        LOG.debug("Unregistering callback for %s", resource_type)
        _validate_resource_type(resource_type)
        self._delete_callback(callback, resource_type)

    @abc.abstractmethod
    def clear(self):
        """Brings the manager to a clean state."""

    def get_subscribed_types(self):
        return list(self._callbacks.keys())


class ProducerResourceCallbacksManager(ResourceCallbacksManager):

    _callbacks = dict()

    def _add_callback(self, callback, resource_type):
        if resource_type in self._callbacks:
            raise rpc_exc.CallbacksMaxLimitReached(resource_type=resource_type)
        self._callbacks[resource_type] = callback

    def _delete_callback(self, callback, resource_type):
        try:
            del self._callbacks[resource_type]
        except KeyError:
            raise rpc_exc.CallbackNotFound(resource_type=resource_type)

    def clear(self):
        self._callbacks = dict()

    def get_callback(self, resource_type):
        _validate_resource_type(resource_type)
        try:
            return self._callbacks[resource_type]
        except KeyError:
            raise rpc_exc.CallbackNotFound(resource_type=resource_type)


class ConsumerResourceCallbacksManager(ResourceCallbacksManager):

    _callbacks = collections.defaultdict(set)

    def _add_callback(self, callback, resource_type):
        self._callbacks[resource_type].add(callback)

    def _delete_callback(self, callback, resource_type):
        try:
            self._callbacks[resource_type].remove(callback)
            if not self._callbacks[resource_type]:
                del self._callbacks[resource_type]
        except KeyError:
            raise rpc_exc.CallbackNotFound(resource_type=resource_type)

    def clear(self):
        self._callbacks = collections.defaultdict(set)

    def get_callbacks(self, resource_type):
        """Return the callback if found, None otherwise.

        :param resource_type: must be a valid resource type.
        """
        _validate_resource_type(resource_type)
        callbacks = self._callbacks[resource_type]
        if not callbacks:
            raise rpc_exc.CallbackNotFound(resource_type=resource_type)
        return callbacks
