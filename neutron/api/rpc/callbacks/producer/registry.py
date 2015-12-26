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

from neutron.api.rpc.callbacks import exceptions
from neutron.api.rpc.callbacks import resource_manager
from neutron.objects import base


# TODO(ajo): consider adding locking: it's safe for eventlet but not
#            for other types of threading.
def _get_manager():
    return resource_manager.ProducerResourceCallbacksManager()


def provide(callback, resource_type):
    """Register a callback as a producer for the resource type.

    This callback will be used to produce resources of corresponding type for
    interested parties.
    """
    _get_manager().register(callback, resource_type)


def unprovide(callback, resource_type):
    """Unregister a callback for corresponding resource type."""
    _get_manager().unregister(callback, resource_type)


def clear():
    """Clear all callbacks."""
    _get_manager().clear()


def pull(resource_type, resource_id, **kwargs):
    """Get resource object that corresponds to resource id.

    The function will return an object that is provided by resource producer.

    :returns: NeutronObject
    """
    callback = _get_manager().get_callback(resource_type)
    obj = callback(resource_type, resource_id, **kwargs)
    if obj:
        if (not isinstance(obj, base.NeutronObject) or
            resource_type != obj.obj_name()):
            raise exceptions.CallbackWrongResourceType(
                resource_type=resource_type)
    return obj
