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

from neutron.api.rpc.callbacks import resource_manager
from neutron.api.rpc.callbacks import resources
from neutron.common import exceptions


# TODO(ajo): consider adding locking
CALLBACK_MANAGER = None


def _get_resources_callback_manager():
    global CALLBACK_MANAGER
    if CALLBACK_MANAGER is None:
        CALLBACK_MANAGER = resource_manager.ResourcesCallbacksManager()
    return CALLBACK_MANAGER


class CallbackReturnedWrongObjectType(exceptions.NeutronException):
    message = _('Callback for %(resource_type)s returned wrong object type')


#resource implementation callback registration functions
def get_info(resource_type, resource_id, **kwargs):
    """Get information about resource type with resource id.

    The function will check the providers for a specific remotable
    resource and get the resource.

    :returns: NeutronObject
    """
    callback = _get_resources_callback_manager().get_callback(resource_type)
    if callback:
        obj = callback(resource_type, resource_id, **kwargs)
        if obj:
            expected_cls = resources.get_resource_cls(resource_type)
            if not isinstance(obj, expected_cls):
                raise CallbackReturnedWrongObjectType(
                    resource_type=resource_type)
        return obj


def register_provider(callback, resource_type):
    _get_resources_callback_manager().register(callback, resource_type)


# resource RPC callback for pub/sub
#Agent side
def subscribe(callback, resource_type, resource_id):
    #TODO(QoS): we have to finish the real update notifications
    raise NotImplementedError("we should finish update notifications")


def unsubscribe(callback, resource_type, resource_id):
    #TODO(QoS): we have to finish the real update notifications
    raise NotImplementedError("we should finish update notifications")


def unsubscribe_all():
    #TODO(QoS): we have to finish the real update notifications
    raise NotImplementedError("we should finish update notifications")


#Server side
def notify(resource_type, event, obj):
    #TODO(QoS): we have to finish the real update notifications
    raise NotImplementedError("we should finish update notifications")


def clear():
    _get_resources_callback_manager().clear()
