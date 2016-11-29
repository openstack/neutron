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

import debtcollector

from neutron.api.rpc.callbacks import resource_manager


#TODO(ajo): consider adding locking to _get_manager, it's
#           safe for eventlet, but not for normal threading.
def _get_manager():
    return resource_manager.ConsumerResourceCallbacksManager()


@debtcollector.removals.remove(
    message="This will be removed in the future. Please register callbacks "
            "using the 'register' method in this model and adjust the "
            "callback to accept the context and resource type as arguments.",
    version="Ocata"
)
def subscribe(callback, resource_type):
    # temporary hack to differentiate between callback types until the
    # 'subscribe' method is removed
    callback.__dict__['_ACCEPTS_CONTEXT'] = False
    _get_manager().register(callback, resource_type)


def register(callback, resource_type):
    # TODO(kevinbenton): remove this on debt collection
    callback.__dict__['_ACCEPTS_CONTEXT'] = True
    _get_manager().register(callback, resource_type)


def unsubscribe(callback, resource_type):
    _get_manager().unregister(callback, resource_type)


def push(context, resource_type, resource_list, event_type):
    """Push resource list into all registered callbacks for the event type."""

    callbacks = _get_manager().get_callbacks(resource_type)
    for callback in callbacks:
        if callback._ACCEPTS_CONTEXT:
            callback(context, resource_type, resource_list, event_type)
        else:
            # backwards compat for callback listeners that don't take
            # context and resource_type
            callback(resource_list, event_type)


def clear():
    _get_manager().clear()
