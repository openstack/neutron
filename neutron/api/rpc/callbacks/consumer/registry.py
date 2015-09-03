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

from oslo_log import log as logging

from neutron.api.rpc.callbacks import resource_manager


LOG = logging.getLogger(__name__)


#TODO(ajo): consider adding locking to _get_manager, it's
#           safe for eventlet, but not for normal threading.
def _get_manager():
    return resource_manager.ConsumerResourceCallbacksManager()


def subscribe(callback, resource_type):
    _get_manager().register(callback, resource_type)


def unsubscribe(callback, resource_type):
    _get_manager().unregister(callback, resource_type)


def push(resource_type, resource, event_type):
    """Push resource events into all registered callbacks for the type."""

    callbacks = _get_manager().get_callbacks(resource_type)
    for callback in callbacks:
        callback(resource, event_type)


def clear():
    _get_manager().clear()
