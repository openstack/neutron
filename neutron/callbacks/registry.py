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

from neutron.callbacks import manager


# TODO(armax): consider adding locking
CALLBACK_MANAGER = None


def _get_callback_manager():
    global CALLBACK_MANAGER
    if CALLBACK_MANAGER is None:
        CALLBACK_MANAGER = manager.CallbacksManager()
    return CALLBACK_MANAGER


def subscribe(callback, resource, event):
    _get_callback_manager().subscribe(callback, resource, event)


def unsubscribe(callback, resource, event):
    _get_callback_manager().unsubscribe(callback, resource, event)


def unsubscribe_by_resource(callback, resource):
    _get_callback_manager().unsubscribe_by_resource(callback, resource)


def unsubscribe_all(callback):
    _get_callback_manager().unsubscribe_all(callback)


def notify(resource, event, trigger, **kwargs):
    _get_callback_manager().notify(resource, event, trigger, **kwargs)


def clear():
    _get_callback_manager().clear()
