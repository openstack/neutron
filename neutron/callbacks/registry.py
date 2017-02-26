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
import inspect

from neutron.callbacks import manager


# TODO(armax): consider adding locking
CALLBACK_MANAGER = None

# stores a dictionary keyed on function pointers with a list of
# (resource, event) tuples to subscribe to on class initialization
_REGISTERED_CLASS_METHODS = collections.defaultdict(list)


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


def receives(resource, events):
    """Use to decorate methods on classes before initialization.

    Any classes that use this must themselves be decorated with the
    @has_registry_receivers decorator to setup the __new__ method to
    actually register the instance methods after initialization.
    """
    def decorator(f):
        for e in events:
            _REGISTERED_CLASS_METHODS[f].append((resource, e))
        return f
    return decorator


def has_registry_receivers(cls):
    """Decorator to setup __new__ method in classes to subscribe bound methods.

    Any method decorated with @receives above is an unbound method on a class.
    This decorator sets up the class __new__ method to subscribe the bound
    method in the callback registry after object instantiation.
    """
    orig_new = cls.__new__

    def replacement_new(cls, *args, **kwargs):
        instance = orig_new(*args, **kwargs)
        for name, unbound_method in inspect.getmembers(cls):
            if (not inspect.ismethod(unbound_method) and
                    not inspect.isfunction(unbound_method)):
                continue
            # handle py27/py34 difference
            func = getattr(unbound_method, 'im_func', unbound_method)
            if func not in _REGISTERED_CLASS_METHODS:
                continue
            for resource, event in _REGISTERED_CLASS_METHODS[func]:
                # subscribe the bound method
                subscribe(getattr(instance, name), resource, event)
        return instance
    cls.__new__ = classmethod(replacement_new)
    return cls
