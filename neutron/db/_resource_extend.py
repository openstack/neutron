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

"""
NOTE: This module shall not be used by external projects. It will be moved
      to neutron-lib in due course, and then it can be used from there.
"""

import collections
import inspect

from neutron.common import utils

# This dictionary will store methods for extending API resources.
# Extensions can add their own methods by invoking register_funcs().
_resource_extend_functions = {
    # <resource1> : [<func1>, <func2>, ...],
    # <resource2> : [<func1>, <func2>, ...],
    # ...
}

# This dictionary will store @extends decorated methods with a list of
# resources that each method will extend on class initialization.
_DECORATED_EXTEND_METHODS = collections.defaultdict(list)


def register_funcs(resource, funcs):
    """Add functions to extend a resource.

    :param resource: A resource collection name.
    :type resource: str

    :param funcs: A list of functions.
    :type funcs: list of callable

    These functions take a resource dict and a resource object and
    update the resource dict with extension data (possibly retrieved
    from the resource db object).
        def _extend_foo_with_bar(foo_res, foo_db):
            foo_res['bar'] = foo_db.bar_info  # example
            return foo_res

    """
    funcs = [utils.make_weak_ref(f) if callable(f) else f
             for f in funcs]
    _resource_extend_functions.setdefault(resource, []).extend(funcs)


def get_funcs(resource):
    """Retrieve a list of functions extending a resource.

    :param resource: A resource collection name.
    :type resource: str

    :return: A list (possibly empty) of functions extending resource.
    :rtype: list of callable

    """
    return _resource_extend_functions.get(resource, [])


def apply_funcs(resource_type, response, db_object):
    for func in get_funcs(resource_type):
        resolved_func = utils.resolve_ref(func)
        if resolved_func:
            resolved_func(response, db_object)


def extends(resources):
    """Use to decorate methods on classes before initialization.

    Any classes that use this must themselves be decorated with the
    @has_resource_extenders decorator to setup the __new__ method to
    actually register the instance methods after initialization.

    :param resources: Resource collection names. The decorated method will
                      be registered with each resource as an extend function.
    :type resources: list of str

    """
    def decorator(method):
        _DECORATED_EXTEND_METHODS[method].extend(resources)
        return method
    return decorator


def has_resource_extenders(klass):
    """Decorator to setup __new__ method in classes to extend resources.

    Any method decorated with @extends above is an unbound method on a class.
    This decorator sets up the class __new__ method to add the bound
    method to _resource_extend_functions after object instantiation.
    """
    orig_new = klass.__new__
    new_inherited = '__new__' not in klass.__dict__

    @staticmethod
    def replacement_new(cls, *args, **kwargs):
        if new_inherited:
            # class didn't define __new__ so we need to call inherited __new__
            super_new = super(klass, cls).__new__
            if super_new is object.__new__:
                # object.__new__ doesn't accept args nor kwargs
                instance = super_new(cls)
            else:
                instance = super_new(cls, *args, **kwargs)
        else:
            instance = orig_new(cls, *args, **kwargs)
        if getattr(instance, '_DECORATED_METHODS_REGISTERED', False):
            # Avoid running this logic twice for classes inheriting other
            # classes with this same decorator. Only one needs to execute
            # to subscribe all decorated methods.
            return instance
        for name, unbound_method in inspect.getmembers(cls):
            if (not inspect.ismethod(unbound_method) and
                    not inspect.isfunction(unbound_method)):
                continue
            # Handle py27/py34 difference
            method = getattr(unbound_method, 'im_func', unbound_method)
            if method not in _DECORATED_EXTEND_METHODS:
                continue
            for resource in _DECORATED_EXTEND_METHODS[method]:
                # Register the bound method for the resourse
                register_funcs(resource, [method])
        setattr(instance, '_DECORATED_METHODS_REGISTERED', True)
        return instance
    klass.__new__ = replacement_new
    return klass
