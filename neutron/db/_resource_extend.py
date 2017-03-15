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

from neutron.common import utils

# This dictionary will store methods for extending API resources.
# Extensions can add their own methods by invoking register_funcs().
_resource_extend_functions = {
    # <resource1> : [<func1>, <func2>, ...],
    # <resource2> : [<func1>, <func2>, ...],
    # ...
}


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
