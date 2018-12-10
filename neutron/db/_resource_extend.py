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

from neutron_lib.db import resource_extend


_resource_extend_functions = resource_extend._resource_extend_functions
_DECORATED_EXTEND_METHODS = resource_extend._DECORATED_EXTEND_METHODS
register_funcs = resource_extend.register_funcs
get_funcs = resource_extend.get_funcs
apply_funcs = resource_extend.apply_funcs
extends = resource_extend.extends
has_resource_extenders = resource_extend.has_resource_extenders
