# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import debtcollector
import inspect
import os

from neutron._i18n import _


class _DeprecateSubset(object):
    def __init__(self, my_globals, other_mod):
        self.other_mod = other_mod
        self.my_globals = copy.copy(my_globals)

    def __getattr__(self, name):
        a = self.my_globals.get(name)
        if (not name.startswith("__") and not inspect.ismodule(a) and
            name in vars(self.other_mod)):

            # These should be enabled after most have been cleaned up
            # in neutron proper, which may not happen during the busy M-3.

            if os.getenv('NEUTRON_SHOW_DEPRECATION_WARNINGS'):
                debtcollector.deprecate(
                    name,
                    message='moved to neutron_lib',
                    version='mitaka',
                    removal_version='newton',
                    stacklevel=4)

            return vars(self.other_mod)[name]

        try:
            return self.my_globals[name]
        except KeyError:
            raise AttributeError(
                _("'module' object has no attribute '%s'") % name)
