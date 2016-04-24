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

import debtcollector
import inspect

from neutron._i18n import _


class _DeprecateSubset(object):
    additional = {}

    def __init__(self, my_globals, other_mod):
        self.other_mod = other_mod
        self.my_globals = my_globals

    @classmethod
    def and_also(cls, name, other_mod):
        cls.additional[name] = other_mod

    def __getattr__(self, name):
        a = self.my_globals.get(name)
        if not name.startswith("__") and not inspect.ismodule(a):
            other_mod = self.additional.get(name) or self.other_mod
            if name in vars(other_mod):

                # These should be enabled after most have been cleaned up
                # in neutron proper, which may not happen during the busy M-3.

                debtcollector.deprecate(
                    name,
                    message='moved to %s' % other_mod.__name__,
                    version='mitaka',
                    removal_version='newton',
                    stacklevel=4)

                return vars(other_mod)[name]

        try:
            return self.my_globals[name]
        except KeyError:
            raise AttributeError(
                _("'module' object has no attribute '%s'") % name)

    def __setattr__(self, name, val):
        if name in ('other_mod', 'my_globals'):
            return super(_DeprecateSubset, self).__setattr__(name, val)
        self.my_globals[name] = val

    def __delattr__(self, name):
        if name not in self.my_globals:
            raise AttributeError(
                _("'module' object has no attribute '%s'") % name)
        self.my_globals.pop(name)
