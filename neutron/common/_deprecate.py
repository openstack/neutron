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

"""
Provide a deprecation method for globals.

NOTE: This module may be a candidate for adoption by debtcollector.
"""

import inspect
import sys

import debtcollector

from neutron._i18n import _


class _MovedGlobals(object):
    """Override a module to deprecate moved globals.

    This class is used when globals (attributes of a module) need to be
    marked as deprecated. It can be used in either or both of two ways:

     1. By specifying a default new module, all accesses to a global in
        the source module will emit a warning if the global does not exist
        in the source module and it does exist in the new module. This way
        is intended to be used when many globals are moved from one module
        to another.

     2. By explicitly deprecating individual globals with the _moved_global()
        function, see below.

    This class must be called from the last line in a module, as follows:
    ``_deprecate._MovedGlobals(default_new_module)``
    or
    ``_deprecate._MovedGlobals()``

    Args:
        :param default_new_module: The default new location for moved globals
        :type default_new_module: module or None

    Attributes:
        :ivar _mg__my_globals: The current vars() of the source module
        :type _mg__my_globals: dict

        :ivar _mg__default_new_mod: The default location for moved globals
        :type _mg__default_new_mod: module or None

        :ivar _mg__old_ref: The original reference to the source module
        :type _mg__old_ref: module

        :cvar _mg__moves: Moves (and renames) not involving default_new_module
        :type _mg__moves: dict

        NOTE: An instance of _MovedGlobals overrides the module it is called
         from, so instance and class variables appear in the module namespace.
         To prevent collisions with existing globals, the instance and class
         variable names here are prefixed with ``_mg__``.

    """
    # Here we store individual moves and renames. This is a dict where
    #   key = (old_module, old_name)
    #   value = (new_module, new_name)
    # If new_module is the same as old_module then it is a rename in place.
    _mg__moves = {}

    def __init__(self, default_new_module=None):

        # To avoid infinite recursion at inspect.getsourcelines() below we
        # must initialize self._mg__my_globals early here.
        self._mg__my_globals = {}

        self._mg__default_new_mod = default_new_module

        caller_frame = inspect.stack()[1][0]
        caller_line = inspect.getframeinfo(caller_frame).lineno
        source_module = inspect.getmodule(caller_frame)
        src_mod_last_line = len(inspect.getsourcelines(source_module)[0])
        if caller_line < src_mod_last_line:
            raise SystemExit(_("_MovedGlobals() not called from last "
                               "line in %s") % source_module.__file__)
        self._mg__my_globals = vars(source_module)

        # When we return from here we override the sys.modules[] entry
        # for the source module with this instance. We must keep a
        # reference to the original module to prevent it from being
        # garbage collected.
        self._mg__old_ref = source_module
        sys.modules[source_module.__name__] = self

    def __getattr__(self, name):
        value = self._mg__my_globals.get(name)
        if not name.startswith("__") and not inspect.ismodule(value):
            old_module = self._mg__old_ref
            specified_move = self._mg__moves.get((old_module, name))
            if specified_move:
                new_module, new_name = specified_move
            else:
                new_module, new_name = self._mg__default_new_mod, name
            if new_module and new_name in vars(new_module):

                old_location = '%s.%s' % (old_module.__name__, name)
                new_location = '%s.%s' % (new_module.__name__, new_name)
                changed = 'renamed' if old_module == new_module else 'moved'
                debtcollector.deprecate(
                    old_location,
                    message='%s to %s' % (changed, new_location),
                    stacklevel=4)

                return vars(new_module)[new_name]

        try:
            return self._mg__my_globals[name]
        except KeyError:
            raise AttributeError(
                _("'module' object has no attribute '%s'") % name)

    def __setattr__(self, name, val):
        if name.startswith('_mg__'):
            return super(_MovedGlobals, self).__setattr__(name, val)
        self._mg__my_globals[name] = val

    def __delattr__(self, name):
        if name not in self._mg__my_globals:
            raise AttributeError(
                _("'module' object has no attribute '%s'") % name)
        self._mg__my_globals.pop(name)


def _moved_global(old_name, new_module=None, new_name=None):
    """Deprecate a single attribute in a module.

    This function is used to move an attribute to a module that differs
    from _mg__default_new_mod in _MovedGlobals. It also handles renames.

    NOTE: This function has no effect if _MovedGlobals() is not called
    at the end of the module containing the attribute.
     [TODO(HenryG): Figure out a way of asserting on this.]

    :param old_name: The name of the attribute that was moved/renamed.
    :type old_name: str

    :param new_module: The new module where the attribute is now.
    :type new_module: module

    :param new_name: The new name of the attribute.
    :type new_name: str

    """
    if not (new_module or new_name):
        raise AssertionError(_("'new_module' and 'new_name' "
                               "must not be both None"))
    if isinstance(new_module, _MovedGlobals):
        # The new module has been shimmed, get the original
        new_module = new_module._mg__old_ref
    old_module = inspect.getmodule(inspect.stack()[1][0])  # caller's module
    new_module = new_module or old_module
    new_name = new_name or old_name
    _MovedGlobals._mg__moves[(old_module, old_name)] = (new_module, new_name)
