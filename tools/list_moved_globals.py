#!/usr/bin/env python
#
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
Check for globals that are now available in neutron-lib
"""

from __future__ import print_function

from neutron_lib import constants as lconst
from neutron_lib import exceptions as lexc

from neutron.common import constants as nconst
from neutron.common import exceptions as nexc


def check_globals(things, nmod, lmod):
    core = vars(nmod)['_mg__my_globals']
    lib = vars(lmod)
    moved_things = []
    for thing in core:
        if thing.startswith('__') or thing == '_':
            continue
        if thing in lib:
            moved_things.append(thing)
    if moved_things:
        print("\nThese %s have moved to neutron-lib:" % things)
        for moved_thing in sorted(moved_things):
            print("    %s" % moved_thing)


def main():
    check_globals('constants', nconst, lconst)
    check_globals('exceptions', nexc, lexc)


if __name__ == '__main__':
    main()
