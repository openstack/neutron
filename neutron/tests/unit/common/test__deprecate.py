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

import mock
from oslo_utils import importutils

from neutron.tests import base
from neutron.tests.unit.common import moved_globals_target as new_mod


def module_path(code):
    return 'neutron.tests.unit.common.moved_globals_' + code


def import_code(code):
    return importutils.import_module(module_path(code))


def expect_moved(code, name, new_name=None):
    old_path = '.'.join([module_path(code), name])
    new_path = '.'.join([new_mod.__name__, new_name or name])
    message = 'moved to ' + new_path
    return old_path, message


def expect_renamed(code, old_name, new_name):
    old_path = '.'.join([module_path(code), old_name])
    new_path = '.'.join([module_path(code), new_name])
    message = 'renamed to ' + new_path
    return old_path, message


class TestMovedGlobals(base.BaseTestCase):

    def test_moved_global(self):
        code = 'code1'
        old_mod = import_code(code)
        with mock.patch('debtcollector.deprecate') as dc:
            self.assertEqual(new_mod.a, old_mod.a)
            old_path, msg = expect_moved(code, 'a')
            dc.assert_called_once_with(old_path, message=msg, stacklevel=4)

    def test_moved_global_no_attr(self):
        mod = import_code('code1')
        self.assertRaises(AttributeError, lambda: mod.NO_SUCH_ATTRIBUTE)

    def test_renamed_global(self):
        code = 'code1'
        mod = import_code(code)
        with mock.patch('debtcollector.deprecate') as dc:
            self.assertEqual(mod.d, mod.c)
            old_path, msg = expect_renamed(code, 'c', 'd')
            dc.assert_called_once_with(old_path, message=msg, stacklevel=4)

    def test_moved_global_renamed(self):
        code = 'code1'
        old_mod = import_code(code)
        with mock.patch('debtcollector.deprecate') as dc:
            self.assertEqual(new_mod.f, old_mod.e)
            old_path, msg = expect_moved(code, 'e', new_name='f')
            dc.assert_called_once_with(old_path, message=msg, stacklevel=4)

    def test_set_unmoved_global(self):
        mod = import_code('code1')
        mod.d = 'dibatag'
        self.assertEqual('dibatag', mod.d)

    def test_set_new_global(self):
        mod = import_code('code1')
        mod.n = 'nyala'
        self.assertEqual('nyala', mod.n)

    def test_delete_unmoved_global(self):
        mod = import_code('code1')
        self.assertEqual('gelada', mod.g)

        def delete_g():
            del mod.g

        delete_g()
        self.assertRaises(AttributeError, lambda: mod.g)
        self.failUnlessRaises(AttributeError, delete_g)

    def test_not_last_line(self):
        self.assertRaises(SystemExit, import_code, 'code2')
