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

import os
import sys

from neutron.tests import base
from neutron.tests import tools
from neutron.tests.unit import tests  # noqa


EXAMPLE_MODULE = 'neutron.tests.unit.tests.example.dir.example_module'


class ImportModulesRecursivelyTestCase(base.BaseTestCase):

    def test_object_modules(self):
        sys.modules.pop(EXAMPLE_MODULE, None)
        modules = tools.import_modules_recursively(
            os.path.dirname(tests.__file__))
        self.assertIn(
            'neutron.tests.unit.tests.example.dir.example_module',
            modules)
        self.assertIn(EXAMPLE_MODULE, sys.modules)
