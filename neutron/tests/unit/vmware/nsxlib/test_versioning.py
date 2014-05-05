# Copyright (c) 2014 VMware, Inc.
#
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
#

from neutron.plugins.vmware.api_client import exception
from neutron.plugins.vmware.api_client import version as version_module
from neutron.plugins.vmware.nsxlib import router as routerlib
from neutron.plugins.vmware.nsxlib import versioning
from neutron.tests import base


class TestVersioning(base.BaseTestCase):

    def test_function_handling_missing_minor(self):
        version = version_module.Version('2.0')
        function = versioning.get_function_by_version(
            routerlib.ROUTER_FUNC_DICT, 'create_lrouter', version)
        self.assertEqual(routerlib.create_implicit_routing_lrouter,
                         function)

    def test_function_handling_with_both_major_and_minor(self):
        version = version_module.Version('3.2')
        function = versioning.get_function_by_version(
            routerlib.ROUTER_FUNC_DICT, 'create_lrouter', version)
        self.assertEqual(routerlib.create_explicit_routing_lrouter,
                         function)

    def test_function_handling_with_newer_major(self):
        version = version_module.Version('5.2')
        function = versioning.get_function_by_version(
            routerlib.ROUTER_FUNC_DICT, 'create_lrouter', version)
        self.assertEqual(routerlib.create_explicit_routing_lrouter,
                         function)

    def test_function_handling_with_obsolete_major(self):
        version = version_module.Version('1.2')
        self.assertRaises(NotImplementedError,
                          versioning.get_function_by_version,
                          routerlib.ROUTER_FUNC_DICT,
                          'create_lrouter', version)

    def test_function_handling_with_unknown_version(self):
        self.assertRaises(exception.ServiceUnavailable,
                          versioning.get_function_by_version,
                          routerlib.ROUTER_FUNC_DICT,
                          'create_lrouter', None)
