# Copyright 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from neutron.cmd import status
from neutron.tests import base


class TestUpgradeChecks(base.BaseTestCase):

    def test_load_checks(self):
        checks = [("test check", "test_check_method")]
        expected_checks = tuple(checks)
        checks_class_1 = mock.MagicMock()
        checks_class_1.entry_point.load()().get_checks.return_value = (
            checks)
        checks_class_2 = mock.MagicMock()
        checks_class_2.entry_point.load()().get_checks.return_value = None
        with mock.patch(
            "neutron_lib.utils.runtime.NamespacedPlugins"
        ) as namespace_plugins_mock:
            namespace_plugins = namespace_plugins_mock.return_value
            namespace_plugins._extensions = {
                "tests": checks_class_1,
                "no-checks-class": checks_class_2}
            self.assertEqual(expected_checks, status.load_checks())
