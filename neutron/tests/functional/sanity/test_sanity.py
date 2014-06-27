# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
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

import os

from neutron.cmd.sanity import checks
from neutron.tests import base


class SanityTestCase(base.BaseTestCase):
    """Sanity checks that do not require root access.

    Tests that just call checks.some_function() are to ensure that
    neutron-sanity-check runs without throwing an exception, as in the case
    where someone modifies the API without updating the check script.
    """

    def setUp(self):
        super(SanityTestCase, self).setUp()

    def test_nova_notify_runs(self):
        checks.nova_notify_supported()


class SanityTestCaseRoot(base.BaseTestCase):
    """Sanity checks that require root access.

    Tests that just call checks.some_function() are to ensure that
    neutron-sanity-check runs without throwing an exception, as in the case
    where someone modifies the API without updating the check script.
    """
    def setUp(self):
        super(SanityTestCaseRoot, self).setUp()

        self.root_helper = 'sudo'
        self.check_sudo_enabled()

    def check_sudo_enabled(self):
        if os.environ.get('OS_SUDO_TESTING') not in base.TRUE_STRING:
            self.skipTest('testing with sudo is not enabled')

    def test_ovs_vxlan_support_runs(self):
        checks.vxlan_supported(self.root_helper)

    def test_ovs_patch_support_runs(self):
        checks.patch_supported(self.root_helper)
