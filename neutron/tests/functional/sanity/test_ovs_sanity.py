# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


class OVSSanityTestCase(base.BaseTestCase):
    def setUp(self):
        super(OVSSanityTestCase, self).setUp()

        self.root_helper = 'sudo'

    def check_sudo_enabled(self):
        if os.environ.get('OS_SUDO_TESTING') not in base.TRUE_STRING:
            self.skipTest('testing with sudo is not enabled')

    def test_ovs_vxlan_support_runs(self):
        """This test just ensures that the test in neutron-sanity-check
            can run through without error, without mocking anything out
        """
        self.check_sudo_enabled()
        checks.vxlan_supported(self.root_helper)

    def test_ovs_patch_support_runs(self):
        """This test just ensures that the test in neutron-sanity-check
            can run through without error, without mocking anything out
        """
        self.check_sudo_enabled()
        checks.patch_supported(self.root_helper)
