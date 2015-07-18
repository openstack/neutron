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

from neutron.cmd.sanity import checks
from neutron.tests import base
from neutron.tests.functional import base as functional_base


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

    def test_dnsmasq_version(self):
        checks.dnsmasq_version_supported()


class SanityTestCaseRoot(functional_base.BaseSudoTestCase):
    """Sanity checks that require root access.

    Tests that just call checks.some_function() are to ensure that
    neutron-sanity-check runs without throwing an exception, as in the case
    where someone modifies the API without updating the check script.
    """

    def test_ovs_vxlan_support_runs(self):
        checks.ovs_vxlan_supported()

    def test_iproute2_vxlan_support_runs(self):
        checks.iproute2_vxlan_supported()

    def test_ovs_patch_support_runs(self):
        checks.patch_supported()

    def test_arp_responder_runs(self):
        checks.arp_responder_supported()

    def test_arp_header_match_runs(self):
        checks.arp_header_match_supported()

    def test_vf_management_runs(self):
        checks.vf_management_supported()

    def test_namespace_root_read_detection_runs(self):
        checks.netns_read_requires_helper()

    def test_ovsdb_native_supported_runs(self):
        checks.ovsdb_native_supported()

    def test_keepalived_ipv6_support(self):
        checks.keepalived_ipv6_supported()
