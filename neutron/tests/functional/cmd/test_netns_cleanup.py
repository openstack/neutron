# Copyright (c) 2015 Red Hat, Inc.
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

import mock

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.cmd import netns_cleanup
from neutron.tests.functional.agent.linux import base

GET_NAMESPACES = 'neutron.agent.linux.ip_lib.IPWrapper.get_namespaces'
TEST_INTERFACE_DRIVER = 'neutron.agent.linux.interface.OVSInterfaceDriver'


class NetnsCleanupTest(base.BaseIPVethTestCase):
    def setUp(self):
        super(NetnsCleanupTest, self).setUp()

        self.get_namespaces_p = mock.patch(GET_NAMESPACES)
        self.get_namespaces = self.get_namespaces_p.start()

    def setup_config(self, args=None):
        if args is None:
            args = []
        # force option enabled to make sure non-empty namespaces are
        # cleaned up and deleted
        args.append('--force')

        self.conf = netns_cleanup.setup_conf()
        self.conf.set_override('interface_driver', TEST_INTERFACE_DRIVER)
        self.config_parse(conf=self.conf, args=args)

    def test_cleanup_network_namespaces_cleans_dhcp_and_l3_namespaces(self):
        l3_ns, dhcp_ns = self.prepare_veth_pairs(l3_agent.NS_PREFIX,
                                                 dhcp.NS_PREFIX)
        # we scope the get_namespaces to our own ones not to affect other
        # tests, as otherwise cleanup will kill them all
        self.get_namespaces.return_value = [l3_ns.namespace,
                                            dhcp_ns.namespace]

        netns_cleanup.cleanup_network_namespaces(self.conf)

        self.get_namespaces_p.stop()
        namespaces_now = ip_lib.IPWrapper.get_namespaces()
        self.assertNotIn(l3_ns.namespace, namespaces_now)
        self.assertNotIn(dhcp_ns.namespace, namespaces_now)
