# Copyright (c) 2015 Mirantis, Inc.
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
from oslo_config import cfg

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_conf
from neutron.conf import common as common_conf
from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


class TestDhcp(functional_base.BaseSudoTestCase):
    def setUp(self):
        super(TestDhcp, self).setUp()
        conf = cfg.ConfigOpts()
        config.register_interface_driver_opts_helper(conf)
        config.register_interface_opts(conf)
        conf.register_opts(common_conf.core_opts)
        conf.register_opts(dhcp_conf.DHCP_AGENT_OPTS)
        conf.set_override('interface_driver', 'openvswitch')
        conf.set_override('host', 'foo-host')
        self.conf = conf
        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.conf.set_override('ovs_integration_bridge', br_int.br_name)

    def test_cleanup_stale_devices(self):
        plugin = mock.MagicMock()
        dev_mgr = dhcp.DeviceManager(self.conf, plugin)
        network = {
            'id': 'foo_id',
            'tenant_id': 'foo_tenant',
            'namespace': 'qdhcp-foo_id',
            'ports': [],
            'subnets': [tests_base.AttributeDict({'id': 'subnet_foo_id',
                                                  'enable_dhcp': True,
                                                  'ipv6_address_mode': None,
                                                  'ipv6_ra_mode': None,
                                                  'cidr': '10.0.0.0/24',
                                                  'ip_version': 4,
                                                  'gateway_ip': '10.0.0.1'})]}
        dhcp_port = {
            'id': 'foo_port_id',
            'mac_address': '10:22:33:44:55:67',
            'fixed_ips': [tests_base.AttributeDict(
                {'subnet_id': 'subnet_foo_id', 'ip_address': '10.0.0.1'})]
        }
        plugin.create_dhcp_port.return_value = tests_base.AttributeDict(
            dhcp_port)
        dev_mgr.driver.plug("foo_id",
                            "foo_id2",
                            "tapfoo_id2",
                            "10:22:33:44:55:68",
                            namespace="qdhcp-foo_id")
        dev_mgr.driver.plug("foo_id",
                            "foo_id3",
                            "tapfoo_id3",
                            "10:22:33:44:55:69",
                            namespace="qdhcp-foo_id")
        ipw = ip_lib.IPWrapper(namespace="qdhcp-foo_id")
        devices = ipw.get_devices()
        self.addCleanup(ipw.netns.delete, 'qdhcp-foo_id')
        self.assertEqual(sorted(["tapfoo_id2", "tapfoo_id3"]),
                         sorted(map(str, devices)))
        # setting up dhcp for the network
        dev_mgr.setup(tests_base.AttributeDict(network))
        common_utils.wait_until_true(
            lambda: 1 == len(ipw.get_devices()),
            timeout=5,
            sleep=0.1,
            exception=RuntimeError("only one non-loopback device must remain"))
        devices = ipw.get_devices()
        self.assertEqual("tapfoo_port_id", devices[0].name)
