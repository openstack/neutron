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

from unittest import mock

from neutron_lib import constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_conf
from neutron.conf import common as common_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


class TestDhcp(functional_base.BaseSudoTestCase):
    def setUp(self):
        super().setUp()
        conf = cfg.ConfigOpts()
        config.register_interface_driver_opts_helper(conf)
        config.register_interface_opts(conf)
        conf.register_opts(common_conf.core_opts)
        conf.register_opts(dhcp_conf.DHCP_AGENT_OPTS)
        ovs_conf.register_ovs_opts(conf)
        conf.set_override('host', 'foo-host')
        self.conf = conf
        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.conf.set_override('integration_bridge', br_int.br_name, 'OVS')

    def test_cleanup_stale_devices(self):
        plugin = mock.MagicMock()
        dev_mgr = dhcp.DeviceManager(self.conf, plugin)
        spool_id = uuidutils.generate_uuid()
        dhcp_port4 = tests_base.AttributeDict({
            'id': 'foo_id4',
            'mac_address': '10:22:33:44:55:70',
            'fixed_ips': [tests_base.AttributeDict(
                {'subnet_id': 'subnet_foo_id4', 'ip_address': '10.0.0.4'})]
        })
        network = {
            'id': 'foo_id',
            'project_id': 'foo_project',
            'namespace': 'qdhcp-foo_id',
            'ports': [dhcp_port4],
            'subnets': [tests_base.AttributeDict({'id': 'subnet_foo_id',
                                                  'enable_dhcp': True,
                                                  'ipv6_address_mode': None,
                                                  'ipv6_ra_mode': None,
                                                  'cidr': '10.0.0.0/24',
                                                  'subnetpool_id': spool_id,
                                                  'ip_version':
                                                      constants.IP_VERSION_4,
                                                  'gateway_ip': '10.0.0.1'})]}
        dhcp_port = {
            'id': 'foo_id',
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
        dev_mgr.driver.plug("foo_id",
                            "foo_id4",
                            "tapfoo_id4",
                            "10:22:33:44:55:70",
                            namespace="qdhcp-foo_id")
        ipw = ip_lib.IPWrapper(namespace="qdhcp-foo_id")
        devices = ipw.get_devices()
        self.addCleanup(ipw.netns.delete, 'qdhcp-foo_id')
        self.assertEqual(sorted(["tapfoo_id2", "tapfoo_id3",
                                 "tapfoo_id4"]),
                         sorted(map(str, devices)))
        # setting up dhcp for the network
        dev_mgr.setup(tests_base.AttributeDict(network))
        common_utils.wait_until_true(
            lambda: 2 == len(ipw.get_devices()),
            timeout=5,
            sleep=0.1,
            exception=RuntimeError(
                "only two non-loopback devices must remain"))
        devices = ipw.get_devices()
        self.assertCountEqual(["tapfoo_id4", "tapfoo_id"],
                              [d.name for d in devices])
