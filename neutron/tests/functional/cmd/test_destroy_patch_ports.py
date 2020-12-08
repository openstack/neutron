# Copyright 2020 Red Hat, Inc.
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

from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron.cmd import destroy_patch_ports
from neutron.common import utils
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class TestDestroyPatchPorts(base.BaseSudoTestCase):
    def setUp(self):
        super(TestDestroyPatchPorts, self).setUp()
        self.int_br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        bridge_mappings = {}
        self.bridges = []
        for network in ('foo', 'bar'):
            bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
            self._create_patch_ports_to_int_br(bridge)
            self.bridges.append(bridge)
            bridge_mappings[network] = bridge.br_name
        self.config = self._create_config_file(bridge_mappings)

    def _create_config_file(self, bridge_mappings):
        config = cfg.ConfigOpts()
        ovs_conf.register_ovs_agent_opts(config)
        config.set_override('integration_bridge', self.int_br.br_name, "OVS")
        config.set_override(
            'bridge_mappings',
            ','.join(["%s:%s" % (net, br)
                      for net, br in bridge_mappings.items()]),
            "OVS")

        return config

    def _create_patch_ports_to_int_br(self, bridge):
        int_if_name, phys_if_name = destroy_patch_ports.get_patch_port_names(
            bridge.br_name)
        self.int_br.add_patch_port(
            int_if_name, constants.NONEXISTENT_PEER)
        bridge.add_patch_port(
            phys_if_name, constants.NONEXISTENT_PEER)
        self.int_br.set_db_attribute(
            'Interface', int_if_name, 'options', {'peer': phys_if_name})
        bridge.set_db_attribute(
            'Interface', phys_if_name, 'options', {'peer': int_if_name})

    def _has_patch_ports(self, bridge):
        int_if_name, phys_if_name = destroy_patch_ports.get_patch_port_names(
            bridge.br_name)
        return (bridge.port_exists(phys_if_name) and
                self.int_br.port_exists(int_if_name))

    def _assert_has_all_ports(self):
        self.assertTrue(all(self._has_patch_ports(bridge)
                            for bridge in self.bridges))

    def test_destroy_patch_ports(self):
        self._assert_has_all_ports()
        cleaner = destroy_patch_ports.PatchPortCleaner(self.config)
        cleaner.destroy_patch_ports()
        self.assertFalse(any(self._has_patch_ports(bridge)
                             for bridge in self.bridges))

    def test_destroy_patch_ports_no_int_br(self):
        name = utils.get_rand_name(
            max_length=n_const.DEVICE_NAME_MAX_LEN)
        self.config.set_override('integration_bridge', name, "OVS")
        cleaner = destroy_patch_ports.PatchPortCleaner(self.config)
        cleaner.destroy_patch_ports()

    def test_destroy_patch_ports_canary_flow_on_int_br(self):
        self.int_br.add_flow(table=constants.CANARY_TABLE, actions="drop")
        self._assert_has_all_ports()
        cleaner = destroy_patch_ports.PatchPortCleaner(self.config)
        cleaner.destroy_patch_ports()
        self._assert_has_all_ports()
