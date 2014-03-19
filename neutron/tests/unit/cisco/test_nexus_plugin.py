# Copyright (c) 2012 OpenStack Foundation.
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

import mock

from oslo.config import cfg

from neutron.db import api as db
from neutron.extensions import providernet as provider
from neutron.openstack.common import importutils
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as cisco_exc
from neutron.plugins.cisco.common import config as cisco_config
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco.nexus import cisco_nexus_plugin_v2
from neutron.tests import base


NEXUS_IP_ADDRESS = '1.1.1.1'
HOSTNAME1 = 'testhost1'
HOSTNAME2 = 'testhost2'
HOSTNAME3 = 'testhost3'
INSTANCE1 = 'testvm1'
INSTANCE2 = 'testvm2'
INSTANCE3 = 'testvm3'
NEXUS_PORT1 = '1/10'
NEXUS_PORT2 = '1/20'
NEXUS_PC_IP_ADDRESS = '2.2.2.2'
NEXUS_PORTCHANNELS = 'portchannel:2'
PC_HOSTNAME = 'testpchost'
NEXUS_SSH_PORT = '22'
NEXUS_DRIVER = ('neutron.plugins.cisco.nexus.'
                'cisco_nexus_network_driver_v2.CiscoNEXUSDriver')
NET_ATTRS = [const.NET_ID,
             const.NET_NAME,
             const.NET_VLAN_NAME,
             const.NET_VLAN_ID]


class TestCiscoNexusPlugin(base.BaseTestCase):

    def setUp(self):
        """Set up function."""
        super(TestCiscoNexusPlugin, self).setUp()
        self.tenant_id = "test_tenant_cisco1"
        self.net_name = "test_network_cisco1"
        self.net_id = 7
        self.vlan_name = "q-" + str(self.net_id) + "vlan"
        self.vlan_id = 267
        self.second_tenant_id = "test_tenant_2"
        self.second_net_name = "test_network_cisco2"
        self.second_net_id = 5
        self.second_vlan_name = "q-" + str(self.second_net_id) + "vlan"
        self.second_vlan_id = 265
        self._pchostname = PC_HOSTNAME

        self.attachment1 = {
            const.TENANT_ID: self.tenant_id,
            const.INSTANCE_ID: INSTANCE1,
            const.HOST_NAME: HOSTNAME1,
        }
        self.attachment2 = {
            const.TENANT_ID: self.second_tenant_id,
            const.INSTANCE_ID: INSTANCE2,
            const.HOST_NAME: HOSTNAME2,
        }
        self.attachment3 = {
            const.TENANT_ID: self.second_tenant_id,
            const.INSTANCE_ID: INSTANCE3,
            const.HOST_NAME: HOSTNAME3,
        }
        self.network1 = {
            const.NET_ID: self.net_id,
            const.NET_NAME: self.net_name,
            const.NET_VLAN_NAME: self.vlan_name,
            const.NET_VLAN_ID: self.vlan_id,
        }
        self.network2 = {
            const.NET_ID: self.second_net_id,
            const.NET_NAME: self.second_net_name,
            const.NET_VLAN_NAME: self.second_vlan_name,
            const.NET_VLAN_ID: self.second_vlan_id,
        }
        self.network3 = {
            const.NET_ID: 8,
            const.NET_NAME: 'vpc_net',
            const.NET_VLAN_NAME: 'q-268',
            const.NET_VLAN_ID: '268',
        }
        self.delete_port_args_1 = [
            self.attachment1[const.INSTANCE_ID],
            self.network1[const.NET_VLAN_ID],
        ]
        self.providernet = {
            const.NET_ID: 9,
            const.NET_NAME: 'pnet1',
            const.NET_VLAN_NAME: 'p-300',
            const.NET_VLAN_ID: 300,
            provider.NETWORK_TYPE: 'vlan',
            provider.PHYSICAL_NETWORK: self.net_name + '200:299',
            provider.SEGMENTATION_ID: 300,
        }

        def new_nexus_init(self):
            self._client = importutils.import_object(NEXUS_DRIVER)
            self._client.nexus_switches = {
                (NEXUS_IP_ADDRESS, HOSTNAME1): NEXUS_PORT1,
                (NEXUS_IP_ADDRESS, 'ssh_port'): NEXUS_SSH_PORT,
                (NEXUS_IP_ADDRESS, HOSTNAME2): NEXUS_PORT2,
                (NEXUS_IP_ADDRESS, 'ssh_port'): NEXUS_SSH_PORT,
                (NEXUS_PC_IP_ADDRESS, 'ssh_port'): NEXUS_SSH_PORT,
            }
            self._nexus_switches = {
                ('NEXUS_SWITCH', NEXUS_IP_ADDRESS, HOSTNAME1): NEXUS_PORT1,
                ('NEXUS_SWITCH', NEXUS_IP_ADDRESS, HOSTNAME2): NEXUS_PORT2,
                ('NEXUS_SWITCH', NEXUS_PC_IP_ADDRESS, HOSTNAME3):
                NEXUS_PORTCHANNELS,
                ('NEXUS_SWITCH', NEXUS_PC_IP_ADDRESS, 'ssh_port'):
                NEXUS_SSH_PORT,
                ('NEXUS_SWITCH', NEXUS_IP_ADDRESS, HOSTNAME3):
                NEXUS_PORTCHANNELS,
                ('NEXUS_SWITCH', NEXUS_IP_ADDRESS, 'ssh_port'): NEXUS_SSH_PORT,
            }
            self._client.credentials = {
                NEXUS_IP_ADDRESS: {
                    'username': 'admin',
                    'password': 'pass1234'
                },
                NEXUS_PC_IP_ADDRESS: {
                    'username': 'admin',
                    'password': 'password'
                },
            }
            db.configure_db()

        self.addCleanup(db.clear_db)
        # Use a mock netconf client
        self.mock_ncclient = mock.Mock()
        self.patch_obj = mock.patch.dict('sys.modules',
                                         {'ncclient': self.mock_ncclient})
        self.patch_obj.start()
        self.addCleanup(self.patch_obj.stop)

        with mock.patch.object(cisco_nexus_plugin_v2.NexusPlugin,
                               '__init__', new=new_nexus_init):
            self._cisco_nexus_plugin = cisco_nexus_plugin_v2.NexusPlugin()

        # Set the Cisco config module's first configured device IP address
        # according to the preceding switch config.
        mock.patch.object(cisco_config, 'first_device_ip',
                          new=NEXUS_IP_ADDRESS).start()

    def test_create_delete_networks(self):
        """Tests creation of two new Virtual Networks."""
        new_net_dict = self._cisco_nexus_plugin.create_network(
            self.network1, self.attachment1)
        for attr in NET_ATTRS:
            self.assertEqual(new_net_dict[attr], self.network1[attr])

        expected_instance_id = self._cisco_nexus_plugin.delete_port(
            INSTANCE1, self.vlan_id)

        self.assertEqual(expected_instance_id, INSTANCE1)

        new_net_dict = self._cisco_nexus_plugin.create_network(
            self.network2, self.attachment1)
        for attr in NET_ATTRS:
            self.assertEqual(new_net_dict[attr], self.network2[attr])

        expected_instance_id = self._cisco_nexus_plugin.delete_port(
            INSTANCE1, self.second_vlan_id)

        self.assertEqual(expected_instance_id, INSTANCE1)

    def _create_delete_providernet(self, auto_create, auto_trunk):
        cfg.CONF.set_override(
            'provider_vlan_auto_create', auto_create, 'CISCO')
        cfg.CONF.set_override(
            'provider_vlan_auto_trunk', auto_trunk, 'CISCO')
        with mock.patch.object(cdb, 'is_provider_vlan',
                               return_value=True) as mock_db:
            # Create a provider network
            new_net_dict = self._cisco_nexus_plugin.create_network(
                self.providernet, self.attachment1)
            mock_db.assert_called_once()
            for attr in NET_ATTRS:
                self.assertEqual(new_net_dict[attr], self.providernet[attr])
            # Delete the provider network
            instance_id = self._cisco_nexus_plugin.delete_port(
                self.attachment1[const.INSTANCE_ID],
                self.providernet[const.NET_VLAN_ID])
            self.assertEqual(instance_id,
                             self.attachment1[const.INSTANCE_ID])

    def test_create_delete_providernet(self):
        self._create_delete_providernet(auto_create=True, auto_trunk=True)

    def test_create_delete_provider_vlan_network_cfg_auto_man(self):
        self._create_delete_providernet(auto_create=True, auto_trunk=False)

    def test_create_delete_provider_vlan_network_cfg_man_auto(self):
        self._create_delete_providernet(auto_create=False, auto_trunk=True)

    def test_create_delete_provider_vlan_network_cfg_man_man(self):
        self._create_delete_providernet(auto_create=False, auto_trunk=False)

    def test_create_delete_network_portchannel(self):
        """Tests creation of a network over a portchannel."""
        new_net_dict = self._cisco_nexus_plugin.create_network(
            self.network3, self.attachment3)
        self.assertEqual(new_net_dict[const.NET_ID],
                         self.network3[const.NET_ID])
        self.assertEqual(new_net_dict[const.NET_NAME],
                         self.network3[const.NET_NAME])
        self.assertEqual(new_net_dict[const.NET_VLAN_NAME],
                         self.network3[const.NET_VLAN_NAME])
        self.assertEqual(new_net_dict[const.NET_VLAN_ID],
                         self.network3[const.NET_VLAN_ID])

        self._cisco_nexus_plugin.delete_port(
            INSTANCE3, self.network3[const.NET_VLAN_ID]
        )

    def _add_router_interface(self):
        """Add a router interface using fixed (canned) parameters."""
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        gateway_ip = '10.0.0.1/24'
        router_id = '00000R1'
        subnet_id = '00001'
        return self._cisco_nexus_plugin.add_router_interface(
            vlan_name, vlan_id, subnet_id, gateway_ip, router_id)

    def _remove_router_interface(self):
        """Remove a router interface created with _add_router_interface."""
        vlan_id = self.vlan_id
        router_id = '00000R1'
        return self._cisco_nexus_plugin.remove_router_interface(vlan_id,
                                                                router_id)

    def test_nexus_add_remove_router_interface(self):
        """Tests addition of a router interface."""
        self.assertTrue(self._add_router_interface())
        self.assertEqual(self._remove_router_interface(), '00000R1')

    def test_nexus_dup_add_router_interface(self):
        """Tests a duplicate add of a router interface."""
        self._add_router_interface()
        try:
            self.assertRaises(
                cisco_exc.SubnetInterfacePresent,
                self._add_router_interface)
        finally:
            self._remove_router_interface()

    def test_nexus_no_svi_switch_exception(self):
        """Tests failure to find a Nexus switch for SVI placement."""
        # Clear the Nexus switches dictionary.
        with mock.patch.dict(self._cisco_nexus_plugin._client.nexus_switches,
                             {}, clear=True):
            # Clear the first Nexus IP address discovered in config
            with mock.patch.object(cisco_config, 'first_device_ip',
                                   new=None):
                self.assertRaises(cisco_exc.NoNexusSviSwitch,
                                  self._add_router_interface)

    def test_nexus_add_port_after_router_interface(self):
        """Tests creating a port after a router interface.

        Test creating a port after an SVI router interface has
        been created. Only a trunk call should be invoked and the
        plugin should not attempt to recreate the vlan.
        """
        self._add_router_interface()
        # Create a network on the switch
        self._cisco_nexus_plugin.create_network(
            self.network1, self.attachment1)

        # Grab a list of all mock calls from ncclient
        last_cfgs = (self.mock_ncclient.manager.connect.return_value.
                     edit_config.mock_calls)

        # The last ncclient call should be for trunking and the second
        # to last call should be creating the SVI interface
        last_cfg = last_cfgs[-1][2]['config']
        self.assertIn('allowed', last_cfg)

        slast_cfg = last_cfgs[-2][2]['config']
        self.assertIn('10.0.0.1/24', slast_cfg)
