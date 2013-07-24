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
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco.nexus import cisco_nexus_plugin_v2
from neutron.tests import base


NEXUS_IP_ADDRESS = '1.1.1.1'
HOSTNAME1 = 'testhost1'
HOSTNAME2 = 'testhost2'
INSTANCE1 = 'testvm1'
INSTANCE2 = 'testvm2'
NEXUS_PORT1 = '1/10'
NEXUS_PORT2 = '1/20'
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
            }
            self._client.credentials = {
                NEXUS_IP_ADDRESS: {
                    'username': 'admin',
                    'password': 'pass1234'
                },
            }
            db.configure_db()

        # Use a mock netconf client
        mock_ncclient = mock.Mock()
        self.patch_obj = mock.patch.dict('sys.modules',
                                         {'ncclient': mock_ncclient})
        self.patch_obj.start()

        with mock.patch.object(cisco_nexus_plugin_v2.NexusPlugin,
                               '__init__', new=new_nexus_init):
            self._cisco_nexus_plugin = cisco_nexus_plugin_v2.NexusPlugin()

        self.addCleanup(self.patch_obj.stop)

    def test_create_networks(self):
        """Tests creation of two new Virtual Networks."""
        new_net_dict = self._cisco_nexus_plugin.create_network(
            self.network1, self.attachment1)
        for attr in NET_ATTRS:
            self.assertEqual(new_net_dict[attr], self.network1[attr])

        new_net_dict = self._cisco_nexus_plugin.create_network(
            self.network2, self.attachment1)
        for attr in NET_ATTRS:
            self.assertEqual(new_net_dict[attr], self.network2[attr])

    def test_create_providernet(self):
        with mock.patch.object(cdb, 'is_provider_vlan',
                               return_value=True) as mock_db:
            new_net_dict = self._cisco_nexus_plugin.create_network(
                self.providernet, self.attachment1)
            mock_db.assert_called_once()
            for attr in NET_ATTRS:
                self.assertEqual(new_net_dict[attr], self.providernet[attr])

    def test_create_provider_vlan_network_cfg_auto_man(self):
        cfg.CONF.set_override('provider_vlan_auto_create', True, 'CISCO')
        cfg.CONF.set_override('provider_vlan_auto_trunk', False, 'CISCO')
        self.addCleanup(cfg.CONF.reset)
        with mock.patch.object(cdb, 'is_provider_vlan', return_value=True):
            new_net_dict = self._cisco_nexus_plugin.create_network(
                self.providernet, self.attachment1)
            for attr in NET_ATTRS:
                self.assertEqual(new_net_dict[attr], self.providernet[attr])

    def test_create_provider_vlan_network_cfg_man_auto(self):
        cfg.CONF.set_override('provider_vlan_auto_create', False, 'CISCO')
        cfg.CONF.set_override('provider_vlan_auto_trunk', True, 'CISCO')
        self.addCleanup(cfg.CONF.reset)
        with mock.patch.object(cdb, 'is_provider_vlan', return_value=True):
            new_net_dict = self._cisco_nexus_plugin.create_network(
                self.providernet, self.attachment1)
            for attr in NET_ATTRS:
                self.assertEqual(new_net_dict[attr], self.providernet[attr])

    def test_create_provider_vlan_network_cfg_man_man(self):
        cfg.CONF.set_override('provider_vlan_auto_create', False, 'CISCO')
        cfg.CONF.set_override('provider_vlan_auto_trunk', False, 'CISCO')
        self.addCleanup(cfg.CONF.reset)
        with mock.patch.object(cdb, 'is_provider_vlan', return_value=True):
            new_net_dict = self._cisco_nexus_plugin.create_network(
                self.providernet, self.attachment1)
            for attr in NET_ATTRS:
                self.assertEqual(new_net_dict[attr], self.providernet[attr])

    def test_nexus_delete_port(self):
        """Test deletion of a vlan."""
        self._cisco_nexus_plugin.create_network(
            self.network1, self.attachment1)

        expected_instance_id = self._cisco_nexus_plugin.delete_port(
            INSTANCE1, self.vlan_id)

        self.assertEqual(expected_instance_id, INSTANCE1)

    def test_nexus_add_remove_router_interface(self):
        """Tests addition of a router interface."""
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        gateway_ip = '10.0.0.1/24'
        router_id = '00000R1'
        subnet_id = '00001'

        result = self._cisco_nexus_plugin.add_router_interface(vlan_name,
                                                               vlan_id,
                                                               subnet_id,
                                                               gateway_ip,
                                                               router_id)
        self.assertTrue(result)
        result = self._cisco_nexus_plugin.remove_router_interface(vlan_id,
                                                                  router_id)
        self.assertEqual(result, router_id)

    def test_nexus_add_router_interface_fail(self):
        """Tests deletion of a router interface."""
        vlan_name = self.vlan_name
        vlan_id = self.vlan_id
        gateway_ip = '10.0.0.1/24'
        router_id = '00000R1'
        subnet_id = '00001'

        self._cisco_nexus_plugin.add_router_interface(vlan_name,
                                                      vlan_id,
                                                      subnet_id,
                                                      gateway_ip,
                                                      router_id)

        self.assertRaises(
            cisco_exc.SubnetInterfacePresent,
            self._cisco_nexus_plugin.add_router_interface,
            vlan_name, vlan_id, subnet_id, gateway_ip, router_id)
