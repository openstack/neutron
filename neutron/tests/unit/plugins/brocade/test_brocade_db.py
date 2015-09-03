# Copyright (c) 2013 OpenStack Foundation.
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


"""
Unit test brocade db.
"""
import uuid

from neutron import context
from neutron.plugins.brocade.db import models as brocade_db
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

TEST_VLAN = 1000


class TestBrocadeDb(test_plugin.NeutronDbPluginV2TestCase):
    """Test brocade db functionality."""

    def test_create_network(self):
        """Test brocade specific network db."""

        net_id = str(uuid.uuid4())

        # Create a network
        self.context = context.get_admin_context()
        brocade_db.create_network(self.context, net_id, TEST_VLAN)

        # Get the network and verify
        net = brocade_db.get_network(self.context, net_id)
        self.assertEqual(net['id'], net_id)
        self.assertEqual(int(net['vlan']), TEST_VLAN)

        # Delete the network
        brocade_db.delete_network(self.context, net['id'])
        self.assertFalse(brocade_db.get_networks(self.context))

    def test_create_port(self):
        """Test brocade specific port db."""

        net_id = str(uuid.uuid4())
        port_id = str(uuid.uuid4())
        # port_id is truncated: since the linux-bridge tap device names are
        # based on truncated port id, this enables port lookups using
        # tap devices
        port_id = port_id[0:11]
        tenant_id = str(uuid.uuid4())
        admin_state_up = True

        # Create Port

        # To create a port a network must exists, Create a network
        self.context = context.get_admin_context()
        brocade_db.create_network(self.context, net_id, TEST_VLAN)

        physical_interface = "em1"
        brocade_db.create_port(self.context, port_id, net_id,
                               physical_interface,
                               TEST_VLAN, tenant_id, admin_state_up)

        port = brocade_db.get_port(self.context, port_id)
        self.assertEqual(port['port_id'], port_id)
        self.assertEqual(port['network_id'], net_id)
        self.assertEqual(port['physical_interface'], physical_interface)
        self.assertEqual(int(port['vlan_id']), TEST_VLAN)
        self.assertEqual(port['tenant_id'], tenant_id)
        self.assertEqual(port['admin_state_up'], admin_state_up)

        admin_state_up = True
        brocade_db.update_port_state(self.context, port_id, admin_state_up)
        port = brocade_db.get_port(self.context, port_id)
        self.assertEqual(port['admin_state_up'], admin_state_up)

        admin_state_up = False
        brocade_db.update_port_state(self.context, port_id, admin_state_up)
        port = brocade_db.get_port(self.context, port_id)
        self.assertEqual(port['admin_state_up'], admin_state_up)

        admin_state_up = True
        brocade_db.update_port_state(self.context, port_id, admin_state_up)
        port = brocade_db.get_port(self.context, port_id)
        self.assertEqual(port['admin_state_up'], admin_state_up)

        # Delete Port
        brocade_db.delete_port(self.context, port_id)
        self.assertFalse(brocade_db.get_ports(self.context))
