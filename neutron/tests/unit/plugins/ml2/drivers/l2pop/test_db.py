# Copyright 2015 Red Hat, Inc.
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

from neutron_lib import constants

from neutron import context
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2 import models
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api


class TestL2PopulationDBTestCase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestL2PopulationDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()

    def test_get_agent_by_host(self):
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        agent = l2pop_db.get_agent_by_host(
            self.ctx.session, helpers.HOST)
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_agent_by_host_no_candidate(self):
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        agent = l2pop_db.get_agent_by_host(
            self.ctx.session, helpers.HOST)
        self.assertIsNone(agent)

    def _setup_port_binding(self, network_id='network_id', dvr=True):
        with self.ctx.session.begin(subtransactions=True):
            self.ctx.session.add(models_v2.Network(id=network_id))
            device_owner = constants.DEVICE_OWNER_DVR_INTERFACE if dvr else ''
            self.ctx.session.add(models_v2.Port(
                id='port_id',
                network_id=network_id,
                mac_address='00:11:22:33:44:55',
                admin_state_up=True,
                status=constants.PORT_STATUS_ACTIVE,
                device_id='',
                device_owner=device_owner))
            port_binding_cls = (models.DVRPortBinding if dvr
                                else models.PortBinding)
            binding_kwarg = {
                'port_id': 'port_id',
                'host': helpers.HOST,
                'vif_type': portbindings.VIF_TYPE_UNBOUND,
                'vnic_type': portbindings.VNIC_NORMAL
            }
            if dvr:
                binding_kwarg['router_id'] = 'router_id'
                binding_kwarg['status'] = constants.PORT_STATUS_DOWN

            self.ctx.session.add(port_binding_cls(**binding_kwarg))

    def test_get_dvr_active_network_ports(self):
        self._setup_port_binding()
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        tunnel_network_ports = l2pop_db.get_dvr_active_network_ports(
            self.ctx.session, 'network_id')
        self.assertEqual(1, len(tunnel_network_ports))
        _, agent = tunnel_network_ports[0]
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_dvr_active_network_ports_no_candidate(self):
        self._setup_port_binding()
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        tunnel_network_ports = l2pop_db.get_dvr_active_network_ports(
            self.ctx.session, 'network_id')
        self.assertEqual(0, len(tunnel_network_ports))

    def test_get_nondvr_active_network_ports(self):
        self._setup_port_binding(dvr=False)
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        fdb_network_ports = l2pop_db.get_nondvr_active_network_ports(
            self.ctx.session, 'network_id')
        self.assertEqual(1, len(fdb_network_ports))
        _, agent = fdb_network_ports[0]
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_nondvr_active_network_ports_no_candidate(self):
        self._setup_port_binding(dvr=False)
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        fdb_network_ports = l2pop_db.get_nondvr_active_network_ports(
            self.ctx.session, 'network_id')
        self.assertEqual(0, len(fdb_network_ports))
