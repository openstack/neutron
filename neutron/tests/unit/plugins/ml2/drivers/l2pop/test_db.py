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

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.tests import tools
from neutron_lib.utils import net
from oslo_utils import uuidutils

from neutron.db.models import l3 as l3_models
from neutron.objects import l3_hamode
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_objs
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2 import models
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api

HOST = helpers.HOST
HOST_2 = 'HOST_2'
HOST_3 = 'HOST_3'
HOST_2_TUNNELING_IP = '20.0.0.2'
HOST_3_TUNNELING_IP = '20.0.0.3'
TEST_ROUTER_ID = uuidutils.generate_uuid()
TEST_NETWORK_ID = uuidutils.generate_uuid()
TEST_HA_NETWORK_ID = uuidutils.generate_uuid()
PLUGIN_NAME = 'ml2'


class TestL2PopulationDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestL2PopulationDBTestCase, self).setUp()
        self.setup_coreplugin(PLUGIN_NAME)
        self.ctx = context.get_admin_context()
        self._create_network()

    def _create_network(self, network_id=TEST_NETWORK_ID):
        network_obj.Network(self.ctx, id=network_id).create()

    def _create_router(self, distributed=True, ha=False):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.ctx.session.add(l3_models.Router(id=TEST_ROUTER_ID))
            l3_objs.RouterExtraAttributes(
                self.ctx,
                router_id=TEST_ROUTER_ID,
                distributed=distributed, ha=ha).create()

    def _create_ha_router(self, distributed=False):
        helpers.register_l3_agent(HOST_2)
        helpers.register_ovs_agent(HOST_2, tunneling_ip=HOST_2_TUNNELING_IP)
        # Register l3 agent on host3, which doesn't host any HA router.
        # Tests should test that host3 is not a HA agent host.
        helpers.register_l3_agent(HOST_3)
        helpers.register_ovs_agent(HOST_3, tunneling_ip=HOST_3_TUNNELING_IP)
        with db_api.CONTEXT_WRITER.using(self.ctx):
            network_obj.Network(self.ctx, id=TEST_HA_NETWORK_ID).create()
            self._create_router(distributed=distributed, ha=True)
            for state, host in [(constants.HA_ROUTER_STATE_ACTIVE, HOST),
                                (constants.HA_ROUTER_STATE_STANDBY, HOST_2)]:
                self._setup_port_binding(
                    network_id=TEST_HA_NETWORK_ID,
                    device_owner=constants.DEVICE_OWNER_ROUTER_HA_INTF,
                    device_id=TEST_ROUTER_ID,
                    host_state=state,
                    host=host)

    def get_l3_agent_by_host(self, agent_host):
        plugin = helpers.FakePlugin()
        return plugin._get_agent_by_type_and_host(
            self.ctx, constants.AGENT_TYPE_L3, agent_host)

    def test_get_agent_by_host(self):
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        agent = l2pop_db.get_agent_by_host(
            self.ctx, helpers.HOST)
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_agent_by_host_no_candidate(self):
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        agent = l2pop_db.get_agent_by_host(
            self.ctx, helpers.HOST)
        self.assertIsNone(agent)

    def _setup_port_binding(self, **kwargs):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            mac = netaddr.EUI(
                    net.get_random_mac('fa:16:3e:00:00:00'.split(':')),
                    dialect=netaddr.mac_unix_expanded)
            port_id = uuidutils.generate_uuid()
            network_id = kwargs.get('network_id', TEST_NETWORK_ID)
            device_owner = kwargs.get('device_owner', '')
            device_id = kwargs.get('device_id', uuidutils.generate_uuid())
            host = kwargs.get('host', helpers.HOST)

            port_obj.Port(self.ctx,
                id=port_id, network_id=network_id, mac_address=mac,
                admin_state_up=True, status=constants.PORT_STATUS_ACTIVE,
                device_id=device_id, device_owner=device_owner).create()

            port_binding_cls = models.PortBinding
            binding_kwarg = {'port_id': port_id,
                             'host': host,
                             'vif_type': portbindings.VIF_TYPE_UNBOUND,
                             'vnic_type': portbindings.VNIC_NORMAL}

            if device_owner == constants.DEVICE_OWNER_DVR_INTERFACE:
                port_binding_cls = models.DistributedPortBinding
                binding_kwarg['router_id'] = TEST_ROUTER_ID
                binding_kwarg['status'] = constants.PORT_STATUS_DOWN

            self.ctx.session.add(port_binding_cls(**binding_kwarg))

            if network_id == TEST_HA_NETWORK_ID:
                agent = self.get_l3_agent_by_host(host)
                l3_hamode.L3HARouterAgentPortBinding(
                    self.ctx, port_id=port_id, router_id=device_id,
                    l3_agent_id=agent['id'], state=kwargs.get(
                        'host_state',
                        constants.HA_ROUTER_STATE_ACTIVE)).create()

    def test_get_distributed_active_network_ports(self):
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_DVR_INTERFACE)
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        tunnel_network_ports = l2pop_db.get_distributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(1, len(tunnel_network_ports))
        _, agent = tunnel_network_ports[0]
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_distributed_active_network_ports_no_candidate(self):
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_DVR_INTERFACE)
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        tunnel_network_ports = l2pop_db.get_distributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(0, len(tunnel_network_ports))

    def test_get_nondistributed_active_network_ports(self):
        self._setup_port_binding(dvr=False)
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        fdb_network_ports = l2pop_db.get_nondistributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(1, len(fdb_network_ports))
        _, agent = fdb_network_ports[0]
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_nondistributed_active_network_ports_no_candidate(self):
        self._setup_port_binding(dvr=False)
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        fdb_network_ports = l2pop_db.get_nondistributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(0, len(fdb_network_ports))

    def test__get_ha_router_interface_ids_with_ha_dvr_snat_port(self):
        helpers.register_dhcp_agent()
        helpers.register_l3_agent()
        helpers.register_ovs_agent()
        self._create_ha_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        ha_iface_ids = l2pop_db._get_ha_router_interface_ids(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(1, len(list(ha_iface_ids)))

    def test__get_ha_router_interface_ids_with_ha_replicated_port(self):
        helpers.register_dhcp_agent()
        helpers.register_l3_agent()
        helpers.register_ovs_agent()
        self._create_ha_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_HA_REPLICATED_INT,
            device_id=TEST_ROUTER_ID)
        ha_iface_ids = l2pop_db._get_ha_router_interface_ids(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(1, len(list(ha_iface_ids)))

    def test__get_ha_router_interface_ids_with_no_ha_port(self):
        self._create_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        ha_iface_ids = l2pop_db._get_ha_router_interface_ids(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(0, len(list(ha_iface_ids)))

    def test_active_network_ports_with_dvr_snat_port(self):
        # Test to get agent hosting dvr snat port
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        # create DVR router
        self._create_router()
        # setup DVR snat port
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        helpers.register_dhcp_agent()
        fdb_network_ports = l2pop_db.get_nondistributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(1, len(fdb_network_ports))

    def test_active_network_ports_with_ha_dvr_snat_port(self):
        # test to get HA agents hosting HA+DVR snat port
        helpers.register_dhcp_agent()
        helpers.register_l3_agent()
        helpers.register_ovs_agent()
        # create HA+DVR router
        self._create_ha_router()
        # setup HA snat port
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        fdb_network_ports = l2pop_db.get_nondistributed_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(0, len(fdb_network_ports))
        ha_ports = l2pop_db.get_ha_active_network_ports(
            self.ctx, TEST_NETWORK_ID)
        self.assertEqual(2, len(ha_ports))

    def test_active_port_count_with_dvr_snat_port(self):
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        self._create_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        helpers.register_dhcp_agent()
        port_count = l2pop_db.get_agent_network_active_port_count(
            self.ctx, HOST, TEST_NETWORK_ID)
        self.assertEqual(1, port_count)
        port_count = l2pop_db.get_agent_network_active_port_count(
            self.ctx, HOST_2, TEST_NETWORK_ID)
        self.assertEqual(0, port_count)

    def test_active_port_count_with_ha_dvr_snat_port(self):
        helpers.register_dhcp_agent()
        helpers.register_l3_agent()
        helpers.register_ovs_agent()
        self._create_ha_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        port_count = l2pop_db.get_agent_network_active_port_count(
            self.ctx, HOST, TEST_NETWORK_ID)
        self.assertEqual(1, port_count)
        port_count = l2pop_db.get_agent_network_active_port_count(
            self.ctx, HOST_2, TEST_NETWORK_ID)
        self.assertEqual(1, port_count)

    def test_get_ha_agents_by_router_id(self):
        helpers.register_dhcp_agent()
        helpers.register_l3_agent()
        helpers.register_ovs_agent()
        self._create_ha_router()
        self._setup_port_binding(
            device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
            device_id=TEST_ROUTER_ID)
        agents = l2pop_db.get_ha_agents_by_router_id(
            self.ctx, TEST_ROUTER_ID)
        ha_agents = [agent.host for agent in agents]
        self.assertEqual(tools.UnorderedList([HOST, HOST_2]), ha_agents)
