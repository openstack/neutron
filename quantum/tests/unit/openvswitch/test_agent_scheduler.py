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

import contextlib
import copy

import mock
from webob import exc

from quantum.api import extensions
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.common import constants
from quantum import context
from quantum.db import agents_db
from quantum.db import dhcp_rpc_base
from quantum.db import l3_rpc_base
from quantum.extensions import agentscheduler
from quantum import manager
from quantum.openstack.common import timeutils
from quantum.openstack.common import uuidutils
from quantum.tests.unit import test_agent_ext_plugin
from quantum.tests.unit.testlib_api import create_request
from quantum.tests.unit import test_db_plugin as test_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import test_l3_plugin
from quantum.wsgi import Serializer

L3_HOSTA = 'hosta'
DHCP_HOSTA = 'hosta'
L3_HOSTB = 'hostb'
DHCP_HOSTC = 'hostc'


class AgentSchedulerTestMixIn(object):

    def _request_list(self, path, admin_context=True,
                      expected_code=exc.HTTPOk.code):
        req = self._path_req(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(self.fmt, res)

    def _path_req(self, path, method='GET', data=None,
                  query_string=None,
                  admin_context=True):
        content_type = 'application/%s' % self.fmt
        body = None
        if data is not None:  # empty dict is valid
            body = Serializer().serialize(data, content_type)
        if admin_context:
            return create_request(
                path, body, content_type, method, query_string=query_string)
        else:
            return create_request(
                path, body, content_type, method, query_string=query_string,
                context=context.Context('', 'tenant_id'))

    def _path_create_request(self, path, data, admin_context=True):
        return self._path_req(path, method='POST', data=data,
                              admin_context=admin_context)

    def _path_show_request(self, path, admin_context=True):
        return self._path_req(path, admin_context=admin_context)

    def _path_delete_request(self, path, admin_context=True):
        return self._path_req(path, method='DELETE',
                              admin_context=admin_context)

    def _path_update_request(self, path, data, admin_context=True):
        return self._path_req(path, method='PUT', data=data,
                              admin_context=admin_context)

    def _list_routers_hosted_by_l3_agent(self, agent_id,
                                         expected_code=exc.HTTPOk.code,
                                         admin_context=True):
        path = "/agents/%s/%s.%s" % (agent_id,
                                     agentscheduler.L3_ROUTERS,
                                     self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_networks_hosted_by_dhcp_agent(self, agent_id,
                                            expected_code=exc.HTTPOk.code,
                                            admin_context=True):
        path = "/agents/%s/%s.%s" % (agent_id,
                                     agentscheduler.DHCP_NETS,
                                     self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_l3_agents_hosting_router(self, router_id,
                                       expected_code=exc.HTTPOk.code,
                                       admin_context=True):
        path = "/routers/%s/%s.%s" % (router_id,
                                      agentscheduler.L3_AGENTS,
                                      self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_dhcp_agents_hosting_network(self, network_id,
                                          expected_code=exc.HTTPOk.code,
                                          admin_context=True):
        path = "/networks/%s/%s.%s" % (network_id,
                                       agentscheduler.DHCP_AGENTS,
                                       self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _add_router_to_l3_agent(self, id, router_id,
                                expected_code=exc.HTTPCreated.code,
                                admin_context=True):
        path = "/agents/%s/%s.%s" % (id,
                                     agentscheduler.L3_ROUTERS,
                                     self.fmt)
        req = self._path_create_request(path,
                                        {'router_id': router_id},
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)

    def _add_network_to_dhcp_agent(self, id, network_id,
                                   expected_code=exc.HTTPCreated.code,
                                   admin_context=True):
        path = "/agents/%s/%s.%s" % (id,
                                     agentscheduler.DHCP_NETS,
                                     self.fmt)
        req = self._path_create_request(path,
                                        {'network_id': network_id},
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)

    def _remove_network_from_dhcp_agent(self, id, network_id,
                                        expected_code=exc.HTTPNoContent.code,
                                        admin_context=True):
        path = "/agents/%s/%s/%s.%s" % (id,
                                        agentscheduler.DHCP_NETS,
                                        network_id,
                                        self.fmt)
        req = self._path_delete_request(path,
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)

    def _remove_router_from_l3_agent(self, id, router_id,
                                     expected_code=exc.HTTPNoContent.code,
                                     admin_context=True):
        path = "/agents/%s/%s/%s.%s" % (id,
                                        agentscheduler.L3_ROUTERS,
                                        router_id,
                                        self.fmt)
        req = self._path_delete_request(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)

    def _register_one_agent_state(self, agent_state):
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': agent_state},
                              time=timeutils.strtime())

    def _disable_agent(self, agent_id, admin_state_up=False):
        new_agent = {}
        new_agent['agent'] = {}
        new_agent['agent']['admin_state_up'] = admin_state_up
        self._update('agents', agent_id, new_agent)

    def _get_agent_id(self, agent_type, host):
        agents = self._list_agents()
        for agent in agents['agents']:
            if (agent['agent_type'] == agent_type and
                agent['host'] == host):
                return agent['id']


class OvsAgentSchedulerTestCase(test_l3_plugin.L3NatTestCaseMixin,
                                test_agent_ext_plugin.AgentDBTestMixIn,
                                AgentSchedulerTestMixIn,
                                test_plugin.QuantumDbPluginV2TestCase):
    fmt = 'json'
    plugin_str = ('quantum.plugins.openvswitch.'
                  'ovs_quantum_plugin.OVSQuantumPluginV2')

    def setUp(self):
        super(OvsAgentSchedulerTestCase, self).setUp(self.plugin_str)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        self.agentscheduler_dbMinxin = manager.QuantumManager.get_plugin()

    def test_report_states(self):
        self._register_agent_states()
        agents = self._list_agents()
        self.assertEqual(4, len(agents['agents']))

    def test_network_scheduling_on_network_creation(self):
        self._register_agent_states()
        with self.network() as net:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                net['network']['id'])
        self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_auto_schedule_with_disabled(self):
        with contextlib.nested(self.network(),
                               self.network()):
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            self._disable_agent(hosta_id)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            # second agent will host all the networks since first is disabled.
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(0, num_hosta_nets)
        self.assertEqual(2, num_hostc_nets)

    def test_network_auto_schedule_with_hosted(self):
        # one agent hosts all the networks, other hosts none
        with contextlib.nested(self.network(),
                               self.network()) as (net1, net2):
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            # second agent will not host the network since first has got it.
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTC)
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                net1['network']['id'])
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            hosta_nets = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(hosta_nets['networks'])
            hostc_nets = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(hostc_nets['networks'])

        self.assertEqual(2, num_hosta_nets)
        self.assertEqual(0, num_hostc_nets)
        self.assertEqual(1, len(dhcp_agents['agents']))
        self.assertEqual(DHCP_HOSTA, dhcp_agents['agents'][0]['host'])

    def test_network_auto_schedule_with_hosted_2(self):
        # one agent hosts one network
        dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        dhcp_hostc = copy.deepcopy(dhcp_hosta)
        dhcp_hostc['host'] = DHCP_HOSTC
        with self.network() as net1:
            self._register_one_agent_state(dhcp_hosta)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            with self.network() as net2:
                self._register_one_agent_state(dhcp_hostc)
                dhcp_rpc.get_active_networks(self.adminContext,
                                             host=DHCP_HOSTC)
                dhcp_agents_1 = self._list_dhcp_agents_hosting_network(
                    net1['network']['id'])
                dhcp_agents_2 = self._list_dhcp_agents_hosting_network(
                    net2['network']['id'])
                hosta_nets = self._list_networks_hosted_by_dhcp_agent(hosta_id)
                num_hosta_nets = len(hosta_nets['networks'])
                hostc_id = self._get_agent_id(
                    constants.AGENT_TYPE_DHCP,
                    DHCP_HOSTC)
                hostc_nets = self._list_networks_hosted_by_dhcp_agent(hostc_id)
                num_hostc_nets = len(hostc_nets['networks'])

        self.assertEqual(1, num_hosta_nets)
        self.assertEqual(1, num_hostc_nets)
        self.assertEqual(1, len(dhcp_agents_1['agents']))
        self.assertEqual(1, len(dhcp_agents_2['agents']))
        self.assertEqual(DHCP_HOSTA, dhcp_agents_1['agents'][0]['host'])
        self.assertEqual(DHCP_HOSTC, dhcp_agents_2['agents'][0]['host'])

    def test_network_scheduling_on_port_creation(self):
        with self.subnet() as subnet:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                subnet['subnet']['network_id'])
            result0 = len(dhcp_agents['agents'])
            self._register_agent_states()
            with self.port(subnet=subnet,
                           device_owner="compute:test:" + DHCP_HOSTA) as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
                result1 = len(dhcp_agents['agents'])
        self.assertEqual(0, result0)
        self.assertEqual(1, result1)

    def test_network_scheduler_with_disabled_agent(self):
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        with self.port() as port1:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port1['port']['network_id'])
        self.assertEqual(1, len(dhcp_agents['agents']))
        agents = self._list_agents()
        self._disable_agent(agents['agents'][0]['id'])
        with self.port() as port2:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port2['port']['network_id'])
        self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_scheduler_with_down_agent(self):
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        is_agent_down_str = 'quantum.db.agents_db.AgentDbMixin.is_agent_down'
        with mock.patch(is_agent_down_str) as mock_is_agent_down:
            mock_is_agent_down.return_value = False
            with self.port() as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
            self.assertEqual(1, len(dhcp_agents['agents']))
        with mock.patch(is_agent_down_str) as mock_is_agent_down:
            mock_is_agent_down.return_value = True
            with self.port() as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
            self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_scheduler_with_hosted_network(self):
        plugin = manager.QuantumManager.get_plugin()
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        with self.port() as port1:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port1['port']['network_id'])
            self.assertEqual(1, len(dhcp_agents['agents']))
        with mock.patch.object(plugin,
                               'get_dhcp_agents_hosting_networks',
                               autospec=True) as mock_hosting_agents:

            mock_hosting_agents.return_value = plugin.get_agents_db(
                self.adminContext)
            with self.network('test', do_delete=False) as net1:
                pass
            with self.subnet(network=net1,
                             cidr='10.0.1.0/24',
                             do_delete=False) as subnet1:
                pass
            with self.port(subnet=subnet1, no_delete=True) as port2:
                pass
        dhcp_agents = self._list_dhcp_agents_hosting_network(
            port2['port']['network_id'])
        self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_policy(self):
        with self.network() as net1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._list_networks_hosted_by_dhcp_agent(
                hosta_id, expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._add_network_to_dhcp_agent(
                hosta_id, net1['network']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._add_network_to_dhcp_agent(hosta_id,
                                            net1['network']['id'])
            self._remove_network_from_dhcp_agent(
                hosta_id, net1['network']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._list_dhcp_agents_hosting_network(
                net1['network']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)

    def test_network_add_to_dhcp_agent(self):
        with self.network() as net1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            num_before_add = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
            self._add_network_to_dhcp_agent(hosta_id,
                                            net1['network']['id'])
            num_after_add = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
        self.assertEqual(0, num_before_add)
        self.assertEqual(1, num_after_add)

    def test_network_remove_from_dhcp_agent(self):
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                      DHCP_HOSTA)
        with self.port() as port1:
            num_before_remove = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
            self._remove_network_from_dhcp_agent(hosta_id,
                                                 port1['port']['network_id'])
            num_after_remove = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
        self.assertEqual(1, num_before_remove)
        self.assertEqual(0, num_after_remove)

    def test_router_auto_schedule_with_hosted(self):
        with self.router() as router:
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            self._register_agent_states()
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTB)
            l3_agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
        self.assertEqual(1, len(l3_agents['agents']))
        self.assertEqual(L3_HOSTA, l3_agents['agents'][0]['host'])

    def test_router_auto_schedule_with_hosted_2(self):
        # one agent hosts one router
        l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
        l3_hosta = {
            'binary': 'quantum-l3-agent',
            'host': L3_HOSTA,
            'topic': 'L3_AGENT',
            'configurations': {'use_namespaces': True,
                               'router_id': None,
                               'handle_internal_only_routers':
                               True,
                               'gateway_external_network_id':
                               None,
                               'interface_driver': 'interface_driver',
                               },
            'agent_type': constants.AGENT_TYPE_L3}
        l3_hostb = copy.deepcopy(l3_hosta)
        l3_hostb['host'] = L3_HOSTB
        with self.router() as router1:
            self._register_one_agent_state(l3_hosta)
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            with self.router() as router2:
                self._register_one_agent_state(l3_hostb)
                l3_rpc.sync_routers(self.adminContext, host=L3_HOSTB)
                l3_agents_1 = self._list_l3_agents_hosting_router(
                    router1['router']['id'])
                l3_agents_2 = self._list_l3_agents_hosting_router(
                    router2['router']['id'])
                hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
                num_hosta_routers = len(hosta_routers['routers'])
                hostb_id = self._get_agent_id(
                    constants.AGENT_TYPE_L3,
                    L3_HOSTB)
                hostb_routers = self._list_routers_hosted_by_l3_agent(hostb_id)
                num_hostc_routers = len(hostb_routers['routers'])

        self.assertEqual(1, num_hosta_routers)
        self.assertEqual(1, num_hostc_routers)
        self.assertEqual(1, len(l3_agents_1['agents']))
        self.assertEqual(1, len(l3_agents_2['agents']))
        self.assertEqual(L3_HOSTA, l3_agents_1['agents'][0]['host'])
        self.assertEqual(L3_HOSTB, l3_agents_2['agents'][0]['host'])

    def test_router_auto_schedule_with_disabled(self):
        with contextlib.nested(self.router(),
                               self.router()):
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            hostb_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTB)
            self._disable_agent(hosta_id)
            # first agent will not host router since it is disabled
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            # second agent will host all the routers since first is disabled.
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTB)
            hostb_routers = self._list_routers_hosted_by_l3_agent(hostb_id)
            num_hostb_routers = len(hostb_routers['routers'])
            hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
            num_hosta_routers = len(hosta_routers['routers'])
        self.assertEqual(2, num_hostb_routers)
        self.assertEqual(0, num_hosta_routers)

    def test_router_auto_schedule_with_candidates(self):
        l3_hosta = {
            'binary': 'quantum-l3-agent',
            'host': L3_HOSTA,
            'topic': 'L3_AGENT',
            'configurations': {'use_namespaces': False,
                               'router_id': None,
                               'handle_internal_only_routers':
                               True,
                               'gateway_external_network_id':
                               None,
                               'interface_driver': 'interface_driver',
                               },
            'agent_type': constants.AGENT_TYPE_L3}
        with contextlib.nested(self.router(),
                               self.router()) as (router1, router2):
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            l3_hosta['configurations']['router_id'] = router1['router']['id']
            self._register_one_agent_state(l3_hosta)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
            num_hosta_routers = len(hosta_routers['routers'])
            l3_agents_1 = self._list_l3_agents_hosting_router(
                router1['router']['id'])
            l3_agents_2 = self._list_l3_agents_hosting_router(
                router2['router']['id'])
        # L3 agent will host only the compatible router.
        self.assertEqual(1, num_hosta_routers)
        self.assertEqual(1, len(l3_agents_1['agents']))
        self.assertEqual(0, len(l3_agents_2['agents']))

    def test_router_schedule_with_candidates(self):
        l3_hosta = {
            'binary': 'quantum-l3-agent',
            'host': L3_HOSTA,
            'topic': 'L3_AGENT',
            'configurations': {'use_namespaces': False,
                               'router_id': None,
                               'handle_internal_only_routers':
                               True,
                               'gateway_external_network_id':
                               None,
                               'interface_driver': 'interface_driver',
                               },
            'agent_type': constants.AGENT_TYPE_L3}
        with contextlib.nested(self.router(),
                               self.router(),
                               self.subnet(),
                               self.subnet(cidr='10.0.3.0/24')) as (router1,
                                                                    router2,
                                                                    subnet1,
                                                                    subnet2):
            l3_hosta['configurations']['router_id'] = router1['router']['id']
            self._register_one_agent_state(l3_hosta)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._router_interface_action('add',
                                          router1['router']['id'],
                                          subnet1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          router2['router']['id'],
                                          subnet2['subnet']['id'],
                                          None)
            hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
            num_hosta_routers = len(hosta_routers['routers'])
            l3_agents_1 = self._list_l3_agents_hosting_router(
                router1['router']['id'])
            l3_agents_2 = self._list_l3_agents_hosting_router(
                router2['router']['id'])
            # safe cleanup
            self._router_interface_action('remove',
                                          router1['router']['id'],
                                          subnet1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          router2['router']['id'],
                                          subnet2['subnet']['id'],
                                          None)

        # L3 agent will host only the compatible router.
        self.assertEqual(1, num_hosta_routers)
        self.assertEqual(1, len(l3_agents_1['agents']))
        self.assertEqual(0, len(l3_agents_2['agents']))

    def test_router_without_l3_agents(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            data = {'router': {'tenant_id': uuidutils.generate_uuid()}}
            data['router']['name'] = 'router1'
            data['router']['external_gateway_info'] = {
                'network_id': s['subnet']['network_id']}
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            l3agents = (
                self.agentscheduler_dbMinxin.get_l3_agents_hosting_routers(
                    self.adminContext, [router['router']['id']]))
            self._delete('routers', router['router']['id'])
        self.assertEqual(0, len(l3agents))

    def test_router_sync_data(self):
        with contextlib.nested(self.subnet(),
                               self.subnet(cidr='10.0.2.0/24'),
                               self.subnet(cidr='10.0.3.0/24')) as (
                                   s1, s2, s3):
            self._register_agent_states()
            self._set_net_external(s1['subnet']['network_id'])
            data = {'router': {'tenant_id': uuidutils.generate_uuid()}}
            data['router']['name'] = 'router1'
            data['router']['external_gateway_info'] = {
                'network_id': s1['subnet']['network_id']}
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            self._router_interface_action('add',
                                          router['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          router['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            l3agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
            self.assertEqual(1, len(l3agents['agents']))
            agents = self._list_agents()
            another_l3_agent_id = None
            another_l3_agent_host = None
            default = l3agents['agents'][0]['id']
            for com in agents['agents']:
                if (com['id'] != default and
                    com['agent_type'] == constants.AGENT_TYPE_L3):
                    another_l3_agent_id = com['id']
                    another_l3_agent_host = com['host']
                    break
            self.assertTrue(another_l3_agent_id is not None)
            self._add_router_to_l3_agent(another_l3_agent_id,
                                         router['router']['id'],
                                         expected_code=exc.HTTPConflict.code)
            self._remove_router_from_l3_agent(default,
                                              router['router']['id'])
            self._add_router_to_l3_agent(another_l3_agent_id,
                                         router['router']['id'])
            l3agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
            self.assertEqual(another_l3_agent_host,
                             l3agents['agents'][0]['host'])
            self._remove_router_from_l3_agent(another_l3_agent_id,
                                              router['router']['id'])
            self._router_interface_action('remove',
                                          router['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            l3agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
            self.assertEqual(1,
                             len(l3agents['agents']))
            self._router_interface_action('remove',
                                          router['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            self._delete('routers', router['router']['id'])

    def test_router_add_to_l3_agent(self):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            num_before_add = len(
                self._list_routers_hosted_by_l3_agent(
                    hosta_id)['routers'])
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            hostb_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTB)
            self._add_router_to_l3_agent(hostb_id,
                                         router1['router']['id'],
                                         expected_code=exc.HTTPConflict.code)
            num_after_add = len(
                self._list_routers_hosted_by_l3_agent(
                    hosta_id)['routers'])
        self.assertEqual(0, num_before_add)
        self.assertEqual(1, num_after_add)

    def test_router_policy(self):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._list_routers_hosted_by_l3_agent(
                hosta_id, expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._add_router_to_l3_agent(
                hosta_id, router1['router']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._add_router_to_l3_agent(
                hosta_id, router1['router']['id'])
            self._remove_router_from_l3_agent(
                hosta_id, router1['router']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)
            self._list_l3_agents_hosting_router(
                router1['router']['id'],
                expected_code=exc.HTTPForbidden.code,
                admin_context=False)


class OvsDhcpAgentNotifierTestCase(test_l3_plugin.L3NatTestCaseMixin,
                                   test_agent_ext_plugin.AgentDBTestMixIn,
                                   AgentSchedulerTestMixIn,
                                   test_plugin.QuantumDbPluginV2TestCase):
    plugin_str = ('quantum.plugins.openvswitch.'
                  'ovs_quantum_plugin.OVSQuantumPluginV2')

    def setUp(self):
        self.dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.dhcp_notifier_cls_p = mock.patch(
            'quantum.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI')
        self.dhcp_notifier_cls = self.dhcp_notifier_cls_p.start()
        self.dhcp_notifier_cls.return_value = self.dhcp_notifier
        super(OvsDhcpAgentNotifierTestCase, self).setUp(self.plugin_str)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        self.addCleanup(self.dhcp_notifier_cls_p.stop)

    def test_network_add_to_dhcp_agent_notification(self):
        with mock.patch.object(self.dhcp_notifier, 'cast') as mock_dhcp:
            with self.network() as net1:
                network_id = net1['network']['id']
                self._register_agent_states()
                hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                              DHCP_HOSTA)
                self._add_network_to_dhcp_agent(hosta_id,
                                                network_id)
            mock_dhcp.assert_called_with(
                mock.ANY,
                self.dhcp_notifier.make_msg(
                    'network_create_end',
                    payload={'network': {'id': network_id}}),
                topic='dhcp_agent.' + DHCP_HOSTA)

    def test_network_remove_from_dhcp_agent_notification(self):
        with self.network(do_delete=False) as net1:
            network_id = net1['network']['id']
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._add_network_to_dhcp_agent(hosta_id,
                                            network_id)
        with mock.patch.object(self.dhcp_notifier, 'cast') as mock_dhcp:
            self._remove_network_from_dhcp_agent(hosta_id,
                                                 network_id)
            mock_dhcp.assert_called_with(
                mock.ANY,
                self.dhcp_notifier.make_msg(
                    'network_delete_end',
                    payload={'network_id': network_id}),
                topic='dhcp_agent.' + DHCP_HOSTA)

    def test_agent_updated_dhcp_agent_notification(self):
        with mock.patch.object(self.dhcp_notifier, 'cast') as mock_dhcp:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            mock_dhcp.assert_called_with(
                mock.ANY, self.dhcp_notifier.make_msg(
                    'agent_updated',
                    payload={'admin_state_up': False}),
                topic='dhcp_agent.' + DHCP_HOSTA)

    def test_network_port_create_notification(self):
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'dhcp_agent',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        with mock.patch.object(self.dhcp_notifier, 'cast') as mock_dhcp:
            with self.network(do_delete=False) as net1:
                with self.subnet(network=net1,
                                 do_delete=False) as subnet1:
                    with self.port(subnet=subnet1, no_delete=True) as port:
                        network_id = port['port']['network_id']
            expected_calls = [
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'network_create_end',
                        payload={'network': {'id': network_id}}),
                    topic='dhcp_agent.' + DHCP_HOSTA),
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'port_create_end',
                        payload={'port': port['port']}),
                    topic='dhcp_agent.' + DHCP_HOSTA)]
            self.assertEqual(mock_dhcp.call_args_list, expected_calls)


class OvsL3AgentNotifierTestCase(test_l3_plugin.L3NatTestCaseMixin,
                                 test_agent_ext_plugin.AgentDBTestMixIn,
                                 AgentSchedulerTestMixIn,
                                 test_plugin.QuantumDbPluginV2TestCase):
    plugin_str = ('quantum.plugins.openvswitch.'
                  'ovs_quantum_plugin.OVSQuantumPluginV2')

    def setUp(self):
        self.dhcp_notifier_cls_p = mock.patch(
            'quantum.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI')
        self.dhcp_notifier = mock.Mock(name='dhcp_notifier')
        self.dhcp_notifier_cls = self.dhcp_notifier_cls_p.start()
        self.dhcp_notifier_cls.return_value = self.dhcp_notifier
        super(OvsL3AgentNotifierTestCase, self).setUp(self.plugin_str)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        self.addCleanup(self.dhcp_notifier_cls_p.stop)

    def test_router_add_to_l3_agent_notification(self):
        plugin = manager.QuantumManager.get_plugin()
        with mock.patch.object(plugin.l3_agent_notifier, 'cast') as mock_l3:
            with self.router() as router1:
                self._register_agent_states()
                hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                              L3_HOSTA)
                self._add_router_to_l3_agent(hosta_id,
                                             router1['router']['id'])
                routers = plugin.get_sync_data(self.adminContext,
                                               [router1['router']['id']])
            mock_l3.assert_called_with(
                mock.ANY,
                plugin.l3_agent_notifier.make_msg(
                    'router_added_to_agent',
                    payload=routers),
                topic='l3_agent.hosta')

    def test_router_remove_from_l3_agent_notification(self):
        plugin = manager.QuantumManager.get_plugin()
        with mock.patch.object(plugin.l3_agent_notifier, 'cast') as mock_l3:
            with self.router() as router1:
                self._register_agent_states()
                hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                              L3_HOSTA)
                self._add_router_to_l3_agent(hosta_id,
                                             router1['router']['id'])
                self._remove_router_from_l3_agent(hosta_id,
                                                  router1['router']['id'])
            mock_l3.assert_called_with(
                mock.ANY, plugin.l3_agent_notifier.make_msg(
                    'router_removed_from_agent',
                    payload={'router_id': router1['router']['id']}),
                topic='l3_agent.hosta')

    def test_agent_updated_l3_agent_notification(self):
        plugin = manager.QuantumManager.get_plugin()
        with mock.patch.object(plugin.l3_agent_notifier, 'cast') as mock_l3:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            mock_l3.assert_called_with(
                mock.ANY, plugin.l3_agent_notifier.make_msg(
                    'agent_updated',
                    payload={'admin_state_up': False}),
                topic='l3_agent.hosta')


class OvsAgentSchedulerTestCaseXML(OvsAgentSchedulerTestCase):
    fmt = 'xml'
