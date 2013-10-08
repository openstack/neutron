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
from oslo.config import cfg
from webob import exc

from neutron.api import extensions
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron import context
from neutron.db import agents_db
from neutron.db import dhcp_rpc_base
from neutron.db import l3_rpc_base
from neutron.extensions import agent
from neutron.extensions import dhcpagentscheduler
from neutron.extensions import l3agentscheduler
from neutron import manager
from neutron.openstack.common import timeutils
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as service_constants
from neutron.tests.unit import test_agent_ext_plugin
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extensions
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit.testlib_api import create_request
from neutron.wsgi import Serializer

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
                                     l3agentscheduler.L3_ROUTERS,
                                     self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_networks_hosted_by_dhcp_agent(self, agent_id,
                                            expected_code=exc.HTTPOk.code,
                                            admin_context=True):
        path = "/agents/%s/%s.%s" % (agent_id,
                                     dhcpagentscheduler.DHCP_NETS,
                                     self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_l3_agents_hosting_router(self, router_id,
                                       expected_code=exc.HTTPOk.code,
                                       admin_context=True):
        path = "/routers/%s/%s.%s" % (router_id,
                                      l3agentscheduler.L3_AGENTS,
                                      self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _list_dhcp_agents_hosting_network(self, network_id,
                                          expected_code=exc.HTTPOk.code,
                                          admin_context=True):
        path = "/networks/%s/%s.%s" % (network_id,
                                       dhcpagentscheduler.DHCP_AGENTS,
                                       self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _add_router_to_l3_agent(self, id, router_id,
                                expected_code=exc.HTTPCreated.code,
                                admin_context=True):
        path = "/agents/%s/%s.%s" % (id,
                                     l3agentscheduler.L3_ROUTERS,
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
                                     dhcpagentscheduler.DHCP_NETS,
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
                                        dhcpagentscheduler.DHCP_NETS,
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
                                        l3agentscheduler.L3_ROUTERS,
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
        for agent_data in agents['agents']:
            if (agent_data['agent_type'] == agent_type and
                agent_data['host'] == host):
                return agent_data['id']


class OvsAgentSchedulerTestCaseBase(test_l3_plugin.L3NatTestCaseMixin,
                                    test_agent_ext_plugin.AgentDBTestMixIn,
                                    AgentSchedulerTestMixIn,
                                    test_plugin.NeutronDbPluginV2TestCase):
    fmt = 'json'
    plugin_str = ('neutron.plugins.openvswitch.'
                  'ovs_neutron_plugin.OVSNeutronPluginV2')
    l3_plugin = None

    def setUp(self):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        if self.l3_plugin:
            service_plugins = {'l3_plugin_name': self.l3_plugin}
        else:
            service_plugins = None
        super(OvsAgentSchedulerTestCaseBase, self).setUp(
            self.plugin_str, service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        self.addCleanup(self.restore_attribute_map)
        self.l3agentscheduler_dbMinxin = (
            manager.NeutronManager.get_service_plugins().get(
                service_constants.L3_ROUTER_NAT))

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map


class OvsAgentSchedulerTestCase(OvsAgentSchedulerTestCaseBase):

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
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with contextlib.nested(self.subnet(),
                               self.subnet()):
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

    def test_network_auto_schedule_with_no_dhcp(self):
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with contextlib.nested(self.subnet(enable_dhcp=False),
                               self.subnet(enable_dhcp=False)):
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            self._disable_agent(hosta_id)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(0, num_hosta_nets)
        self.assertEqual(0, num_hostc_nets)

    def test_network_auto_schedule_with_multiple_agents(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with contextlib.nested(self.subnet(),
                               self.subnet()):
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(2, num_hosta_nets)
        self.assertEqual(2, num_hostc_nets)

    def test_network_auto_schedule_restart_dhcp_agent(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        with self.subnet() as sub1:
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                sub1['subnet']['network_id'])
        self.assertEqual(1, len(dhcp_agents['agents']))

    def test_network_auto_schedule_with_hosted(self):
        # one agent hosts all the networks, other hosts none
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with contextlib.nested(self.subnet(),
                               self.subnet()) as (sub1, sub2):
            dhcp_rpc = dhcp_rpc_base.DhcpRpcCallbackMixin()
            self._register_agent_states()
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            # second agent will not host the network since first has got it.
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTC)
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                sub1['subnet']['network_id'])
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
            'binary': 'neutron-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        dhcp_hostc = copy.deepcopy(dhcp_hosta)
        dhcp_hostc['host'] = DHCP_HOSTC
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet() as sub1:
            self._register_one_agent_state(dhcp_hosta)
            dhcp_rpc.get_active_networks(self.adminContext, host=DHCP_HOSTA)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            with self.subnet() as sub2:
                self._register_one_agent_state(dhcp_hostc)
                dhcp_rpc.get_active_networks(self.adminContext,
                                             host=DHCP_HOSTC)
                dhcp_agents_1 = self._list_dhcp_agents_hosting_network(
                    sub1['subnet']['network_id'])
                dhcp_agents_2 = self._list_dhcp_agents_hosting_network(
                    sub2['subnet']['network_id'])
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

    def test_network_ha_scheduling_on_port_creation(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
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
        self.assertEqual(2, result1)

    def test_network_ha_scheduling_on_port_creation_with_new_agent(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 3)
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
            self._register_one_dhcp_agent()
            with self.port(subnet=subnet,
                           device_owner="compute:test:" + DHCP_HOSTA) as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
                result2 = len(dhcp_agents['agents'])
        self.assertEqual(0, result0)
        self.assertEqual(2, result1)
        self.assertEqual(3, result2)

    def test_network_scheduler_with_disabled_agent(self):
        dhcp_hosta = {
            'binary': 'neutron-dhcp-agent',
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
            'binary': 'neutron-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        self._register_one_agent_state(dhcp_hosta)
        is_agent_down_str = 'neutron.db.agents_db.AgentDbMixin.is_agent_down'
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
        plugin = manager.NeutronManager.get_plugin()
        dhcp_hosta = {
            'binary': 'neutron-dhcp-agent',
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
            'binary': 'neutron-dhcp-agent',
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

    def test_router_auto_schedule_with_invalid_router(self):
        with self.router() as router:
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            self._register_agent_states()
        # deleted router
        ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                    router_ids=[router['router']['id']])
        self.assertFalse(ret_a)
        # non-existent router
        ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                    router_ids=[uuidutils.generate_uuid()])
        self.assertFalse(ret_a)

    def test_router_auto_schedule_with_hosted(self):
        with self.router() as router:
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            self._register_agent_states()
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            ret_b = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTB)
            l3_agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
            self.assertEqual(1, len(ret_a))
            self.assertIn(router['router']['id'], [r['id'] for r in ret_a])
            self.assertFalse(len(ret_b))
        self.assertEqual(1, len(l3_agents['agents']))
        self.assertEqual(L3_HOSTA, l3_agents['agents'][0]['host'])

    def test_router_auto_schedule_restart_l3_agent(self):
        with self.router():
            l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
            self._register_agent_states()
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)

    def test_router_auto_schedule_with_hosted_2(self):
        # one agent hosts one router
        l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
        l3_hosta = {
            'binary': 'neutron-l3-agent',
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
            'binary': 'neutron-l3-agent',
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

    def test_rpc_sync_routers(self):
        l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
        self._register_agent_states()

        # No routers
        ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
        self.assertEqual(0, len(ret_a))

        with contextlib.nested(self.router(),
                               self.router(),
                               self.router()) as routers:
            router_ids = [r['router']['id'] for r in routers]

            # Get all routers
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA)
            self.assertEqual(3, len(ret_a))
            self.assertEqual(set(router_ids), set([r['id'] for r in ret_a]))

            # Get all routers (router_ids=None)
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                        router_ids=None)
            self.assertEqual(3, len(ret_a))
            self.assertEqual(set(router_ids), set([r['id'] for r in ret_a]))

            # Get router2 only
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                        router_ids=[router_ids[1]])
            self.assertEqual(1, len(ret_a))
            self.assertIn(router_ids[1], [r['id'] for r in ret_a])

            # Get router1 and router3
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                        router_ids=[router_ids[0],
                                                    router_ids[2]])
            self.assertEqual(2, len(ret_a))
            self.assertIn(router_ids[0], [r['id'] for r in ret_a])
            self.assertIn(router_ids[2], [r['id'] for r in ret_a])

    def test_router_auto_schedule_for_specified_routers(self):

        def _sync_router_with_ids(router_ids, exp_synced, exp_hosted, host_id):
            ret_a = l3_rpc.sync_routers(self.adminContext, host=L3_HOSTA,
                                        router_ids=router_ids)
            self.assertEqual(exp_synced, len(ret_a))
            for r in router_ids:
                self.assertIn(r, [r['id'] for r in ret_a])
            host_routers = self._list_routers_hosted_by_l3_agent(host_id)
            num_host_routers = len(host_routers['routers'])
            self.assertEqual(exp_hosted, num_host_routers)

        l3_rpc = l3_rpc_base.L3RpcCallbackMixin()
        self._register_agent_states()
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3, L3_HOSTA)

        with contextlib.nested(self.router(), self.router(),
                               self.router(), self.router()) as routers:
            router_ids = [r['router']['id'] for r in routers]
            # Sync router1 (router1 is scheduled)
            _sync_router_with_ids([router_ids[0]], 1, 1, hosta_id)
            # Sync router1 only (no router is scheduled)
            _sync_router_with_ids([router_ids[0]], 1, 1, hosta_id)
            # Schedule router2
            _sync_router_with_ids([router_ids[1]], 1, 2, hosta_id)
            # Sync router2 and router4 (router4 is scheduled)
            _sync_router_with_ids([router_ids[1], router_ids[3]],
                                  2, 3, hosta_id)
            # Sync all routers (router3 is scheduled)
            _sync_router_with_ids(router_ids, 4, 4, hosta_id)

    def test_router_schedule_with_candidates(self):
        l3_hosta = {
            'binary': 'neutron-l3-agent',
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
                self.l3agentscheduler_dbMinxin.get_l3_agents_hosting_routers(
                    self.adminContext, [router['router']['id']]))
            self._delete('routers', router['router']['id'])
        self.assertEqual(0, len(l3agents))

    def test_router_sync_data(self):
        with contextlib.nested(
            self.subnet(),
            self.subnet(cidr='10.0.2.0/24'),
            self.subnet(cidr='10.0.3.0/24')
        ) as (s1, s2, s3):
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
            self.assertIsNotNone(another_l3_agent_id)
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

    def test_router_add_to_l3_agent_two_times(self):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'],
                                         expected_code=exc.HTTPConflict.code)

    def test_router_add_to_two_l3_agents(self):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            hostb_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTB)
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            self._add_router_to_l3_agent(hostb_id,
                                         router1['router']['id'],
                                         expected_code=exc.HTTPConflict.code)

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
                                   test_plugin.NeutronDbPluginV2TestCase):
    plugin_str = ('neutron.plugins.openvswitch.'
                  'ovs_neutron_plugin.OVSNeutronPluginV2')

    def setUp(self):
        self.dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.dhcp_notifier_cls_p = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI')
        self.dhcp_notifier_cls = self.dhcp_notifier_cls_p.start()
        self.dhcp_notifier_cls.return_value = self.dhcp_notifier
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        super(OvsDhcpAgentNotifierTestCase, self).setUp(self.plugin_str)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        self.addCleanup(self.dhcp_notifier_cls_p.stop)
        self.addCleanup(self.restore_attribute_map)

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

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

    def _network_port_create(
        self, hosts, gateway=attributes.ATTR_NOT_SPECIFIED, owner=None):
        for host in hosts:
            self._register_one_agent_state(
                {'binary': 'neutron-dhcp-agent',
                 'host': host,
                 'topic': 'dhcp_agent',
                 'configurations': {'dhcp_driver': 'dhcp_driver',
                                    'use_namespaces': True, },
                 'agent_type': constants.AGENT_TYPE_DHCP})
        with mock.patch.object(self.dhcp_notifier, 'cast') as mock_dhcp:
            with self.network(do_delete=False) as net1:
                with self.subnet(network=net1,
                                 gateway_ip=gateway,
                                 do_delete=False) as subnet1:
                    if owner:
                        with self.port(subnet=subnet1,
                                       no_delete=True,
                                       device_owner=owner) as port:
                            return [mock_dhcp, net1, subnet1, port]
                    else:
                        with self.port(subnet=subnet1,
                                       no_delete=True) as port:
                            return [mock_dhcp, net1, subnet1, port]

    def _notification_mocks(self, hosts, mock_dhcp, net, subnet, port):
        host_calls = {}
        for host in hosts:
            expected_calls = [
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'network_create_end',
                        payload={'network': {'id': net['network']['id']}}),
                    topic='dhcp_agent.' + host),
                mock.call(
                    mock.ANY,
                    self.dhcp_notifier.make_msg(
                        'port_create_end',
                        payload={'port': port['port']}),
                    topic='dhcp_agent.' + host)]
            host_calls[host] = expected_calls
        return host_calls

    def test_network_port_create_notification(self):
        hosts = [DHCP_HOSTA]
        [mock_dhcp, net, subnet, port] = self._network_port_create(hosts)
        expected_calls = self._notification_mocks(hosts, mock_dhcp,
                                                  net, subnet, port)
        self.assertEqual(expected_calls[DHCP_HOSTA], mock_dhcp.call_args_list)

    def test_network_ha_port_create_notification(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        hosts = [DHCP_HOSTA, DHCP_HOSTC]
        [mock_dhcp, net, subnet, port] = self._network_port_create(hosts)
        expected_calls = self._notification_mocks(hosts, mock_dhcp,
                                                  net, subnet, port)
        for expected in expected_calls[DHCP_HOSTA]:
            self.assertIn(expected, mock_dhcp.call_args_list)
        for expected in expected_calls[DHCP_HOSTC]:
            self.assertIn(expected, mock_dhcp.call_args_list)


class OvsL3AgentNotifierTestCase(test_l3_plugin.L3NatTestCaseMixin,
                                 test_agent_ext_plugin.AgentDBTestMixIn,
                                 AgentSchedulerTestMixIn,
                                 test_plugin.NeutronDbPluginV2TestCase):
    plugin_str = ('neutron.plugins.openvswitch.'
                  'ovs_neutron_plugin.OVSNeutronPluginV2')
    l3_plugin = None

    def setUp(self):
        self.dhcp_notifier_cls_p = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI')
        self.dhcp_notifier = mock.Mock(name='dhcp_notifier')
        self.dhcp_notifier_cls = self.dhcp_notifier_cls_p.start()
        self.dhcp_notifier_cls.return_value = self.dhcp_notifier
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        if self.l3_plugin:
            service_plugins = {'l3_plugin_name': self.l3_plugin}
        else:
            service_plugins = None
        super(OvsL3AgentNotifierTestCase, self).setUp(
            self.plugin_str, service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        self.addCleanup(self.dhcp_notifier_cls_p.stop)
        self.addCleanup(self.restore_attribute_map)

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_router_add_to_l3_agent_notification(self):
        plugin = manager.NeutronManager.get_plugin()
        l3_notifier = plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(l3_notifier, 'cast') as mock_l3:
            with self.router() as router1:
                self._register_agent_states()
                hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                              L3_HOSTA)
                self._add_router_to_l3_agent(hosta_id,
                                             router1['router']['id'])
                routers = [router1['router']['id']]
            mock_l3.assert_called_with(
                mock.ANY,
                l3_notifier.make_msg(
                    'router_added_to_agent',
                    payload=routers),
                topic='l3_agent.hosta')

    def test_router_remove_from_l3_agent_notification(self):
        plugin = manager.NeutronManager.get_plugin()
        l3_notifier = plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(l3_notifier, 'cast') as mock_l3:
            with self.router() as router1:
                self._register_agent_states()
                hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                              L3_HOSTA)
                self._add_router_to_l3_agent(hosta_id,
                                             router1['router']['id'])
                self._remove_router_from_l3_agent(hosta_id,
                                                  router1['router']['id'])
            mock_l3.assert_called_with(
                mock.ANY, l3_notifier.make_msg(
                    'router_removed_from_agent',
                    payload={'router_id': router1['router']['id']}),
                topic='l3_agent.hosta')

    def test_agent_updated_l3_agent_notification(self):
        plugin = manager.NeutronManager.get_plugin()
        l3_notifier = plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(l3_notifier, 'cast') as mock_l3:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            mock_l3.assert_called_with(
                mock.ANY, l3_notifier.make_msg(
                    'agent_updated', payload={'admin_state_up': False}),
                topic='l3_agent.hosta')


class OvsAgentSchedulerTestCaseXML(OvsAgentSchedulerTestCase):
    fmt = 'xml'
