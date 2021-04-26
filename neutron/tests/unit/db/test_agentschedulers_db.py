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

import copy
import datetime

import mock
from neutron_lib.api.definitions import dhcpagentscheduler as das_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.tests.unit import fake_notifier
from oslo_config import cfg
from oslo_db import exception as db_exc
import oslo_messaging
from oslo_utils import uuidutils
from webob import exc

from neutron.api import extensions
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import l3_rpc
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db.models import agent as agent_model
from neutron.extensions import l3agentscheduler
from neutron.objects import agent as ag_obj
from neutron.objects import l3agent as rb_obj
from neutron.tests.common import helpers
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_agent
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api
from neutron import wsgi


L3_HOSTA = 'hosta'
DHCP_HOSTA = 'hosta'
L3_HOSTB = 'hostb'
DHCP_HOSTC = 'hostc'
DHCP_HOSTD = 'hostd'

DEVICE_OWNER_COMPUTE = ''.join([constants.DEVICE_OWNER_COMPUTE_PREFIX,
                                'test:',
                                DHCP_HOSTA])


class AgentSchedulerTestMixIn(object):

    block_dhcp_notifier = False

    def _request_list(self, path, admin_context=True,
                      expected_code=exc.HTTPOk.code):
        req = self._path_req(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        return self.deserialize(self.fmt, res)

    def _path_req(self, path, method='GET', data=None,
                  query_string=None,
                  admin_context=True):
        content_type = 'application/%s' % self.fmt
        body = None
        if data is not None:  # empty dict is valid
            body = wsgi.Serializer().serialize(data, content_type)
        if admin_context:
            return testlib_api.create_request(
                path, body, content_type, method, query_string=query_string)
        else:
            return testlib_api.create_request(
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
                                     das_apidef.DHCP_NETS,
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
                                       das_apidef.DHCP_AGENTS,
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
        self.assertEqual(expected_code, res.status_int)

    def _add_network_to_dhcp_agent(self, id, network_id,
                                   expected_code=exc.HTTPCreated.code,
                                   admin_context=True):
        path = "/agents/%s/%s.%s" % (id,
                                     das_apidef.DHCP_NETS,
                                     self.fmt)
        req = self._path_create_request(path,
                                        {'network_id': network_id},
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)

    def _remove_network_from_dhcp_agent(self, id, network_id,
                                        expected_code=exc.HTTPNoContent.code,
                                        admin_context=True):
        path = "/agents/%s/%s/%s.%s" % (id,
                                        das_apidef.DHCP_NETS,
                                        network_id,
                                        self.fmt)
        req = self._path_delete_request(path,
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)

    def _remove_router_from_l3_agent(self, id, router_id,
                                     expected_code=exc.HTTPNoContent.code,
                                     admin_context=True):
        path = "/agents/%s/%s/%s.%s" % (id,
                                        l3agentscheduler.L3_ROUTERS,
                                        router_id,
                                        self.fmt)
        req = self._path_delete_request(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)

    def _assert_notify(self, notifications, expected_event_type):
        event_types = [event['event_type'] for event in notifications]
        self.assertIn(expected_event_type, event_types)

    def test_agent_registration_bad_timestamp(self):
        callback = agents_db.AgentExtRpcCallback()
        delta_time = datetime.datetime.now() - datetime.timedelta(days=1)
        str_time = delta_time.strftime('%Y-%m-%dT%H:%M:%S.%f')
        callback.report_state(
            self.adminContext,
            agent_state={
                'agent_state': helpers._get_dhcp_agent_dict(DHCP_HOSTA)},
            time=str_time)

    def test_agent_registration_invalid_timestamp_allowed(self):
        callback = agents_db.AgentExtRpcCallback()
        utc_time = datetime.datetime.utcnow()
        delta_time = utc_time - datetime.timedelta(seconds=10)
        str_time = delta_time.strftime('%Y-%m-%dT%H:%M:%S.%f')
        callback.report_state(
            self.adminContext,
            agent_state={
                'agent_state': helpers._get_dhcp_agent_dict(DHCP_HOSTA)},
            time=str_time)

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


class OvsAgentSchedulerTestCaseBase(test_l3.L3NatTestCaseMixin,
                                    test_agent.AgentDBTestMixIn,
                                    AgentSchedulerTestMixIn,
                                    test_plugin.NeutronDbPluginV2TestCase):
    fmt = 'json'
    l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                 'TestL3NatAgentSchedulingServicePlugin')

    def setUp(self):
        if self.l3_plugin:
            service_plugins = {
                'l3_plugin_name': self.l3_plugin,
                'flavors_plugin_name': 'neutron.services.flavors.'
                                       'flavors_plugin.FlavorsPlugin'
            }
        else:
            service_plugins = None
        # NOTE(ivasilevskaya) mocking this way allows some control over mocked
        # client like further method mocking with asserting calls
        self.client_mock = mock.MagicMock(name="mocked client")
        mock.patch.object(
            n_rpc, 'get_client').start().return_value = self.client_mock
        super(OvsAgentSchedulerTestCaseBase, self).setUp(
            'ml2', service_plugins=service_plugins)
        mock.patch.object(
            self.plugin, 'filter_hosts_with_network_access',
            side_effect=lambda context, network_id, hosts: hosts).start()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        self.l3plugin = directory.get_plugin(plugin_constants.L3)
        self.l3_notify_p = mock.patch(
            'neutron.extensions.l3agentscheduler.notify')
        self.patched_l3_notify = self.l3_notify_p.start()
        self.l3_periodic_p = mock.patch('neutron.db.l3_agentschedulers_db.'
                                        'L3AgentSchedulerDbMixin.'
                                        'add_periodic_l3_agent_status_check')
        self.patched_l3_periodic = self.l3_periodic_p.start()
        self.dhcp_notify_p = mock.patch(
            'neutron.extensions.dhcpagentscheduler.notify')
        self.patched_dhcp_notify = self.dhcp_notify_p.start()


class OvsAgentSchedulerTestCase(OvsAgentSchedulerTestCaseBase):

    def test_report_states(self):
        self._register_agent_states()
        agents = self._list_agents()
        self.assertEqual(4, len(agents['agents']))

    def test_list_router_ids_on_host_no_l3_agent(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self.assertEqual(
            [],
            l3_rpc_cb.get_router_ids(self.adminContext, host="fake host"))

    def test_network_scheduling_on_network_creation(self):
        self._register_agent_states()
        with self.network() as net:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                net['network']['id'])
        self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_auto_schedule_with_disabled(self):
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet(), self.subnet():
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            self._disable_agent(hosta_id)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            # second agent will host all the networks since first is disabled.
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(0, num_hosta_nets)
        self.assertEqual(2, num_hostc_nets)

    def test_network_auto_schedule_with_no_dhcp(self):
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False), self.subnet(enable_dhcp=False):
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            self._disable_agent(hosta_id)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(0, num_hosta_nets)
        self.assertEqual(0, num_hostc_nets)

    def test_network_auto_schedule_with_multiple_agents(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet(), self.subnet():
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
        self.assertEqual(2, num_hosta_nets)
        self.assertEqual(2, num_hostc_nets)

    def test_network_auto_schedule_restart_dhcp_agent(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 2)
        with self.subnet() as sub1:
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                sub1['subnet']['network_id'])
        self.assertEqual(1, len(dhcp_agents['agents']))

    def test_network_auto_schedule_with_hosted(self):
        # one agent hosts all the networks, other hosts none
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet() as sub1, self.subnet():
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            # second agent will not host the network since first has got it.
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTC)
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
        dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
        cfg.CONF.set_override('allow_overlapping_ips', True)
        with self.subnet() as sub1:
            helpers.register_dhcp_agent(DHCP_HOSTA)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            with self.subnet() as sub2:
                helpers.register_dhcp_agent(DHCP_HOSTC)
                dhcp_rpc_cb.get_active_networks_info(self.adminContext,
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
                           device_owner=DEVICE_OWNER_COMPUTE) as port:
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
                           device_owner=DEVICE_OWNER_COMPUTE) as port:
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
                           device_owner=DEVICE_OWNER_COMPUTE) as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
                result1 = len(dhcp_agents['agents'])
            helpers.register_dhcp_agent('host1')
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE) as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
                result2 = len(dhcp_agents['agents'])
        self.assertEqual(0, result0)
        self.assertEqual(2, result1)
        self.assertEqual(3, result2)

    def test_network_scheduler_with_disabled_agent(self):
        helpers.register_dhcp_agent(DHCP_HOSTA)
        with self.port() as port1:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port1['port']['network_id'])
        self._delete('ports', port1['port']['id'])
        self._delete('networks', port1['port']['network_id'])
        self.assertEqual(1, len(dhcp_agents['agents']))
        agents = self._list_agents()
        self._disable_agent(agents['agents'][0]['id'])
        with self.port() as port2:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port2['port']['network_id'])
        self._delete('ports', port2['port']['id'])
        self.assertEqual(0, len(dhcp_agents['agents']))

    def test_is_eligible_agent(self):
        agent_startup = ('neutron.db.agentschedulers_db.'
                         'DhcpAgentSchedulerDbMixin.agent_starting_up')
        is_eligible_agent = ('neutron.db.agentschedulers_db.'
                             'AgentSchedulerDbMixin.is_eligible_agent')
        dhcp_mixin = agentschedulers_db.DhcpAgentSchedulerDbMixin()
        with mock.patch(agent_startup) as startup,\
                mock.patch(is_eligible_agent) as elig:
            tests = [(True, True),
                     (True, False),
                     (False, True),
                     (False, False)]
            for rv1, rv2 in tests:
                startup.return_value = rv1
                elig.return_value = rv2
                self.assertEqual(rv1 or rv2,
                                 dhcp_mixin.is_eligible_agent(None,
                                                              None, None))

    def test_network_scheduler_with_down_agent(self):
        helpers.register_dhcp_agent(DHCP_HOSTA)
        eligible_agent_str = ('neutron.db.agentschedulers_db.'
                              'DhcpAgentSchedulerDbMixin.is_eligible_agent')
        with mock.patch(eligible_agent_str) as eligible_agent:
            eligible_agent.return_value = True
            with self.port() as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
            self._delete('ports', port['port']['id'])
            self._delete('networks', port['port']['network_id'])
            self.assertEqual(1, len(dhcp_agents['agents']))

        with mock.patch(eligible_agent_str) as eligible_agent:
            eligible_agent.return_value = False
            with self.port() as port:
                dhcp_agents = self._list_dhcp_agents_hosting_network(
                    port['port']['network_id'])
            self._delete('ports', port['port']['id'])
            self.assertEqual(0, len(dhcp_agents['agents']))

    def test_network_scheduler_with_hosted_network(self):
        plugin = directory.get_plugin()
        helpers.register_dhcp_agent(DHCP_HOSTA)
        with self.port() as port1:
            dhcp_agents = self._list_dhcp_agents_hosting_network(
                port1['port']['network_id'])
            self.assertEqual(1, len(dhcp_agents['agents']))
        with mock.patch.object(plugin,
                               'get_dhcp_agents_hosting_networks',
                               autospec=True) as mock_hosting_agents:

            mock_hosting_agents.return_value = plugin.get_agent_objects(
                self.adminContext)
            with self.network('test') as net1:
                pass
            with self.subnet(network=net1,
                             cidr='10.0.1.0/24') as subnet1:
                pass
            with self.port(subnet=subnet1) as port2:
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

    def _test_network_add_to_dhcp_agent(self, admin_state_up=True):
        with self.network() as net1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            if not admin_state_up:
                self._set_agent_admin_state_up(DHCP_HOSTA, False)
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

    def test_network_add_to_dhcp_agent(self):
        self._test_network_add_to_dhcp_agent()

    def test_network_add_to_dhcp_agent_with_admin_state_down(self):
        cfg.CONF.set_override(
            'enable_services_on_agents_with_admin_state_down', True)
        self._test_network_add_to_dhcp_agent(admin_state_up=False)

    def _test_network_remove_from_dhcp_agent(self,
                                             concurrent_port_delete=False):
        agent = helpers.register_dhcp_agent(DHCP_HOSTA)
        hosta_id = agent.id
        with self.port(device_owner=constants.DEVICE_OWNER_DHCP,
                       host=DHCP_HOSTA) as port1:
            num_before_remove = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
            if concurrent_port_delete:
                plugin = directory.get_plugin()
                # Return a foo port to emulate the port not found scenario
                # caused by a concurrent port deletion during unscheduling
                port = {'id': 'foo_port_id', 'device_id': 'foo_device_id'}
                mock.patch.object(plugin, 'get_ports',
                                  return_value=[port]).start()
            self._remove_network_from_dhcp_agent(hosta_id,
                                                 port1['port']['network_id'])
            num_after_remove = len(
                self._list_networks_hosted_by_dhcp_agent(
                    hosta_id)['networks'])
        self.assertEqual(1, num_before_remove)
        self.assertEqual(0, num_after_remove)

    def test_network_remove_from_dhcp_agent(self):
        self._test_network_remove_from_dhcp_agent()

    def test_network_remove_from_dhcp_agent_on_concurrent_port_delete(self):
        self._test_network_remove_from_dhcp_agent(concurrent_port_delete=True)

    def test_list_active_networks_on_not_registered_yet_dhcp_agent(self):
        plugin = directory.get_plugin()
        nets = plugin.list_active_networks_on_active_dhcp_agent(
            self.adminContext, host=DHCP_HOSTA)
        self.assertEqual([], nets)

    def test_reserved_port_after_network_remove_from_dhcp_agent(self):
        helpers.register_dhcp_agent(DHCP_HOSTA)
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                      DHCP_HOSTA)
        with self.port(device_owner=constants.DEVICE_OWNER_DHCP,
                       host=DHCP_HOSTA) as port1:
            self._remove_network_from_dhcp_agent(hosta_id,
                                                 port1['port']['network_id'])
            port_res = self._list_ports(
                'json',
                200,
                network_id=port1['port']['network_id'])
            port_list = self.deserialize('json', port_res)
            self.assertEqual(port_list['ports'][0]['device_id'],
                             constants.DEVICE_ID_RESERVED_DHCP_PORT)

    def _test_get_active_networks_from_admin_state_down_agent(self,
                                                              keep_services):
        if keep_services:
            cfg.CONF.set_override(
                'enable_services_on_agents_with_admin_state_down', True)
        helpers.register_dhcp_agent(DHCP_HOSTA)
        dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
        with self.port():
            nets = dhcp_rpc_cb.get_active_networks_info(self.adminContext,
                                                        host=DHCP_HOSTA)
            self.assertEqual(1, len(nets))
            self._set_agent_admin_state_up(DHCP_HOSTA, False)
            nets = dhcp_rpc_cb.get_active_networks_info(self.adminContext,
                                                        host=DHCP_HOSTA)
            if keep_services:
                self.assertEqual(1, len(nets))
            else:
                self.assertEqual(0, len(nets))

    def test_dhcp_agent_keep_services_off(self):
        self._test_get_active_networks_from_admin_state_down_agent(False)

    def test_dhcp_agent_keep_services_on(self):
        self._test_get_active_networks_from_admin_state_down_agent(True)

    def _take_down_agent_and_run_reschedule(self, host):
        # take down the agent on host A and ensure B is alive
        with db_api.CONTEXT_WRITER.using(self.adminContext):
            query = self.adminContext.session.query(agent_model.Agent)
            agt = query.filter_by(host=host).first()
            agt.heartbeat_timestamp = (
                agt.heartbeat_timestamp - datetime.timedelta(hours=1))

        plugin = directory.get_plugin(plugin_constants.L3)
        plugin.reschedule_routers_from_down_agents()

    def _set_agent_admin_state_up(self, host, state):
        with db_api.CONTEXT_WRITER.using(self.adminContext):
            query = self.adminContext.session.query(agent_model.Agent)
            agt_db = query.filter_by(host=host).first()
            agt_db.admin_state_up = state

    def test_router_rescheduler_catches_rpc_db_and_reschedule_exceptions(self):
        with self.router():
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            # schedule the router to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)

            plugin = directory.get_plugin(plugin_constants.L3)
            mock.patch.object(
                plugin, 'reschedule_router',
                side_effect=[
                    db_exc.DBError(), oslo_messaging.RemoteError(),
                    l3agentscheduler.RouterReschedulingFailed(router_id='f',
                                                              agent_id='f'),
                    ValueError('this raises'),
                    Exception()
                ]).start()
            self._take_down_agent_and_run_reschedule(L3_HOSTA)  # DBError
            self._take_down_agent_and_run_reschedule(L3_HOSTA)  # RemoteError
            self._take_down_agent_and_run_reschedule(L3_HOSTA)  # schedule err
            self._take_down_agent_and_run_reschedule(L3_HOSTA)  # Value error
            self._take_down_agent_and_run_reschedule(L3_HOSTA)  # Exception

    def test_router_rescheduler_catches_exceptions_on_fetching_bindings(self):
        with mock.patch('neutron_lib.context.get_admin_context') as get_ctx:
            mock_ctx = mock.Mock()
            get_ctx.return_value = mock_ctx
            mock_ctx.session.query.side_effect = db_exc.DBError()
            plugin = directory.get_plugin(plugin_constants.L3)
            # check that no exception is raised
            plugin.reschedule_routers_from_down_agents()

    def test_router_rescheduler_iterates_after_reschedule_failure(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()
        with self.router() as r1, self.router() as r2:
            # schedule the routers to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)

            rs_mock = mock.patch.object(
                plugin, 'reschedule_router',
                side_effect=l3agentscheduler.RouterReschedulingFailed(
                    router_id='f', agent_id='f'),
            ).start()
            self._take_down_agent_and_run_reschedule(L3_HOSTA)
            # make sure both had a reschedule attempt even though first failed
            rs_mock.assert_has_calls([mock.call(mock.ANY, r1['router']['id']),
                                      mock.call(mock.ANY, r2['router']['id'])],
                                     any_order=True)

    def test_router_is_not_rescheduled_from_alive_agent(self):
        with self.router():
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()

            # schedule the router to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            with mock.patch('neutron.db.l3_agentschedulers_db.'
                            'L3AgentSchedulerDbMixin.reschedule_router') as rr:
                # take down some unrelated agent and run reschedule check
                self._take_down_agent_and_run_reschedule(DHCP_HOSTC)
                self.assertFalse(rr.called)

    def test_router_is_not_rescheduled_if_agent_is_back_online(self):
        plugin = directory.get_plugin(plugin_constants.L3)
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        agent = helpers.register_l3_agent(host=L3_HOSTA)
        with self.router(),\
                self.router(),\
                mock.patch.object(plugin, 'reschedule_router') as rs_mock,\
                mock.patch.object(plugin, '_get_agent') as get_agent_mock:

            # schedule the routers to the agent
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            self._take_down_agent_and_run_reschedule(L3_HOSTA)
            # since _get_agent is mocked it will return Mock object and
            # agent.is_active will return true, so no rescheduling will be done
            self.assertFalse(rs_mock.called)
            # should be called only once as for second router alive agent id
            # will be in cache
            get_agent_mock.assert_called_once_with(mock.ANY, agent['id'])

    def test_router_reschedule_from_dead_agent(self):
        with self.router():
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()

            # schedule the router to host A
            ret_a = l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            self._take_down_agent_and_run_reschedule(L3_HOSTA)

            # B should now pick up the router
            ret_b = l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTB)
        self.assertEqual(ret_b, ret_a)

    def test_router_no_reschedule_from_dead_admin_down_agent(self):
        with self.router() as r:
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()

            # schedule the router to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            self._set_agent_admin_state_up(L3_HOSTA, False)
            self._take_down_agent_and_run_reschedule(L3_HOSTA)

            # A should still have it even though it was inactive due to the
            # admin_state being down
            bindings = rb_obj.RouterL3AgentBinding.get_objects(
                    self.adminContext, router_id=r['router']['id'])
            binding = bindings.pop() if bindings else None
            l3_agent = ag_obj.Agent.get_objects(
                self.adminContext, id=binding.l3_agent_id)
            self.assertEqual(l3_agent[0].host, L3_HOSTA)

            # B should not pick up the router
            ret_b = l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTB)
            self.assertFalse(ret_b)

    def test_router_reschedule_succeeded_after_failed_notification(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()
        with self.router() as router:
            # schedule the router to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            ctxt_mock = mock.MagicMock()
            call_mock = mock.MagicMock(
                side_effect=[oslo_messaging.MessagingTimeout, None])
            ctxt_mock.call = call_mock
            self.client_mock.prepare = mock.MagicMock(return_value=ctxt_mock)
            self._take_down_agent_and_run_reschedule(L3_HOSTA)
            self.assertEqual(2, call_mock.call_count)
            # make sure router was rescheduled even when first attempt
            # failed to notify l3 agent
            l3_agents = self._list_l3_agents_hosting_router(
                router['router']['id'])['agents']
            self.assertEqual(1, len(l3_agents))
            self.assertEqual(L3_HOSTB, l3_agents[0]['host'])

    def test_router_reschedule_failed_notification_all_attempts(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()
        with self.router() as router:
            # schedule the router to host A
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            # mock client.prepare and context.call
            ctxt_mock = mock.MagicMock()
            call_mock = mock.MagicMock(
                side_effect=oslo_messaging.MessagingTimeout)
            ctxt_mock.call = call_mock
            self.client_mock.prepare = mock.MagicMock(return_value=ctxt_mock)
            # perform operations
            self._take_down_agent_and_run_reschedule(L3_HOSTA)
            self.assertEqual(
                l3_rpc_agent_api.AGENT_NOTIFY_MAX_ATTEMPTS,
                call_mock.call_count)
            l3_agents = self._list_l3_agents_hosting_router(
                router['router']['id'])['agents']
            self.assertEqual(0, len(l3_agents))

    def test_router_reschedule_no_remove_if_agent_has_dvr_service_ports(self):
        l3_notifier = self.l3plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        agent_a = helpers.register_l3_agent(
            host=L3_HOSTA, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        agent_b = helpers.register_l3_agent(
            host=L3_HOSTB, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        with self.subnet() as s, \
                mock.patch.object(l3_notifier.client, 'prepare',
                    return_value=l3_notifier.client) as mock_prepare, \
                mock.patch.object(l3_notifier.client, 'cast') as mock_cast, \
                mock.patch.object(l3_notifier.client, 'call'):
            net_id = s['subnet']['network_id']
            self._set_net_external(net_id)
            router = {'name': 'router1',
                      'external_gateway_info': {'network_id': net_id},
                      'tenant_id': 'tenant_id',
                      'admin_state_up': True,
                      'distributed': True}
            r = self.l3plugin.create_router(self.adminContext,
                                            {'router': router})

            # schedule the dvr to one of the agents
            self.l3plugin.schedule_router(self.adminContext, r['id'])
            l3agents = self.l3plugin.list_l3_agents_hosting_router(
                    self.adminContext, r['id'])
            agent = l3agents['agents'][0]
            # emulating dvr serviceable ports exist on the host
            with mock.patch.object(
                    self.l3plugin, '_check_dvr_serviceable_ports_on_host') \
                    as ports_exist:
                ports_exist.return_value = True
                # reschedule the dvr to one of the other agent
                candidate_agent = (agent_b if agent['host'] == L3_HOSTA
                                   else agent_a)
                self.l3plugin.reschedule_router(self.adminContext, r['id'],
                        candidates=[candidate_agent])
                # make sure dvr serviceable ports are checked when rescheduling
                self.assertTrue(ports_exist.called)

            # make sure sending update instead of removing for dvr
            mock_prepare.assert_called_with(server=candidate_agent['host'])
            mock_cast.assert_called_with(
                    mock.ANY, 'routers_updated',
                    routers=[r['id']])

            # make sure the rescheduling completes
            l3agents = self.l3plugin.list_l3_agents_hosting_router(
                    self.adminContext, r['id'])
            self.assertEqual(1, len(l3agents['agents']))
            new_agent_host = l3agents['agents'][0]['host']
            self.assertNotEqual(agent['host'], new_agent_host)

    def test_router_auto_schedule_with_invalid_router(self):
        with self.router() as router:
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
        self._delete('routers', router['router']['id'])

        # deleted router
        ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                       router_ids=[router['router']['id']])
        self.assertFalse(ret_a)
        # non-existent router
        ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                       router_ids=[uuidutils.generate_uuid()])
        self.assertFalse(ret_a)

    def test_router_auto_schedule_with_hosted(self):
        with self.router() as router:
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            ret_a = l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            ret_b = l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTB)
            l3_agents = self._list_l3_agents_hosting_router(
                router['router']['id'])
            self.assertEqual(1, len(ret_a))
            self.assertIn(router['router']['id'], ret_a)
            self.assertFalse(len(ret_b))
        self.assertEqual(1, len(l3_agents['agents']))
        self.assertEqual(L3_HOSTA, l3_agents['agents'][0]['host'])

    def test_router_auto_schedule_restart_l3_agent(self):
        with self.router():
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)

    def test_router_auto_schedule_with_hosted_2(self):
        # one agent hosts one router
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        with self.router() as router1:
            hosta_id = helpers.register_l3_agent(host=L3_HOSTA).id
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            self._disable_agent(hosta_id, admin_state_up=False)
            with self.router() as router2:
                hostb_id = helpers.register_l3_agent(host=L3_HOSTB).id
                l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTB)
                l3_agents_1 = self._list_l3_agents_hosting_router(
                    router1['router']['id'])
                l3_agents_2 = self._list_l3_agents_hosting_router(
                    router2['router']['id'])
                hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
                num_hosta_routers = len(hosta_routers['routers'])
                hostb_routers = self._list_routers_hosted_by_l3_agent(hostb_id)
                num_hostb_routers = len(hostb_routers['routers'])

        self.assertEqual(1, num_hosta_routers)
        self.assertEqual(1, num_hostb_routers)
        self.assertEqual(1, len(l3_agents_1['agents']))
        self.assertEqual(1, len(l3_agents_2['agents']))
        self.assertEqual(L3_HOSTA, l3_agents_1['agents'][0]['host'])
        self.assertEqual(L3_HOSTB, l3_agents_2['agents'][0]['host'])

    def test_router_auto_schedule_with_disabled(self):
        with self.router(), self.router():
            l3_rpc_cb = l3_rpc.L3RpcCallback()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            hostb_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTB)
            self._disable_agent(hosta_id)
            # first agent will not host router since it is disabled
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            # second agent will host all the routers since first is disabled.
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTB)
            hostb_routers = self._list_routers_hosted_by_l3_agent(hostb_id)
            num_hostb_routers = len(hostb_routers['routers'])
            hosta_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
            num_hosta_routers = len(hosta_routers['routers'])
        self.assertEqual(2, num_hostb_routers)
        self.assertEqual(0, num_hosta_routers)

    def test_rpc_sync_routers(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()

        # No routers
        ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
        self.assertEqual(0, len(ret_a))

        with self.router() as v1, self.router() as v2, self.router() as v3:
            routers = (v1, v2, v3)
            router_ids = [r['router']['id'] for r in routers]

            # auto schedule routers first
            l3_rpc_cb.get_router_ids(self.adminContext, host=L3_HOSTA)
            # Get all routers
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
            self.assertEqual(3, len(ret_a))
            self.assertEqual(set(router_ids), set([r['id'] for r in ret_a]))

            # Get all routers (router_ids=None)
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                           router_ids=None)
            self.assertEqual(3, len(ret_a))
            self.assertEqual(set(router_ids), set([r['id'] for r in ret_a]))

            # Get router2 only
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                           router_ids=[router_ids[1]])
            self.assertEqual(1, len(ret_a))
            self.assertIn(router_ids[1], [r['id'] for r in ret_a])

            # Get router1 and router3
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                           router_ids=[router_ids[0],
                                                       router_ids[2]])
            self.assertEqual(2, len(ret_a))
            self.assertIn(router_ids[0], [r['id'] for r in ret_a])
            self.assertIn(router_ids[2], [r['id'] for r in ret_a])

    def test_sync_router(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3, L3_HOSTA)

        with self.router() as r1:
            ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA,
                                           router_ids=[r1['router']['id']])
            # Not return router to agent if the router is not bound to it.
            self.assertEqual([], ret_a)
            host_routers = self._list_routers_hosted_by_l3_agent(hosta_id)
            # No router will be auto scheduled.
            self.assertEqual(0, len(host_routers['routers']))

    def test_sync_dvr_router(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        dvr_agents = self._register_dvr_agents()

        with self.router() as r1, \
                mock.patch.object(self.l3plugin, 'get_subnet_ids_on_router',
                                  return_value=['fake_subnet_id']), \
                mock.patch.object(self.l3plugin,
                                  '_check_dvr_serviceable_ports_on_host',
                                  return_value=True):
            for l3_agent in dvr_agents:
                host = l3_agent['host']
                ret_a = l3_rpc_cb.sync_routers(self.adminContext, host=host,
                                               router_ids=[r1['router']['id']])
                router_ids = [r['id'] for r in ret_a]
                # Return router to agent if there is dvr service port in agent.
                self.assertIn(r1['router']['id'], router_ids)
                host_routers = self._list_routers_hosted_by_l3_agent(
                    l3_agent['id'])
                # No router will be auto scheduled.
                self.assertEqual(0, len(host_routers['routers']))

    def test_sync_dvr_router_with_fixedip_on_fip_net(self):
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_dvr_agents()

        with self.subnet() as s:
            # first create an external network
            net_id = s['subnet']['network_id']
            self._set_net_external(net_id)
            # create router with external gateway
            router = {'name': 'router1',
                      'external_gateway_info': {'network_id': net_id},
                      'tenant_id': 'tenant_id',
                      'admin_state_up': True,
                      'distributed': True}
            r = self.l3plugin.create_router(self.adminContext,
                                            {'router': router})
            self.l3plugin.schedule_router(self.adminContext, r['id'])
            with self.port(subnet=s,
                           device_owner=DEVICE_OWNER_COMPUTE) as port:
                # bind port to L3_HOSTB
                updated_port = {
                    "port": {
                        portbindings.HOST_ID: L3_HOSTB
                    }
                }
                self.plugin.update_port(
                    self.adminContext,
                    port['port']['id'],
                    updated_port
                )
                ret_b = l3_rpc_cb.sync_routers(
                    self.adminContext,
                    host=L3_HOSTB,
                    router_ids=[r['id']])

                router_ids = [r['id'] for r in ret_b]
                self.assertEqual(0, len(router_ids))

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
                self.l3plugin.get_l3_agents_hosting_routers(
                    self.adminContext, [router['router']['id']]))
            self._delete('routers', router['router']['id'])
        self.assertEqual(0, len(l3agents))

    def test_dvr_router_scheduling_to_only_dvr_snat_agent(self):
        self._register_dvr_agents()
        with self.subnet() as s:
            net_id = s['subnet']['network_id']
            self._set_net_external(net_id)

            router = {'name': 'router1',
                      'external_gateway_info': {'network_id': net_id},
                      'tenant_id': 'tenant_id',
                      'admin_state_up': True,
                      'distributed': True}
            r = self.l3plugin.create_router(self.adminContext,
                                            {'router': router})
            with mock.patch.object(
                    self.l3plugin,
                    '_check_dvr_serviceable_ports_on_host') as ports_exist:
                # emulating dvr serviceable ports exist on compute node
                ports_exist.return_value = True
                self.l3plugin.schedule_router(
                    self.adminContext, r['id'])

        l3agents = self._list_l3_agents_hosting_router(r['id'])
        self.assertEqual(1, len(l3agents['agents']))
        agent = l3agents['agents'][0]
        self.assertEqual('dvr_snat',
                         agent['configurations']['agent_mode'])

    def test_dvr_router_csnat_rescheduling(self):
        helpers.register_l3_agent(
            host=L3_HOSTA, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        helpers.register_l3_agent(
            host=L3_HOSTB, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        with self.subnet() as s:
            net_id = s['subnet']['network_id']
            self._set_net_external(net_id)

            router = {'name': 'router1',
                      'external_gateway_info': {'network_id': net_id},
                      'tenant_id': 'tenant_id',
                      'admin_state_up': True,
                      'distributed': True}
            r = self.l3plugin.create_router(self.adminContext,
                                            {'router': router})
            self.l3plugin.schedule_router(
                    self.adminContext, r['id'])
            l3agents = self._list_l3_agents_hosting_router(r['id'])
            self.assertEqual(1, len(l3agents['agents']))
            agent_host = l3agents['agents'][0]['host']
            self._take_down_agent_and_run_reschedule(agent_host)
            l3agents = self._list_l3_agents_hosting_router(r['id'])
            self.assertEqual(1, len(l3agents['agents']))
            new_agent_host = l3agents['agents'][0]['host']
            self.assertNotEqual(agent_host, new_agent_host)

    def test_dvr_router_manual_rescheduling(self):
        helpers.register_l3_agent(
            host=L3_HOSTA, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        helpers.register_l3_agent(
            host=L3_HOSTB, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        with self.subnet() as s:
            net_id = s['subnet']['network_id']
            self._set_net_external(net_id)

            router = {'name': 'router1',
                      'external_gateway_info': {'network_id': net_id},
                      'tenant_id': 'tenant_id',
                      'admin_state_up': True,
                      'distributed': True}
            r = self.l3plugin.create_router(self.adminContext,
                                            {'router': router})
            self.l3plugin.schedule_router(
                    self.adminContext, r['id'])
            l3agents = self.l3plugin.list_l3_agents_hosting_router(
                self.adminContext, r['id'])
            self.assertEqual(1, len(l3agents['agents']))
            agent = l3agents['agents'][0]
            # NOTE: Removing the router from the l3_agent will
            # remove all the namespace since there is no other
            # serviceable ports in the node that requires it.
            self.l3plugin.remove_router_from_l3_agent(
                self.adminContext, agent['id'], r['id'])

            l3agents = self.l3plugin.list_l3_agents_hosting_router(
                self.adminContext, r['id'])
            self.assertEqual(0, len(l3agents['agents']))

            self.l3plugin.add_router_to_l3_agent(
                self.adminContext, agent['id'], r['id'])

            l3agents = self.l3plugin.list_l3_agents_hosting_router(
                self.adminContext, r['id'])
            self.assertEqual(1, len(l3agents['agents']))
            new_agent = l3agents['agents'][0]
            self.assertEqual(agent['id'], new_agent['id'])

    def test_router_sync_data(self):
        with self.subnet() as s1,\
                self.subnet(cidr='10.0.2.0/24') as s2,\
                self.subnet(cidr='10.0.3.0/24') as s3:
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

    def _test_router_add_to_l3_agent(self, admin_state_up=True):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            if not admin_state_up:
                self._set_agent_admin_state_up(L3_HOSTA, False)
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

    def test_router_add_to_l3_agent(self):
        self._test_router_add_to_l3_agent()

    def test_router_add_to_l3_agent_with_admin_state_down(self):
        cfg.CONF.set_override(
            'enable_services_on_agents_with_admin_state_down', True)
        self._test_router_add_to_l3_agent(admin_state_up=False)

    def test_router_add_to_l3_agent_two_times(self):
        with self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            # scheduling twice on the same agent is fine
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])

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

    def _test_sync_routers_from_admin_state_down_agent(self, keep_services):
        if keep_services:
            cfg.CONF.set_override(
                'enable_services_on_agents_with_admin_state_down', True)
        l3_rpc_cb = l3_rpc.L3RpcCallback()
        self._register_agent_states()
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3, L3_HOSTA)
        with self.router() as router:
            self._add_router_to_l3_agent(hosta_id,
                                         router['router']['id'])
            routers = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
            self.assertEqual(1, len(routers))
            self._set_agent_admin_state_up(L3_HOSTA, False)
            routers = l3_rpc_cb.sync_routers(self.adminContext, host=L3_HOSTA)
            if keep_services:
                self.assertEqual(1, len(routers))
            else:
                self.assertEqual(0, len(routers))

    def test_l3_agent_keep_services_off(self):
        self._test_sync_routers_from_admin_state_down_agent(False)

    def test_l3_agent_keep_services_on(self):
        self._test_sync_routers_from_admin_state_down_agent(True)

    def test_list_routers_hosted_by_l3_agent_with_invalid_agent(self):
        invalid_agentid = 'non_existing_agent'
        self._list_routers_hosted_by_l3_agent(invalid_agentid,
                                              exc.HTTPNotFound.code)

    def test_list_networks_hosted_by_dhcp_agent_with_invalid_agent(self):
        invalid_agentid = 'non_existing_agent'
        self._list_networks_hosted_by_dhcp_agent(invalid_agentid,
                                                 exc.HTTPNotFound.code)

    def test_network_no_reschedule(self):
        cfg.CONF.set_override('allow_overlapping_ips', True)
        cfg.CONF.set_override('network_auto_schedule', False)
        with self.subnet() as sb1, self.subnet():
            network1_id = sb1['subnet']['network_id']
            dhcp_rpc_cb = dhcp_rpc.DhcpRpcCallback()
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            hostc_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTC)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTA)
            dhcp_rpc_cb.get_active_networks_info(
                self.adminContext, host=DHCP_HOSTC)
            networks = self._list_networks_hosted_by_dhcp_agent(hostc_id)
            num_hostc_nets = len(networks['networks'])
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
            self.assertEqual(0, num_hosta_nets)
            self.assertEqual(0, num_hostc_nets)
            # After this patch, network which requires DHCP
            # has to be manually mapped
            self._add_network_to_dhcp_agent(hosta_id,
                                            network1_id)
            networks = self._list_networks_hosted_by_dhcp_agent(hosta_id)
            num_hosta_nets = len(networks['networks'])
            self.assertEqual(1, num_hosta_nets)


class OvsDhcpAgentNotifierTestCase(test_agent.AgentDBTestMixIn,
                                   AgentSchedulerTestMixIn,
                                   test_plugin.NeutronDbPluginV2TestCase):
    def setUp(self):
        super(OvsDhcpAgentNotifierTestCase, self).setUp('ml2')
        mock.patch.object(
            self.plugin, 'filter_hosts_with_network_access',
            side_effect=lambda context, network_id, hosts: hosts).start()
        plugin = directory.get_plugin()
        self.dhcp_notifier = plugin.agent_notifiers[constants.AGENT_TYPE_DHCP]
        self.dhcp_notifier_cast = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI._cast_message').start()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        fake_notifier.reset()

    def test_network_add_to_dhcp_agent_notification(self):
        with self.network() as net1:
            network_id = net1['network']['id']
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._add_network_to_dhcp_agent(hosta_id,
                                            network_id)
        self.dhcp_notifier_cast.assert_called_with(
                mock.ANY, 'network_create_end',
                {'network': {'id': network_id},
                 'priority': dhcp_rpc_agent_api.PRIORITY_NETWORK_CREATE},
                DHCP_HOSTA)
        notifications = fake_notifier.NOTIFICATIONS
        expected_event_type = 'dhcp_agent.network.add'
        self._assert_notify(notifications, expected_event_type)

    def test_network_remove_from_dhcp_agent_notification(self):
        with self.network() as net1:
            network_id = net1['network']['id']
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                          DHCP_HOSTA)
            self._add_network_to_dhcp_agent(hosta_id,
                                            network_id)

        self._remove_network_from_dhcp_agent(hosta_id,
                                             network_id)
        self.dhcp_notifier_cast.assert_called_with(
                mock.ANY, 'network_delete_end',
                {'network_id': network_id,
                 'priority': dhcp_rpc_agent_api.PRIORITY_NETWORK_DELETE},
                DHCP_HOSTA)
        notifications = fake_notifier.NOTIFICATIONS
        expected_event_type = 'dhcp_agent.network.remove'
        self._assert_notify(notifications, expected_event_type)

    def test_agent_updated_dhcp_agent_notification(self):
        self._register_agent_states()
        hosta_id = self._get_agent_id(constants.AGENT_TYPE_DHCP,
                                      DHCP_HOSTA)
        self._disable_agent(hosta_id, admin_state_up=False)

        self.dhcp_notifier_cast.assert_called_with(
                mock.ANY, 'agent_updated',
                {'admin_state_up': False}, DHCP_HOSTA)

    def _api_network_port_create(
            self, hosts, gateway=constants.ATTR_NOT_SPECIFIED, owner=None):
        for host in hosts:
            helpers.register_dhcp_agent(host)
        with self.network() as net1:
            with self.subnet(network=net1,
                             gateway_ip=gateway) as subnet1:
                if owner:
                    with self.port(subnet=subnet1,
                                   device_owner=owner) as port:
                        return [net1, subnet1, port]
                else:
                    with self.port(subnet=subnet1) as port:
                        return [net1, subnet1, port]

    def _network_port_create(self, *args, **kwargs):
        net, sub, port = self._api_network_port_create(*args, **kwargs)

        dhcp_notifier = self.plugin.agent_notifiers[constants.AGENT_TYPE_DHCP]
        if (not hasattr(dhcp_notifier, 'uses_native_notifications') or
            not all(dhcp_notifier.uses_native_notifications[r]['create']
                    for r in ('port', 'subnet', 'network'))):
            return net, sub, port
        # since plugin has native dhcp notifications, the payloads will be the
        # same as the getter outputs
        ctx = context.get_admin_context()
        net['network'] = self.plugin.get_network(ctx, net['network']['id'])
        sub['subnet'] = self.plugin.get_subnet(ctx, sub['subnet']['id'])
        sub['priority'] = dhcp_rpc_agent_api.PRIORITY_SUBNET_UPDATE
        port['port'] = self.plugin.get_port(ctx, port['port']['id'])
        return net, sub, port

    def _notification_mocks(self, hosts, net, subnet, port, port_priority):
        subnet['subnet']['network'] = copy.deepcopy(net['network'])
        # 'availability_zones' is empty at the time subnet_create_end
        # notification is sent
        subnet['subnet']['network']['availability_zones'] = []
        port['port']['network'] = net['network']
        host_calls = {}
        for host in hosts:
            expected_calls = [
                mock.call(
                    mock.ANY,
                    'network_create_end',
                    {'priority': dhcp_rpc_agent_api.PRIORITY_NETWORK_CREATE,
                     'network': {'id': net['network']['id']}},
                    host),
                mock.call(
                    mock.ANY,
                    'subnet_create_end',
                    subnet,
                    host, 'dhcp_agent'),
                mock.call(
                    mock.ANY,
                    'port_create_end',
                    {'port': port['port'],
                     'priority': port_priority},
                    host, 'dhcp_agent')]
            host_calls[host] = expected_calls
        return host_calls

    def test_network_port_create_notification(self):
        hosts = [DHCP_HOSTA]
        net, subnet, port = self._network_port_create(hosts)
        expected_calls = self._notification_mocks(
            hosts, net, subnet, port,
            dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH)
        self.assertEqual(
            expected_calls[DHCP_HOSTA], self.dhcp_notifier_cast.call_args_list)

    def test_network_ha_port_create_notification(self):
        cfg.CONF.set_override('dhcp_agents_per_network', 3)
        hosts = [DHCP_HOSTA, DHCP_HOSTC, DHCP_HOSTD]
        net, subnet, port = self._network_port_create(hosts)
        for host_call in self.dhcp_notifier_cast.call_args_list:
            if ("'priority': " + str(
                    dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH)
                    in str(host_call)):
                if DHCP_HOSTA in str(host_call):
                    expected_high_calls = self._notification_mocks(
                        [DHCP_HOSTA], net, subnet, port,
                        dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH)
                    high_host = DHCP_HOSTA
                    hosts.pop(0)
                elif DHCP_HOSTC in str(host_call):
                    expected_high_calls = self._notification_mocks(
                        [DHCP_HOSTC], net, subnet, port,
                        dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH)
                    high_host = DHCP_HOSTC
                    hosts.pop(1)
                elif DHCP_HOSTD in str(host_call):
                    expected_high_calls = self._notification_mocks(
                        [DHCP_HOSTD], net, subnet, port,
                        dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH)
                    high_host = DHCP_HOSTD
                    hosts.pop(2)
        expected_low_calls = self._notification_mocks(
            hosts, net, subnet, port,
            dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_LOW)
        for expected in expected_high_calls[high_host]:
            self.assertIn(expected, self.dhcp_notifier_cast.call_args_list)
        for host, low_expecteds in expected_low_calls.items():
            for expected in low_expecteds:
                self.assertIn(expected, self.dhcp_notifier_cast.call_args_list)

    def _test_auto_schedule_new_network_segments(self, subnet_on_segment):
        ctx = mock.Mock()
        payload = events.DBEventPayload(
            ctx,
            metadata={'host': 'HOST A',
                      'current_segment_ids': set(['segment-1'])})
        segments_plugin = mock.Mock()
        segments_plugin.get_segments.return_value = [
            {'id': 'segment-1', 'hosts': ['HOST A']}]
        dhcp_notifier = mock.Mock()
        dhcp_mixin = agentschedulers_db.DhcpAgentSchedulerDbMixin()
        with mock.patch(
                'neutron_lib.plugins.directory.get_plugin',
                return_value=segments_plugin), \
            mock.patch(
                'neutron.objects.subnet.Subnet.get_objects') as get_subnets, \
            mock.patch.object(
                dhcp_mixin, '_schedule_network') as schedule_network:

            get_subnets.return_value = (
                [subnet_on_segment] if subnet_on_segment else [])

            dhcp_mixin.agent_notifiers[constants.AGENT_TYPE_DHCP] = (
                dhcp_notifier)
            dhcp_mixin.auto_schedule_new_network_segments(
                resources.SEGMENT_HOST_MAPPING, events.AFTER_CREATE,
                ctx, payload)
            if subnet_on_segment:
                schedule_network.assert_called_once_with(
                    ctx, subnet_on_segment.network_id,
                    dhcp_notifier, candidate_hosts=['HOST A'])
            else:
                schedule_network.assert_not_called()

    def test_auto_schedule_new_network_segments(self):
        self._test_auto_schedule_new_network_segments(
            subnet_on_segment=mock.Mock(network_id='net-1'))

    def test_auto_schedule_new_network_segments_no_networks_on_segment(self):
        self._test_auto_schedule_new_network_segments(subnet_on_segment=None)

    def _is_schedule_network_called(self, device_id):
        dhcp_notifier_schedule = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI._schedule_network').start()
        plugin = directory.get_plugin()
        with self.subnet() as subnet,\
                self.port(subnet=subnet, device_id=device_id),\
                mock.patch.object(plugin,
                                  'get_dhcp_agents_hosting_networks',
                                  return_value=[]):
            return dhcp_notifier_schedule.call_count > 1

    def test_reserved_dhcp_port_creation(self):
        device_id = constants.DEVICE_ID_RESERVED_DHCP_PORT
        self.assertFalse(self._is_schedule_network_called(device_id))

    def test_unreserved_dhcp_port_creation(self):
        device_id = 'not_reserved'
        self.assertTrue(self._is_schedule_network_called(device_id))


class OvsL3AgentNotifierTestCase(test_l3.L3NatTestCaseMixin,
                                 test_agent.AgentDBTestMixIn,
                                 AgentSchedulerTestMixIn,
                                 test_plugin.NeutronDbPluginV2TestCase):
    l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                 'TestL3NatAgentSchedulingServicePlugin')

    def setUp(self):
        self.dhcp_notifier_cls_p = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI')
        self.dhcp_notifier = mock.Mock(name='dhcp_notifier')
        self.dhcp_notifier_cls = self.dhcp_notifier_cls_p.start()
        self.dhcp_notifier_cls.return_value = self.dhcp_notifier

        if self.l3_plugin:
            service_plugins = {
                'l3_plugin_name': self.l3_plugin,
                'flavors_plugin_name': 'neutron.services.flavors.'
                                       'flavors_plugin.FlavorsPlugin'
            }
        else:
            service_plugins = None
        super(OvsL3AgentNotifierTestCase, self).setUp(
            'ml2', service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
        fake_notifier.reset()

    def test_router_add_to_l3_agent_notification(self):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        l3_notifier = l3_plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(
            l3_notifier.client,
            'prepare',
            return_value=l3_notifier.client) as mock_prepare,\
                mock.patch.object(l3_notifier.client, 'call') as mock_call,\
                self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            routers = [router1['router']['id']]
            mock_prepare.assert_called_with(server='hosta')
            mock_call.assert_called_with(
                mock.ANY, 'router_added_to_agent', payload=routers)
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'l3_agent.router.add'
            self._assert_notify(notifications, expected_event_type)

    def test_router_remove_from_l3_agent_notification(self):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        l3_notifier = l3_plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(
            l3_notifier.client,
            'prepare',
            return_value=l3_notifier.client) as mock_prepare,\
                mock.patch.object(l3_notifier.client, 'cast') as mock_cast,\
                mock.patch.object(l3_notifier.client, 'call'),\
                self.router() as router1:
            self._register_agent_states()
            hosta_id = self._get_agent_id(constants.AGENT_TYPE_L3,
                                          L3_HOSTA)
            self._add_router_to_l3_agent(hosta_id,
                                         router1['router']['id'])
            self._remove_router_from_l3_agent(hosta_id,
                                              router1['router']['id'])
            mock_prepare.assert_called_with(server='hosta')
            mock_cast.assert_called_with(
                    mock.ANY, 'router_removed_from_agent',
                    payload={'router_id': router1['router']['id']})
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'l3_agent.router.remove'
            self._assert_notify(notifications, expected_event_type)

    def test_agent_updated_l3_agent_notification(self):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        l3_notifier = l3_plugin.agent_notifiers[constants.AGENT_TYPE_L3]
        with mock.patch.object(
            l3_notifier.client,
            'prepare',
            return_value=l3_notifier.client) as mock_prepare,\
                mock.patch.object(l3_notifier.client, 'cast') as mock_cast:
            agent_id = helpers.register_l3_agent(L3_HOSTA).id
            self._disable_agent(agent_id, admin_state_up=False)

            mock_prepare.assert_called_with(server=L3_HOSTA)

            mock_cast.assert_called_with(
                mock.ANY, 'agent_updated', payload={'admin_state_up': False})
