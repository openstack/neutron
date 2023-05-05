# Copyright (c) 2013 OpenStack Foundation.
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

import time

from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc

from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import agent
from neutron.tests.common import helpers
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2


_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path
L3_HOSTA = 'hosta'
DHCP_HOSTA = 'hosta'
L3_HOSTB = 'hostb'
DHCP_HOSTC = 'hostc'


class AgentTestExtensionManager(object):

    def get_resources(self):
        return agent.Agent.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# This plugin class is just for testing
class TestAgentPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                      agents_db.AgentDbMixin):
    supported_extension_aliases = [agent_apidef.ALIAS]


class AgentDBTestMixIn(object):

    def _list_agents(self, expected_res_status=None,
                     query_string=None):
        agent_res = self._list('agents',
                               query_params=query_string,
                               as_admin=True)
        if expected_res_status:
            self.assertEqual(expected_res_status, agent_res.status_int)
        return agent_res

    def _register_agent_states(self):
        """Register two L3 agents and two DHCP agents."""
        l3_hosta = helpers._get_l3_agent_dict(
            L3_HOSTA, constants.L3_AGENT_MODE_LEGACY)
        l3_hostb = helpers._get_l3_agent_dict(
            L3_HOSTB, constants.L3_AGENT_MODE_LEGACY)
        dhcp_hosta = helpers._get_dhcp_agent_dict(DHCP_HOSTA)
        dhcp_hostc = helpers._get_dhcp_agent_dict(DHCP_HOSTC)
        helpers.register_l3_agent(host=L3_HOSTA)
        helpers.register_l3_agent(host=L3_HOSTB)
        helpers.register_dhcp_agent(host=DHCP_HOSTA)
        helpers.register_dhcp_agent(host=DHCP_HOSTC)

        return [l3_hosta, l3_hostb, dhcp_hosta, dhcp_hostc]

    def _register_dvr_agents(self):
        dvr_snat_agent = helpers.register_l3_agent(
            host=L3_HOSTA, agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        dvr_agent = helpers.register_l3_agent(
            host=L3_HOSTB, agent_mode=constants.L3_AGENT_MODE_DVR)
        return [dvr_snat_agent, dvr_agent]

    def _register_l3_agent(self, host):
        helpers.register_l3_agent(host)


class AgentDBTestCase(AgentDBTestMixIn,
                      test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    fmt = 'json'

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_agent.TestAgentPlugin'
        ext_mgr = AgentTestExtensionManager()
        super(AgentDBTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)
        self.adminContext = context.get_admin_context()

    def test_create_agent(self):
        data = {'agent': {}}
        _req = self.new_create_request('agents', data, self.fmt)
        res = _req.get_response(self.ext_api)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_list_agent(self):
        agents = self._register_agent_states()
        res = self._list('agents', as_admin=True)
        self.assertEqual(len(agents), len(res['agents']))

    def test_show_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string='binary=' + constants.AGENT_PROCESS_L3)
        self.assertEqual(2, len(agents['agents']))
        agent = self._show('agents', agents['agents'][0]['id'], as_admin=True)
        self.assertEqual(constants.AGENT_PROCESS_L3, agent['agent']['binary'])

    def test_update_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string=('binary=' + constants.AGENT_PROCESS_L3 +
                '&host=' + L3_HOSTB))
        self.assertEqual(1, len(agents['agents']))
        com_id = agents['agents'][0]['id']
        agent = self._show('agents', com_id, as_admin=True)
        new_agent = {}
        new_agent['agent'] = {}
        new_agent['agent']['admin_state_up'] = False
        new_agent['agent']['description'] = 'description'
        self._update('agents', com_id, new_agent, as_admin=True)
        agent = self._show('agents', com_id, as_admin=True)
        self.assertFalse(agent['agent']['admin_state_up'])
        self.assertEqual('description', agent['agent']['description'])

    def test_dead_agent(self):
        cfg.CONF.set_override('agent_down_time', 1)
        self._register_agent_states()
        time.sleep(1.5)
        agents = self._list_agents(
            query_string=('binary=' + constants.AGENT_PROCESS_L3 +
                '&host=' + L3_HOSTB))
        self.assertFalse(agents['agents'][0]['alive'])
