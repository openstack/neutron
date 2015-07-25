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

import copy
from datetime import datetime
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
from webob import exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron import context
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import agent
from neutron.tests.common import helpers
from neutron.tests import tools
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path
L3_HOSTA = 'hosta'
DHCP_HOSTA = 'hosta'
L3_HOSTB = 'hostb'
DHCP_HOSTC = 'hostc'
LBAAS_HOSTA = 'hosta'
LBAAS_HOSTB = 'hostb'


class AgentTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        return agent.Agent.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# This plugin class is just for testing
class TestAgentPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                      agents_db.AgentDbMixin):
    supported_extension_aliases = ["agent"]


class AgentDBTestMixIn(object):

    def _list_agents(self, expected_res_status=None,
                     neutron_context=None,
                     query_string=None):
        agent_res = self._list('agents',
                               neutron_context=neutron_context,
                               query_params=query_string)
        if expected_res_status:
            self.assertEqual(agent_res.status_int, expected_res_status)
        return agent_res

    def _register_agent_states(self, lbaas_agents=False):
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

        res = [l3_hosta, l3_hostb, dhcp_hosta, dhcp_hostc]
        if lbaas_agents:
            lbaas_hosta = {
                'binary': 'neutron-loadbalancer-agent',
                'host': LBAAS_HOSTA,
                'topic': 'LOADBALANCER_AGENT',
                'configurations': {'device_drivers': ['haproxy_ns']},
                'agent_type': constants.AGENT_TYPE_LOADBALANCER}
            lbaas_hostb = copy.deepcopy(lbaas_hosta)
            lbaas_hostb['host'] = LBAAS_HOSTB
            callback = agents_db.AgentExtRpcCallback()
            callback.report_state(self.adminContext,
                                  agent_state={'agent_state': lbaas_hosta},
                                  time=datetime.utcnow().isoformat())
            callback.report_state(self.adminContext,
                                  agent_state={'agent_state': lbaas_hostb},
                                  time=datetime.utcnow().isoformat())
            res += [lbaas_hosta, lbaas_hostb]

        return res


class AgentDBTestCase(AgentDBTestMixIn,
                      test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    fmt = 'json'

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_agent.TestAgentPlugin'
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        self.useFixture(tools.AttributeMapMemento())
        ext_mgr = AgentTestExtensionManager()
        super(AgentDBTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)
        self.adminContext = context.get_admin_context()

    def test_create_agent(self):
        data = {'agent': {}}
        _req = self.new_create_request('agents', data, self.fmt)
        _req.environ['neutron.context'] = context.Context(
            '', 'tenant_id')
        res = _req.get_response(self.ext_api)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_list_agent(self):
        agents = self._register_agent_states()
        res = self._list('agents')
        self.assertEqual(len(agents), len(res['agents']))

    def test_show_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string='binary=neutron-l3-agent')
        self.assertEqual(2, len(agents['agents']))
        agent = self._show('agents', agents['agents'][0]['id'])
        self.assertEqual('neutron-l3-agent', agent['agent']['binary'])

    def test_update_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string='binary=neutron-l3-agent&host=' + L3_HOSTB)
        self.assertEqual(1, len(agents['agents']))
        com_id = agents['agents'][0]['id']
        agent = self._show('agents', com_id)
        new_agent = {}
        new_agent['agent'] = {}
        new_agent['agent']['admin_state_up'] = False
        new_agent['agent']['description'] = 'description'
        self._update('agents', com_id, new_agent)
        agent = self._show('agents', com_id)
        self.assertFalse(agent['agent']['admin_state_up'])
        self.assertEqual('description', agent['agent']['description'])

    def test_dead_agent(self):
        cfg.CONF.set_override('agent_down_time', 1)
        self._register_agent_states()
        time.sleep(1.5)
        agents = self._list_agents(
            query_string='binary=neutron-l3-agent&host=' + L3_HOSTB)
        self.assertFalse(agents['agents'][0]['alive'])
