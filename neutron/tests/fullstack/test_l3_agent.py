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

from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.tests.fullstack import base
from neutron.tests.fullstack import fullstack_fixtures as f_fixtures


class SingleNodeEnvironment(f_fixtures.FullstackFixture):
    def _setUp(self):
        super(SingleNodeEnvironment, self)._setUp()

        neutron_config = self.neutron_server.neutron_cfg_fixture
        ml2_config = self.neutron_server.plugin_cfg_fixture

        self.ovs_agent = self.useFixture(
            f_fixtures.OVSAgentFixture(
                self.test_name, neutron_config, ml2_config))

        self.l3_agent = self.useFixture(
            f_fixtures.L3AgentFixture(
                self.test_name,
                self.temp_dir,
                neutron_config,
                self.ovs_agent._get_br_int_name()))

        self.wait_until_env_is_up(agents_count=2)


class TestLegacyL3Agent(base.BaseFullStackTestCase):
    def __init__(self, *args, **kwargs):
        super(TestLegacyL3Agent, self).__init__(
            SingleNodeEnvironment(), *args, **kwargs)

    def _get_namespace(self, router_id):
        return namespaces.build_ns_name(l3_agent.NS_PREFIX, router_id)

    def _assert_namespace_exists(self, ns_name):
        ip = ip_lib.IPWrapper(ns_name)
        utils.wait_until_true(lambda: ip.netns.exists(ns_name))

    def test_namespace_exists(self):
        tenant_id = uuidutils.generate_uuid()

        router = self.safe_client.create_router(tenant_id)
        network = self.safe_client.create_network(tenant_id)
        subnet = self.safe_client.create_subnet(
            tenant_id, network['id'], '20.0.0.0/24', gateway_ip='20.0.0.1')
        self.safe_client.add_router_interface(router['id'], subnet['id'])

        namespace = "%s@%s" % (
            self._get_namespace(router['id']),
            self.environment.l3_agent.get_namespace_suffix(), )
        self._assert_namespace_exists(namespace)
