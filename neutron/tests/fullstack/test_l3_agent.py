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

import functools

from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment


class TestLegacyL3Agent(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [environment.HostDescription(l3_agent=True)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=False),
            host_descriptions)
        super(TestLegacyL3Agent, self).setUp(env)

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
            self.environment.hosts[0].l3_agent.get_namespace_suffix(), )
        self._assert_namespace_exists(namespace)


class TestHAL3Agent(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True) for _ in range(2)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vxlan', l2_pop=True),
            host_descriptions)
        super(TestHAL3Agent, self).setUp(env)

    def _is_ha_router_active_on_one_agent(self, router_id):
        agents = self.client.list_l3_agent_hosting_routers(router_id)
        return (
            agents['agents'][0]['ha_state'] != agents['agents'][1]['ha_state'])

    def test_ha_router(self):
        # TODO(amuller): Test external connectivity before and after a
        # failover, see: https://review.openstack.org/#/c/196393/

        tenant_id = uuidutils.generate_uuid()
        router = self.safe_client.create_router(tenant_id, ha=True)
        agents = self.client.list_l3_agent_hosting_routers(router['id'])
        self.assertEqual(2, len(agents['agents']),
                         'HA router must be scheduled to both nodes')

        utils.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)
