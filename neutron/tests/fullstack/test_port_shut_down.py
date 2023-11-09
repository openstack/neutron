# Copyright 2017 - Nokia
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools

from neutron.common import utils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api
from neutron_lib import constants
from oslo_utils import uuidutils

load_tests = testlib_api.module_load_tests


class PortShutDownTest(base.BaseFullStackTestCase):
    # This is a test to confirm the port status
    # on shutting down the port administratively.
    # The port status should no longer be ACTIVE
    # and go to DOWN

    use_dhcp = True
    l2_pop = False
    arp_responder = False
    num_hosts = 1

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS})
    ]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type,
                dhcp_agent=self.use_dhcp,
            )
            for _ in range(self.num_hosts)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                l2_pop=self.l2_pop,
                arp_responder=self.arp_responder),
            host_descriptions)
        super(PortShutDownTest, self).setUp(env)

    def _create_external_network_and_subnet(self, tenant_id):
        # This test is not exclusive for the external networks.
        # It is only used here to implicitly create a dhcp port
        # on the network creation.
        network = self.safe_client.create_network(
            tenant_id, name='test-public', external=True, network_type='local')
        self.safe_client.create_subnet(tenant_id, network['id'],
                                       '240.0.0.0/8', gateway_ip='240.0.0.2')
        return network

    def _get_network_dhcp_ports(self, network_id):
        return self.client.list_ports(network_id=network_id,
                          device_owner=constants.DEVICE_OWNER_DHCP)['ports']

    def _is_port_active(self, port_id):
        port = self.client.show_port(port_id)['port']
        return port['status'] == constants.PORT_STATUS_ACTIVE

    def _is_port_down(self, port_id):
        port = self.client.show_port(port_id)['port']
        return port['status'] == constants.PORT_STATUS_DOWN

    def test_port_shut_down(self):
        tenant_id = uuidutils.generate_uuid()
        # Create an external network
        network = self._create_external_network_and_subnet(tenant_id)

        # Check if the DHCP port is created
        port_created = functools.partial(self._get_network_dhcp_ports,
                                         network['id'])
        utils.wait_until_true(port_created)

        # Get the DHCP port
        port = self._get_network_dhcp_ports(network['id'])[0]

        # Wait till the changes are reflected to DB
        port_status_active_predicate = functools.partial(
            self._is_port_active, port['id'])
        utils.wait_until_true(port_status_active_predicate)

        # Shut down the port
        self.safe_client.update_port(port['id'], admin_state_up=False)

        port_status_down_predicate = functools.partial(
            self._is_port_down, port['id'])
        utils.wait_until_true(port_status_down_predicate)
