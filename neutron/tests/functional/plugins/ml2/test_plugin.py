# Copyright (c) 2016 Red Hat, Inc.
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context

from neutron.db import agents_db
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class TestMl2PortBinding(ml2_test_base.ML2TestFramework,
                         agents_db.AgentDbMixin):
    def setUp(self):
        super(TestMl2PortBinding, self).setUp()
        self.admin_context = context.get_admin_context()
        self.host_args = {portbindings.HOST_ID: helpers.HOST,
                          'admin_state_up': True}

    def test_port_bind_successfully(self):
        helpers.register_ovs_agent(host=helpers.HOST)
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(
                        subnet=subnet, device_owner=DEVICE_OWNER_COMPUTE,
                        arg_list=(portbindings.HOST_ID, 'admin_state_up',),
                        **self.host_args) as port:
                    # Note: Port creation invokes _bind_port_if_needed(),
                    # therefore it is all we need in order to test a successful
                    # binding
                    self.assertEqual(port['port']['binding:vif_type'],
                                     portbindings.VIF_TYPE_OVS)

    def test_port_bind_retry(self):
        agent = helpers.register_ovs_agent(host=helpers.HOST)
        helpers.kill_agent(agent_id=agent.id)
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(
                        subnet=subnet, device_owner=DEVICE_OWNER_COMPUTE,
                        arg_list=(portbindings.HOST_ID, 'admin_state_up',),
                        **self.host_args) as port:
                    # Since the agent is dead, expect binding to fail
                    self.assertEqual(port['port']['binding:vif_type'],
                                     portbindings.VIF_TYPE_BINDING_FAILED)
                    helpers.revive_agent(agent.id)
                    # When an agent starts, The RPC call get_device_details()
                    # will invoke get_bound_port_context() which eventually use
                    # _bind_port_if_needed()
                    bound_context = self.plugin.get_bound_port_context(
                        self.admin_context, port['port']['id'], helpers.HOST)
                    # Since the agent is back online, expect binding to succeed
                    self.assertEqual(bound_context.vif_type,
                                     portbindings.VIF_TYPE_OVS)
                    self.assertEqual(bound_context.current['binding:vif_type'],
                                     portbindings.VIF_TYPE_OVS)
