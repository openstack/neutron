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

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api

from neutron.db import agents_db
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class TestMl2PortBinding(ml2_test_base.ML2TestFramework,
                         agents_db.AgentDbMixin):
    def setUp(self):
        super().setUp()
        self.admin_context = context.get_admin_context()
        self.host_args = {portbindings.HOST_ID: helpers.HOST,
                          'admin_state_up': True}
        self._max_bind_retries = ml2_plugin.MAX_BIND_TRIES
        ml2_plugin.MAX_BIND_TRIES = 1
        self.addCleanup(self._restore_max_bind_retries)

    def _restore_max_bind_retries(self):
        ml2_plugin.MAX_BIND_TRIES = self._max_bind_retries

    def test_port_bind_successfully(self):
        helpers.register_ovs_agent(host=helpers.HOST)
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(
                        subnet=subnet, device_owner=DEVICE_OWNER_COMPUTE,
                        is_admin=True,
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
                        is_admin=True,
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

    @mock.patch.object(ml2_plugin, 'LOG')
    def test_delete_port_no_binding_register(self, mock_log):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(
                        subnet=subnet, device_owner=DEVICE_OWNER_COMPUTE,
                        is_admin=True,
                        arg_list=(portbindings.HOST_ID, 'admin_state_up',),
                        **self.host_args) as port:
                    pass

        port_id = port['port']['id']
        ports = self._list('ports')['ports']
        self.assertEqual(1, len(ports))
        self.assertEqual(port_id, ports[0]['id'])
        with db_api.CONTEXT_WRITER.using(self.context):
            port_binding = self.context.session.query(
                models.PortBinding).filter(
                models.PortBinding.port_id == port_id).one()
            self.context.session.delete(port_binding)

        req = self.new_delete_request('ports', port['port']['id'])
        req.get_response(self.api)
        ports = self._list('ports')['ports']
        self.assertEqual(0, len(ports))
        mock_log.warning.assert_called_once_with(
            'The port %s has no binding information, the "ml2_port_bindings" '
            'register is not present', port_id)
