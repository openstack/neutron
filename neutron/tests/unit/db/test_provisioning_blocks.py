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

import mock
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_ctx
import testtools

from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.db import provisioning_blocks as pb
from neutron.objects import network as net_obj
from neutron.tests.unit import testlib_api

CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestStatusBarriers(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestStatusBarriers, self).setUp()
        self.setup_coreplugin(CORE_PLUGIN)
        self.ctx = n_ctx.get_admin_context()
        self.provisioned = mock.Mock()
        self.port = self._make_port()
        registry.subscribe(self.provisioned, resources.PORT,
                           pb.PROVISIONING_COMPLETE)

    def _make_net(self):
        network_obj = net_obj.Network(self.ctx, name='net_net',
                                      status='ACTIVE', project_id='1',
                                      admin_state_up=True)
        network_obj.create()
        return network_obj

    def _make_port(self):
        net = self._make_net()
        with db_api.context_manager.writer.using(self.ctx):
            port = models_v2.Port(network_id=net.id, mac_address='1',
                                  tenant_id='1', admin_state_up=True,
                                  status='DOWN', device_id='2',
                                  device_owner='3')
            self.ctx.session.add(port)
        return port

    def test_no_callback_on_missing_object(self):
        pb.provisioning_complete(self.ctx, 'someid', resources.PORT, 'entity')
        self.assertFalse(self.provisioned.called)

    def test_provisioned_with_no_components(self):
        pb.provisioning_complete(self.ctx, self.port.id, resources.PORT,
                                 'entity')
        self.assertTrue(self.provisioned.called)

    def test_provisioned_after_component_finishes(self):
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'entity')
        pb.provisioning_complete(self.ctx, self.port.id, resources.PORT,
                                 'entity')
        self.assertTrue(self.provisioned.called)

    def test_not_provisioned_until_final_component_complete(self):
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'entity1')
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'entity2')
        pb.provisioning_complete(self.ctx, self.port.id, resources.PORT,
                                 'entity1')
        self.assertFalse(self.provisioned.called)
        pb.provisioning_complete(self.ctx, self.port.id, resources.PORT,
                                 'entity2')
        self.assertTrue(self.provisioned.called)

    def test_provisioning_of_correct_item(self):
        port2 = self._make_port()
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'entity1')
        pb.provisioning_complete(self.ctx, port2.id,
                                 resources.PORT, 'entity1')
        self.provisioned.assert_called_once_with(
            resources.PORT, pb.PROVISIONING_COMPLETE, mock.ANY,
            context=self.ctx, object_id=port2.id)

    def test_not_provisioned_when_wrong_component_reports(self):
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'entity1')
        pb.provisioning_complete(self.ctx, self.port.id,
                                 resources.PORT, 'entity2')
        self.assertFalse(self.provisioned.called)

    def test_is_object_blocked(self):
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'e1')
        self.assertTrue(pb.is_object_blocked(self.ctx, self.port.id,
                                             resources.PORT))
        self.assertFalse(pb.is_object_blocked(self.ctx, 'xyz',
                                              resources.PORT))
        pb.provisioning_complete(self.ctx, self.port.id,
                                 resources.PORT, 'e1')
        self.assertFalse(pb.is_object_blocked(self.ctx, self.port.id,
                                              resources.PORT))

    def test_remove_provisioning_component(self):
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'e1')
        pb.add_provisioning_component(self.ctx, self.port.id, resources.PORT,
                                      'e2')
        self.assertTrue(pb.remove_provisioning_component(
              self.ctx, self.port.id, resources.PORT, 'e1'))
        self.assertFalse(self.provisioned.called)
        pb.provisioning_complete(self.ctx, self.port.id,
                                 resources.PORT, 'other')
        self.assertFalse(self.provisioned.called)
        pb.provisioning_complete(self.ctx, self.port.id,
                                 resources.PORT, 'e2')
        self.assertTrue(self.provisioned.called)

    def test_adding_component_idempotent(self):
        for i in range(5):
            pb.add_provisioning_component(self.ctx, self.port.id,
                                          resources.PORT, 'entity1')
        pb.provisioning_complete(self.ctx, self.port.id,
                                 resources.PORT, 'entity1')
        self.assertTrue(self.provisioned.called)

    def test_adding_component_for_new_resource_type(self):
        provisioned = mock.Mock()
        registry.subscribe(provisioned, 'NETWORK', pb.PROVISIONING_COMPLETE)
        net = self._make_net()
        # expect failed because the model was not registered for the type
        with testtools.ExpectedException(RuntimeError):
            pb.add_provisioning_component(self.ctx, net.id, 'NETWORK', 'ent')
        pb.add_model_for_resource('NETWORK', models_v2.Network)
        pb.add_provisioning_component(self.ctx, net.id, 'NETWORK', 'ent')
        pb.provisioning_complete(self.ctx, net.id, 'NETWORK', 'ent')
        self.assertTrue(provisioned.called)
