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
#

from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import qos_fip as qos_fip_apidef
from neutron_lib import context
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.conf.db import extraroute_db
from neutron.db import l3_fip_qos
from neutron.extensions import l3
from neutron.objects.qos import policy
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.extensions import test_l3


class FloatingIPQoSTestExtensionManager:

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFloatingIPQoSIntPlugin(
        test_l3.TestL3NatIntPlugin,
        l3_fip_qos.FloatingQoSDbMixin):
    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   qos_fip_apidef.ALIAS]


class TestFloatingIPQoSL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        l3_fip_qos.FloatingQoSDbMixin):
    supported_extension_aliases = [l3_apidef.ALIAS, 'qos',
                                   qos_fip_apidef.ALIAS]


class FloatingIPQoSDBTestCaseBase:

    def test_create_fip_with_qos_policy_id(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id,
                qos_policy_id=policy_obj.id)
            self.assertEqual(policy_obj.id,
                             fip['floatingip'][qos_consts.QOS_POLICY_ID])

    def test_fip_has_qos_policy_id_remove_policy(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id,
                qos_policy_id=policy_obj.id)
            self.assertEqual(policy_obj.id,
                             fip['floatingip'][qos_consts.QOS_POLICY_ID])
            self.assertRaises(qos_exc.QosPolicyInUse, policy_obj.delete)

    def test_floatingip_update_qos_policy_id(self):
        ctx = context.get_admin_context()
        policy_obj_1 = policy.QosPolicy(ctx,
                                        id=uuidutils.generate_uuid(),
                                        project_id='tenant', name='pol2',
                                        rules=[])
        policy_obj_1.create()
        policy_obj_2 = policy.QosPolicy(ctx,
                                        id=uuidutils.generate_uuid(),
                                        project_id='tenant', name='pol3',
                                        rules=[])
        policy_obj_2.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id,
                qos_policy_id=policy_obj_1.id)
            self.assertEqual(policy_obj_1.id,
                             fip['floatingip'][qos_consts.QOS_POLICY_ID])
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertEqual(policy_obj_1.id,
                             body['floatingip'][qos_consts.QOS_POLICY_ID])

            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: policy_obj_2.id}})
            self.assertEqual(policy_obj_2.id,
                             body['floatingip'][qos_consts.QOS_POLICY_ID])
            updated_revision_number = body['floatingip'].get('revision_number')
            fip_revision_number = fip['floatingip'].get('revision_number')
            if updated_revision_number and fip_revision_number:
                self.assertGreater(updated_revision_number,
                                   fip_revision_number)

    def test_floatingip_adding_qos_policy_id_by_update(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol4',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id)
            self.assertIsNone(fip['floatingip'].get(qos_consts.QOS_POLICY_ID))
            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: policy_obj.id}})

            body = self._show('floatingips', body['floatingip']['id'])
            self.assertEqual(policy_obj.id,
                             body['floatingip'][qos_consts.QOS_POLICY_ID])

    def _update_fip_with_port_or_qos_and_verify(
            self, fip_id, port_id=None, qos_policy_id=None,
            revision_number=None):
        update_body = {'floatingip': {
            'port_id': port_id,
            qos_consts.QOS_POLICY_ID: qos_policy_id}}
        body = self._update('floatingips', fip_id, update_body)
        body = self._show('floatingips', body['floatingip']['id'])
        self.assertEqual(port_id,
                         body['floatingip']['port_id'])
        self.assertEqual(qos_policy_id,
                         body['floatingip'].get(qos_consts.QOS_POLICY_ID))
        updated_revision_number = body['floatingip'].get('revision_number')
        if updated_revision_number and revision_number:
            self.assertGreater(updated_revision_number,
                               revision_number)

    def test_floatingip_update_with_port_and_qos(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol4',
                                      rules=[])
        policy_obj.create()
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(
                ext_net, cidr='10.10.10.0/24'
            ), self.router() as router, self.subnet(
                cidr='11.0.0.0/24') as private_subnet, self.port(
                    private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                self.assertIsNone(
                    fip['floatingip'].get(qos_consts.QOS_POLICY_ID))
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    port['port']['id'],
                    policy_obj.id,
                    revision_number=fip['floatingip'].get('revision_number'))

    def test_floatingip_update_with_port_and_qos_scenarios(self):
        ctx = context.get_admin_context()
        policy_obj_1 = policy.QosPolicy(ctx,
                                        id=uuidutils.generate_uuid(),
                                        project_id='tenant', name='pol2',
                                        rules=[])
        policy_obj_1.create()
        policy_obj_2 = policy.QosPolicy(ctx,
                                        id=uuidutils.generate_uuid(),
                                        project_id='tenant', name='pol3',
                                        rules=[])
        policy_obj_2.create()
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(
                ext_net, cidr='10.10.10.0/24'
            ), self.router() as router, self.subnet(
                cidr='11.0.0.0/24') as private_subnet, self.port(
                    private_subnet) as port_1, self.port(
                        private_subnet) as port_2:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(self.fmt, network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                self.assertIsNone(
                    fip['floatingip'].get(qos_consts.QOS_POLICY_ID))

                # update from: {port_id: null, qos_policy_id: null}
                #        to  : {port_id: port_id_1, qos_policy_id: null}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    port_1['port']['id'],
                    None,
                    revision_number=fip['floatingip'].get('revision_number'))

                # update from: {port_id: port_id_1, qos_policy_id: null}
                #        to  : {port_id: port_id_1, qos_policy_id: policy_1}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    port_1['port']['id'],
                    policy_obj_1.id)

                # update from: {port_id: port_id_1, qos_policy_id: policy_1}
                #        to  : {port_id: port_id_2, qos_policy_id: policy_2}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    port_2['port']['id'],
                    policy_obj_2.id)

                # update from: {port_id: port_id_2, qos_policy_id: policy_2}
                #        to  : {port_id: port_id_1, qos_policy_id: null}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    port_1['port']['id'],
                    None)

                # update from: {port_id: port_id_1, qos_policy_id: null}
                #        to  : {port_id: null, qos_policy_id: policy_1}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'],
                    None,
                    policy_obj_1.id)

                # update from: {port_id: null, qos_policy_id: policy_1}
                #        to  : {port_id: null, qos_policy_id: null}
                self._update_fip_with_port_or_qos_and_verify(
                    fip['floatingip']['id'])

    def test_floatingip_remove_qos_policy_id(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol5',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id,
                qos_policy_id=policy_obj.id)
            self.assertEqual(policy_obj.id,
                             fip['floatingip'][qos_consts.QOS_POLICY_ID])

            self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: None}})
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertIsNone(
                body['floatingip'].get(qos_consts.QOS_POLICY_ID))

    def test_floatingip_update_change_nothing(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id='tenant', name='pol2',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fip = self._make_floatingip(
                self.fmt,
                network_id)
            self.assertIsNone(fip['floatingip'].get(qos_consts.QOS_POLICY_ID))

            # Updating policy_id from None to None
            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: None}})
            self.assertIsNone(
                body['floatingip'].get(qos_consts.QOS_POLICY_ID))
            body = self._show('floatingips', fip['floatingip']['id'])
            self.assertIsNone(
                body['floatingip'].get(qos_consts.QOS_POLICY_ID))

            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: policy_obj.id}})
            self.assertEqual(policy_obj.id,
                             body['floatingip'][qos_consts.QOS_POLICY_ID])
            # Updating again with same policy_id
            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {qos_consts.QOS_POLICY_ID: policy_obj.id}})
            self.assertEqual(policy_obj.id,
                             body['floatingip'][qos_consts.QOS_POLICY_ID])


class FloatingIPQoSDBIntTestCase(test_l3.L3BaseForIntTests,
                                 test_l3.L3NatTestCaseMixin,
                                 FloatingIPQoSDBTestCaseBase):

    def setUp(self, plugin=None, service_plugins=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_qos_fip.'
                      'TestFloatingIPQoSIntPlugin')
        if not service_plugins:
            service_plugins = {'qos': 'neutron.services.qos.qos_plugin.'
                                      'QoSPlugin'}

        extraroute_db.register_db_extraroute_opts()
        cfg.CONF.set_default('max_routes', 3)

        ext_mgr = FloatingIPQoSTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()


class FloatingIPQoSDBSepTestCase(test_l3.L3BaseForSepTests,
                                 test_l3.L3NatTestCaseMixin,
                                 FloatingIPQoSDBTestCaseBase):

    def setUp(self, service_plugins=None):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        if not service_plugins:
            l3_plugin = ('neutron.tests.unit.extensions.test_qos_fip.'
                         'TestFloatingIPQoSL3NatServicePlugin')
            service_plugins = {'l3_plugin_name': l3_plugin,
                               'qos': 'neutron.services.qos.qos_plugin.'
                                      'QoSPlugin'}

        extraroute_db.register_db_extraroute_opts()
        cfg.CONF.set_default('max_routes', 3)

        ext_mgr = FloatingIPQoSTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()


class FloatingIPQoSDBWithRevisionIntTestCase(FloatingIPQoSDBIntTestCase):

    def setUp(self, plugin=None):
        service_plugins = {'qos': 'neutron.services.qos.qos_plugin.QoSPlugin',
                           'revision_plugin_name': 'revisions'}
        super().setUp(
            service_plugins=service_plugins)
        revision_plugin.RevisionPlugin()


class FloatingIPQoSDBWithRevisionSepTestCase(FloatingIPQoSDBSepTestCase):

    def setUp(self):
        l3_plugin = ('neutron.tests.unit.extensions.test_qos_fip.'
                     'TestFloatingIPQoSL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin,
                           'qos': 'neutron.services.qos.qos_plugin.QoSPlugin',
                           'revision_plugin_name': 'revisions'}
        super().setUp(
            service_plugins=service_plugins)
        revision_plugin.RevisionPlugin()
