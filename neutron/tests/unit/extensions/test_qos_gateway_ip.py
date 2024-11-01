# Copyright 2018 OpenStack Foundation
# Copyright 2017 Letv Cloud Computing
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
#

from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode
from neutron_lib.api.definitions import qos_gateway_ip
from neutron_lib import context
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.conf.db import extraroute_db
from neutron.db import l3_gateway_ip_qos
from neutron.extensions import l3
from neutron.objects.qos import binding
from neutron.objects.qos import policy
from neutron.tests.unit.extensions import test_l3


class GatewayIPQoSTestExtensionManager:

    def get_resources(self):
        l3_apidef.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            qos_gateway_ip.RESOURCE_ATTRIBUTE_MAP['routers'])
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestGatewayIPQoSIntPlugin(
        test_l3.TestL3NatIntPlugin,
        l3_gateway_ip_qos.L3_gw_ip_qos_db_mixin):
    supported_extension_aliases = [enet_apidef.ALIAS,
                                   l3_apidef.ALIAS,
                                   l3_ext_gw_mode.ALIAS,
                                   qos_gateway_ip.ALIAS]


class TestGatewayIPQoSL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        l3_gateway_ip_qos.L3_gw_ip_qos_db_mixin):
    supported_extension_aliases = [l3_apidef.ALIAS,
                                   l3_ext_gw_mode.ALIAS,
                                   qos_gateway_ip.ALIAS]


class GatewayIPQoSDBTestCaseBase:

    def test_create_router_gateway_with_qos_policy(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id=self._tenant_id, name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                policy_id=policy_obj.id)
            self.assertEqual(
                policy_obj.id,
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))

    def test_update_router_gateway_with_qos_policy(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id=self._tenant_id, name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self.assertIsNone(
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))

            # update router gateway
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                policy_id=policy_obj.id)
            self.assertEqual(
                policy_obj.id,
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))

    def test_clear_router_gateway_and_create_again(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id=self._tenant_id, name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                policy_id=policy_obj.id)
            self.assertEqual(
                policy_obj.id,
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))
            gw_binding = binding.QosPolicyRouterGatewayIPBinding.get_object(
                ctx, router_id=r['router']['id'])
            self.assertEqual(r['router']['id'], gw_binding.router_id)

            # Clear router gateway, the QoS policy must be removed.
            self._remove_external_gateway_from_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                external_gw_info={})
            gw_binding = binding.QosPolicyRouterGatewayIPBinding.get_object(
                ctx, router_id=r['router']['id'])
            self.assertIsNone(gw_binding)

            # Create router gateway again.
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self.assertIsNone(res['router']['external_gateway_info'].get(
                qos_consts.QOS_POLICY_ID))

    def test_clear_router_gateway_qos_policy(self):
        ctx = context.get_admin_context()
        policy_obj = policy.QosPolicy(ctx,
                                      id=uuidutils.generate_uuid(),
                                      project_id=self._tenant_id, name='pol1',
                                      rules=[])
        policy_obj.create()
        with self.subnet(cidr='11.0.0.0/24') as public_sub,\
                self.router() as r:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'])
            self.assertIsNone(
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))

            # update router gateway
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                policy_id=policy_obj.id)
            self.assertEqual(
                policy_obj.id,
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))

            # Explicitly clear router gateway qos policy binding
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                public_sub['subnet']['network_id'],
                policy_id=None,
                is_remove=True)
            self.assertIsNone(
                res['router']['external_gateway_info'].get(
                    qos_consts.QOS_POLICY_ID))


class GatewayIPQoSDBIntTestCase(test_l3.L3BaseForIntTests,
                                test_l3.L3NatTestCaseMixin,
                                GatewayIPQoSDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_qos_gateway_ip.'
                      'TestGatewayIPQoSIntPlugin')
        service_plugins = {'qos': 'neutron.services.qos.qos_plugin.QoSPlugin'}

        extraroute_db.register_db_extraroute_opts()
        cfg.CONF.set_default('max_routes', 3)

        ext_mgr = GatewayIPQoSTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()


class GatewayIPQoSDBSepTestCase(test_l3.L3BaseForSepTests,
                                test_l3.L3NatTestCaseMixin,
                                GatewayIPQoSDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_qos_gateway_ip.'
                     'TestGatewayIPQoSL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin,
                           'qos': 'neutron.services.qos.qos_plugin.QoSPlugin'}

        extraroute_db.register_db_extraroute_opts()
        cfg.CONF.set_default('max_routes', 3)

        ext_mgr = GatewayIPQoSTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
