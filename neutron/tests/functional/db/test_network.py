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

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.db import l3_dvrscheduler_db
from neutron.objects import network as network_obj
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron import quota
from neutron.services.l3_router import l3_router_plugin
from neutron.tests.unit import testlib_api


class NetworkRBACTestCase(testlib_api.SqlTestCase):
    """Base class to test network RBAC policies"""

    def setUp(self):
        super(NetworkRBACTestCase, self).setUp()
        cfg.CONF.set_override('notify_nova_on_port_status_changes', False)
        DB_PLUGIN_KLASS = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.plugin = ml2_plugin.Ml2Plugin()
        self.mock_notify_l3_agent = mock.patch.object(
            l3_dvrscheduler_db, '_notify_l3_agent_new_port').start()
        self.plugin_l3 = l3_router_plugin.L3RouterPlugin()
        self.ctx = context.Context(user_id=None,
                                   tenant_id=None,
                                   is_admin=True,
                                   overwrite=False)
        self.tenant_1 = uuidutils.generate_uuid()
        self.tenant_2 = uuidutils.generate_uuid()
        self.network_id = uuidutils.generate_uuid()
        self.subnet_1_id = uuidutils.generate_uuid()
        self.subnet_2_id = uuidutils.generate_uuid()
        self.port_id = uuidutils.generate_uuid()
        quota_check = mock.patch.object(quota.QuotaEngine, 'quota_limit_check')
        self.mock_quota_check = quota_check.start()

    def _create_network(self, tenant_id, network_id, shared, external=False):
        network = {'tenant_id': tenant_id,
                   'id': network_id,
                   'name': 'test-net',
                   'admin_state_up': True,
                   'shared': shared,
                   extnet_apidef.EXTERNAL: external,
                   'status': constants.NET_STATUS_ACTIVE}
        return self.plugin.create_network(self.ctx, {'network': network})

    def _update_network(self, network_id, network):
        return self.plugin.update_network(self.ctx, network_id,
                                          {'network': network})

    def _create_subnet(self, tenant_id, subnet_id, shared, cidr=None):
        cidr = cidr if cidr else '10.10.10.0/24'
        subnet = {'tenant_id': tenant_id,
                  'id': subnet_id,
                  'name': 'test_sub',
                  'network_id': self.network_id,
                  'ip_version': constants.IP_VERSION_4,
                  'cidr': cidr,
                  'enable_dhcp': False,
                  'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                  'shared': shared,
                  'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                  'host_routes': constants.ATTR_NOT_SPECIFIED}
        return self.plugin.create_subnet(self.ctx, {'subnet': subnet})

    def _create_port(self, tenant_id, network_id, port_id):
        port = {'tenant_id': tenant_id,
                'name': 'test_port',
                'id': port_id,
                'network_id': network_id,
                'mac_address': constants.ATTR_NOT_SPECIFIED,
                'admin_state_up': True,
                'status': constants.PORT_STATUS_ACTIVE,
                'device_id': 'test_dev_id',
                'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX,
                'fixed_ips': constants.ATTR_NOT_SPECIFIED}
        return self.plugin.create_port(self.ctx, {'port': port})

    def _create_floating_ip(self, tenant_id, network_id):
        fip = {'tenant_id': tenant_id,
               'floating_network_id': network_id}
        return self.plugin_l3.create_floatingip(self.ctx, {'floatingip': fip})

    def _create_rbac(self, project_id, network_id, action, target_project):
        rbac = {'project_id': project_id,
                'object_id': network_id,
                'object_type': 'network',
                'target_project': target_project,
                'action': action}
        return self.plugin.create_rbac_policy(self.ctx, {'rbac_policy': rbac})

    def _delete_rbac(self, rbac_id):
        return self.plugin.delete_rbac_policy(self.ctx, rbac_id)

    def _list_networks(self, ctx):
        return self.plugin.get_networks(ctx)

    def _check_rbac(self, network_id, is_none, action):
        rbac = network_obj.NetworkRBAC.get_object(
            self.ctx, object_id=network_id, action=action, target_project='*')
        if is_none:
            self.assertIsNone(rbac)
        else:
            self.assertIsNotNone(rbac)

    def test_network_owner(self):
        tenant_1 = {
            'net-not-shared': (uuidutils.generate_uuid(), False),
            'net-shared': (uuidutils.generate_uuid(), True)}
        tenant_2 = {
            'net-not-shared': (uuidutils.generate_uuid(), False),
            'net-shared': (uuidutils.generate_uuid(), True)}
        for uuid, shared in tenant_1.values():
            self._create_network(self.tenant_1, uuid, shared)
            self._check_rbac(uuid, is_none=(not shared),
                             action=constants.ACCESS_SHARED)
        for uuid, shared in tenant_2.values():
            self._create_network(self.tenant_2, uuid, shared)
            self._check_rbac(uuid, is_none=(not shared),
                             action=constants.ACCESS_SHARED)

        ctx_1 = context.Context(user_id=None,
                                tenant_id=self.tenant_1,
                                is_admin=False,
                                overwrite=False)
        ctx_2 = context.Context(user_id=None,
                                tenant_id=self.tenant_2,
                                is_admin=False,
                                overwrite=False)

        nets_1 = [net['id'] for net in self._list_networks(ctx_1)]
        self.assertEqual(3, len(nets_1))
        self.assertIn(tenant_1['net-shared'][0], nets_1)
        self.assertIn(tenant_1['net-not-shared'][0], nets_1)
        self.assertIn(tenant_2['net-shared'][0], nets_1)

        nets_2 = [net['id'] for net in self._list_networks(ctx_2)]
        self.assertEqual(3, len(nets_2))
        self.assertIn(tenant_2['net-shared'][0], nets_2)
        self.assertIn(tenant_2['net-not-shared'][0], nets_2)
        self.assertIn(tenant_1['net-shared'][0], nets_2)

    def test_create_network_shared(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)

    def test_create_network_not_shared(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)

    def test_create_network_not_shared_external(self):
        with mock.patch.object(resource_extend, 'apply_funcs'):
            self._create_network(self.tenant_1, self.network_id, False,
                                 external=True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)

    def test_update_network_to_shared(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)
        network_data = {'shared': True}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)

    def test_update_network_to_no_shared_no_subnets(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)

        network_data = {'shared': False}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)

    def test_update_network_shared_to_external(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_EXTERNAL)

        network_data = {extnet_apidef.EXTERNAL: True}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)

    def test_update_network_shared_to_internal(self):
        self._create_network(self.tenant_1, self.network_id, True,
                             external=True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)

        network_data = {extnet_apidef.EXTERNAL: False}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_EXTERNAL)

    def test_update_network_to_no_shared_tenant_subnet(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)

        network_data = {'shared': False}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)

    def test_update_network_to_no_shared_no_tenant_subnet(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_subnet(self.tenant_2, self.subnet_2_id, True,
                            cidr='10.10.20/24')

        network_data = {'shared': False}
        self.assertRaises(n_exc.InvalidSharedSetting, self._update_network,
                          self.network_id, network_data)

    def test_ensure_no_port_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, '*')

    def test_ensure_no_port_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_port_in_tenant_2(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, self.tenant_2)

    def test_ensure_port_tenant_1_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_1, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, '*')

    def test_ensure_port_tenant_2_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.assertRaises(n_exc.InvalidSharedSetting,
                          self.plugin.ensure_no_tenant_ports_on_network,
                          self.ctx, self.network_id, self.tenant_1, '*')

    def test_ensure_port_tenant_1_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_1, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_share_port_tenant_2_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.ctx, self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_share_port_tenant_2_in_tenant_2(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.assertRaises(n_exc.InvalidSharedSetting,
                          self.plugin.ensure_no_tenant_ports_on_network,
                          self.ctx, self.network_id, self.tenant_1,
                          self.tenant_2)

    def _external_and_shared_network(self, project_id):
        self._create_network(self.tenant_1, self.network_id, False,
                             external=True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, False)
        self._create_floating_ip(project_id, self.network_id)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)

        # Add a RBAC with action=access_as_shared
        rbac_shared = self._create_rbac(
            self.tenant_1, self.network_id, action=constants.ACCESS_SHARED,
            target_project='*')
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)

        # Delete the created RBAC with action=access_as_shared. The FIP does
        # not interfere with the RBAC deletion because it can be created due
        # to the RBAC action=access_as_external.
        self._delete_rbac(rbac_shared['id'])
        self._check_rbac(self.network_id, is_none=True,
                         action=constants.ACCESS_SHARED)
        self._check_rbac(self.network_id, is_none=False,
                         action=constants.ACCESS_EXTERNAL)

    def test_external_network_update_shared_flag_own_project_fip(self):
        self._external_and_shared_network(self.tenant_1)

    def test_external_network_update_shared_flag_other_project_fip(self):
        self._external_and_shared_network(self.tenant_2)
