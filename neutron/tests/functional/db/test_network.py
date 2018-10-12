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

from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.objects import network as network_obj
from neutron.tests.unit import testlib_api


class NetworkRBACTestCase(testlib_api.SqlTestCase):
    """Base class to test network RBAC policies"""

    def setUp(self):
        super(NetworkRBACTestCase, self).setUp()
        cfg.CONF.set_override('notify_nova_on_port_status_changes', False)
        DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.plugin = base_plugin.NeutronDbPluginV2()
        self.cxt = context.Context(user_id=None,
                                   tenant_id=None,
                                   is_admin=True,
                                   overwrite=False)
        self.tenant_1 = uuidutils.generate_uuid()
        self.tenant_2 = uuidutils.generate_uuid()
        self.network_id = uuidutils.generate_uuid()
        self.subnet_1_id = uuidutils.generate_uuid()
        self.subnet_2_id = uuidutils.generate_uuid()
        self.port_id = uuidutils.generate_uuid()

    def _create_network(self, tenant_id, network_id, shared):
        network = {'tenant_id': tenant_id,
                   'id': network_id,
                   'name': 'test-net',
                   'admin_state_up': True,
                   'shared': shared,
                   'status': constants.NET_STATUS_ACTIVE}
        return self.plugin.create_network(self.cxt, {'network': network})

    def _update_network(self, network_id, network):
        return self.plugin.update_network(self.cxt, network_id,
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
        return self.plugin.create_subnet(self.cxt, {'subnet': subnet})

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
        return self.plugin.create_port(self.cxt, {'port': port})

    def _check_rbac(self, network_id, is_none=True):
        rbac = network_obj.NetworkRBAC.get_object(
            self.cxt, object_id=network_id, action='access_as_shared',
            target_tenant='*')
        if is_none:
            self.assertIsNone(rbac)
        else:
            self.assertIsNotNone(rbac)

    def test_create_network_shared(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, False)

    def test_create_network_not_shared(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._check_rbac(self.network_id)

    def test_update_network_to_shared(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._check_rbac(self.network_id)
        network_data = {'shared': True}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id, False)

    def test_update_network_to_no_shared_no_subnets(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, False)

        network_data = {'shared': False}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id)

    def test_update_network_to_no_shared_tenant_subnet(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)

        network_data = {'shared': False}
        self._update_network(self.network_id, network_data)
        self._check_rbac(self.network_id)

    def test_update_network_to_no_shared_no_tenant_subnet(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._check_rbac(self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_subnet(self.tenant_2, self.subnet_2_id, True,
                            cidr='10.10.20/24')

        network_data = {'shared': False}
        self.assertRaises(n_exc.InvalidSharedSetting, self._update_network,
                          self.network_id, network_data)

    def test_ensure_no_port_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, '*')

    def test_ensure_no_port_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_port_in_tenant_2(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, self.tenant_2)

    def test_ensure_port_tenant_1_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_1, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, '*')

    def test_ensure_port_tenant_2_in_asterisk(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.assertRaises(n_exc.InvalidSharedSetting,
                          self.plugin.ensure_no_tenant_ports_on_network,
                          self.network_id, self.tenant_1, '*')

    def test_ensure_port_tenant_1_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, True)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_1, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_share_port_tenant_2_in_tenant_1(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.plugin.ensure_no_tenant_ports_on_network(
            self.network_id, self.tenant_1, self.tenant_1)

    def test_ensure_no_share_port_tenant_2_in_tenant_2(self):
        self._create_network(self.tenant_1, self.network_id, False)
        self._create_subnet(self.tenant_1, self.subnet_1_id, True)
        self._create_port(self.tenant_2, self.network_id, self.port_id)
        self.assertRaises(n_exc.InvalidSharedSetting,
                          self.plugin.ensure_no_tenant_ports_on_network,
                          self.network_id, self.tenant_1, self.tenant_2)
