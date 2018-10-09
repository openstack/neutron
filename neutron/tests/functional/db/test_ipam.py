# Copyright 2015 SUSE Linux Products GmbH
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

import netaddr
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.objects import ports as port_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests.unit import testlib_api


# required in order for testresources to optimize same-backend
# tests together
load_tests = testlib_api.module_load_tests
# FIXME(zzzeek): needs to be provided by oslo.db, current version
# is not working
# load_tests = test_base.optimize_db_test_loader(__file__)


class IpamTestCase(testlib_api.SqlTestCase):
    """Base class for tests that aim to test ip allocation."""
    def setUp(self):
        super(IpamTestCase, self).setUp()
        cfg.CONF.set_override('notify_nova_on_port_status_changes', False)
        DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.plugin = base_plugin.NeutronDbPluginV2()
        self.cxt = context.Context(user_id=None,
                                   tenant_id=None,
                                   is_admin=True,
                                   overwrite=False)
        self.tenant_id = uuidutils.generate_uuid()
        self.network_id = uuidutils.generate_uuid()
        self.subnet_id = uuidutils.generate_uuid()
        self.port_id = uuidutils.generate_uuid()
        self._create_network()
        self._create_subnet()

    def result_set_to_dicts(self, resultset, keys):
        dicts = []
        for item in resultset:
            item_dict = dict((x, item[x]) for x in keys)
            dicts.append(item_dict)
        return dicts

    def assert_ip_alloc_matches(self, expected):
        result_set = port_obj.IPAllocation.get_objects(self.cxt)
        keys = ['port_id', 'ip_address', 'subnet_id', 'network_id']
        actual = self.result_set_to_dicts(result_set, keys)
        self.assertEqual(expected, actual)

    def assert_ip_alloc_pool_matches(self, expected):
        result_set = subnet_obj.IPAllocationPool.get_objects(self.cxt)
        keys = ['start', 'end', 'subnet_id']
        actual = self.result_set_to_dicts(result_set, keys)
        self.assertEqual(expected, actual)

    def _create_network(self):
        network = {'tenant_id': self.tenant_id,
                   'id': self.network_id,
                   'name': 'test-net',
                   'admin_state_up': True,
                   'shared': False,
                   'status': constants.NET_STATUS_ACTIVE}
        return self.plugin.create_network(self.cxt, {'network': network})

    def _create_subnet(self):
        subnet = {'tenant_id': self.tenant_id,
                  'id': self.subnet_id,
                  'name': 'test_sub',
                  'network_id': self.network_id,
                  'ip_version': constants.IP_VERSION_4,
                  'cidr': '10.10.10.0/29',
                  'enable_dhcp': False,
                  'gateway_ip': '10.10.10.1',
                  'shared': False,
                  'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                  'host_routes': constants.ATTR_NOT_SPECIFIED}
        return self.plugin.create_subnet(self.cxt, {'subnet': subnet})

    def _create_port(self, port_id, fixed_ips=None):
        port_fixed_ips = (fixed_ips if fixed_ips else
                          constants.ATTR_NOT_SPECIFIED)
        port = {'tenant_id': self.tenant_id,
                'name': 'test_port',
                'id': port_id,
                'network_id': self.network_id,
                'mac_address': constants.ATTR_NOT_SPECIFIED,
                'admin_state_up': True,
                'status': constants.PORT_STATUS_ACTIVE,
                'device_id': 'test_dev_id',
                'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX,
                'fixed_ips': port_fixed_ips}
        self.plugin.create_port(self.cxt, {'port': port})

    def test_allocate_fixed_ip(self):
        fixed_ip = [{'ip_address': "10.10.10.3", 'subnet_id': self.subnet_id}]
        self._create_port(self.port_id, fixed_ip)

        ip_alloc_expected = [{'port_id': self.port_id,
                              'ip_address': netaddr.IPAddress(
                                  fixed_ip[0].get('ip_address')),
                              'subnet_id': self.subnet_id,
                              'network_id': self.network_id}]
        ip_alloc_pool_expected = [{'start': netaddr.IPAddress('10.10.10.2'),
                                   'end': netaddr.IPAddress('10.10.10.6'),
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_matches(ip_alloc_expected)
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)

    def test_allocate_ip_exausted_pool(self):
        # available from .2 up to .6 -> 5
        for i in range(1, 6):
            self._create_port(uuidutils.generate_uuid())

        ip_alloc_pool_expected = [{'start': netaddr.IPAddress('10.10.10.2'),
                                   'end': netaddr.IPAddress('10.10.10.6'),
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        with testtools.ExpectedException(n_exc.IpAddressGenerationFailure):
            self._create_port(self.port_id)


class TestIpamMySql(testlib_api.MySQLTestCaseMixin, IpamTestCase):
    pass


class TestIpamPsql(testlib_api.PostgreSQLTestCaseMixin, IpamTestCase):
    pass
