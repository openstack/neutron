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

from oslo_config import cfg
from oslo_db.sqlalchemy import session
from oslo_db.sqlalchemy import test_base
import testtools

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import model_base
from neutron.db import models_v2
from neutron.tests import base


def get_admin_test_context(db_url):
    """
    get_admin_test_context is used to provide a test context. A new session is
    created using the db url specified
    """
    ctx = context.Context(user_id=None,
                          tenant_id=None,
                          is_admin=True,
                          read_deleted="no",
                          load_admin_roles=True,
                          overwrite=False)
    facade = session.EngineFacade(db_url, mysql_sql_mode='STRICT_ALL_TABLES')
    ctx._session = facade.get_session(autocommit=False, expire_on_commit=True)
    return ctx


class IpamTestCase(object):
    """
    Base class for tests that aim to test ip allocation.
    """

    def configure_test(self):
        model_base.BASEV2.metadata.create_all(self.engine)
        cfg.CONF.set_override('notify_nova_on_port_status_changes', False)
        self.plugin = base_plugin.NeutronDbPluginV2()
        self.cxt = get_admin_test_context(self.engine.url)
        self.addCleanup(self.cxt._session.close)
        self.tenant_id = 'test_tenant'
        self.network_id = 'test_net_id'
        self.subnet_id = 'test_sub_id'
        self.port_id = 'test_p_id'
        self._create_network()
        self._create_subnet()

    def result_set_to_dicts(self, resultset, keys):
        dicts = []
        for item in resultset:
            item_dict = dict((x, item[x]) for x in keys)
            dicts.append(item_dict)
        return dicts

    def assert_ip_alloc_matches(self, expected):
        result_set = self.cxt.session.query(models_v2.IPAllocation).all()
        keys = ['port_id', 'ip_address', 'subnet_id', 'network_id']
        actual = self.result_set_to_dicts(result_set, keys)
        self.assertEqual(expected, actual)

    def assert_ip_avail_range_matches(self, expected):
        result_set = self.cxt.session.query(
            models_v2.IPAvailabilityRange).all()
        keys = ['first_ip', 'last_ip']
        actual = self.result_set_to_dicts(result_set, keys)
        self.assertEqual(expected, actual)

    def assert_ip_alloc_pool_matches(self, expected):
        result_set = self.cxt.session.query(models_v2.IPAllocationPool).all()
        keys = ['first_ip', 'last_ip', 'subnet_id']
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
                  'ip_version': 4,
                  'cidr': '10.10.10.0/29',
                  'enable_dhcp': False,
                  'gateway_ip': '10.10.10.1',
                  'shared': False,
                  'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                  'host_routes': attributes.ATTR_NOT_SPECIFIED}
        return self.plugin.create_subnet(self.cxt, {'subnet': subnet})

    def _create_port(self, port_id, fixed_ips=None):
        port_fixed_ips = (fixed_ips if fixed_ips else
                          attributes.ATTR_NOT_SPECIFIED)
        port = {'tenant_id': self.tenant_id,
                'name': 'test_port',
                'id': port_id,
                'network_id': self.network_id,
                'mac_address': attributes.ATTR_NOT_SPECIFIED,
                'admin_state_up': True,
                'status': constants.PORT_STATUS_ACTIVE,
                'device_id': 'test_dev_id',
                'device_owner': 'compute',
                'fixed_ips': port_fixed_ips}
        self.plugin.create_port(self.cxt, {'port': port})

    def test_allocate_fixed_ip(self):
        fixed_ip = [{'ip_address': "10.10.10.3", 'subnet_id': self.subnet_id}]
        self._create_port(self.port_id, fixed_ip)

        ip_alloc_expected = [{'port_id': self.port_id,
                              'ip_address': fixed_ip[0].get('ip_address'),
                              'subnet_id': self.subnet_id,
                              'network_id': self.network_id}]
        ip_avail_ranges_expected = [{'first_ip': '10.10.10.2',
                                     'last_ip': '10.10.10.2'},
                                    {'first_ip': '10.10.10.4',
                                     'last_ip': '10.10.10.6'}]
        ip_alloc_pool_expected = [{'first_ip': '10.10.10.2',
                                   'last_ip': '10.10.10.6',
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_matches(ip_alloc_expected)
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        self.assert_ip_avail_range_matches(
            ip_avail_ranges_expected)

    def test_allocate_first_available_ip(self):
        self._create_port(self.port_id)
        ip_alloc_expected = [{'port_id': self.port_id,
                              'ip_address': '10.10.10.2',
                              'subnet_id': self.subnet_id,
                              'network_id': self.network_id}]
        ip_avail_ranges_expected = [{'first_ip': '10.10.10.3',
                                     'last_ip': '10.10.10.6'}]
        ip_alloc_pool_expected = [{'first_ip': '10.10.10.2',
                                   'last_ip': '10.10.10.6',
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_matches(ip_alloc_expected)
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        self.assert_ip_avail_range_matches(
            ip_avail_ranges_expected)

    def test_allocate_ip_exausted_pool(self):
        # available from .2 up to .6 -> 5
        for i in range(1, 6):
            self._create_port(self.port_id + str(i))

        ip_avail_ranges_expected = []
        ip_alloc_pool_expected = [{'first_ip': '10.10.10.2',
                                   'last_ip': '10.10.10.6',
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        self.assert_ip_avail_range_matches(
            ip_avail_ranges_expected)
        # Create another port
        with testtools.ExpectedException(n_exc.IpAddressGenerationFailure):
            self._create_port(self.port_id)

    def test_rebuild_availability_range(self):
        for i in range(1, 6):
            self._create_port(self.port_id + str(i))

        ip_avail_ranges_expected = []
        ip_alloc_pool_expected = [{'first_ip': '10.10.10.2',
                                   'last_ip': '10.10.10.6',
                                   'subnet_id': self.subnet_id}]
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        self.assert_ip_avail_range_matches(
            ip_avail_ranges_expected)
        # Delete some ports, this will free the first two IPs
        for i in range(1, 3):
            self.plugin.delete_port(self.cxt, self.port_id + str(i))
        # Create another port, this will trigger the rebuilding of the
        # availability ranges
        self._create_port(self.port_id)
        ip_avail_ranges_expected = [{'first_ip': '10.10.10.3',
                                     'last_ip': '10.10.10.3'}]

        ip_alloc = self.cxt.session.query(models_v2.IPAllocation).all()
        self.assertEqual(4, len(ip_alloc))
        self.assert_ip_alloc_pool_matches(ip_alloc_pool_expected)
        self.assert_ip_avail_range_matches(
            ip_avail_ranges_expected)


class TestIpamMySql(test_base.MySQLOpportunisticTestCase, base.BaseTestCase,
                    IpamTestCase):

    def setUp(self):
        super(TestIpamMySql, self).setUp()
        self.configure_test()


class TestIpamPsql(test_base.PostgreSQLOpportunisticTestCase,
                   base.BaseTestCase, IpamTestCase):

    def setUp(self):
        super(TestIpamPsql, self).setUp()
        self.configure_test()
