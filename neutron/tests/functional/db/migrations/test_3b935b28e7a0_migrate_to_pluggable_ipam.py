# Copyright 2016 Infoblox Inc.
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

from neutron_lib import constants
from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


class MigrationToPluggableIpamMixin(object):
    """Validates data migration to Pluggable IPAM."""

    _standard_attribute_id = 0

    def _gen_attr_id(self, engine, type):
        self._standard_attribute_id += 1
        standardattributes = db_utils.get_table(engine, 'standardattributes')
        engine.execute(standardattributes.insert().values({
            'id': self._standard_attribute_id, 'resource_type': type}))
        return self._standard_attribute_id

    def _create_subnets(self, engine, data):
        """Create subnets and saves subnet id in data"""
        networks = db_utils.get_table(engine, 'networks')
        subnets = db_utils.get_table(engine, 'subnets')
        pools = db_utils.get_table(engine, 'ipallocationpools')
        allocations = db_utils.get_table(engine, 'ipallocations')

        for cidr in data:
            ip_version = (constants.IP_VERSION_6 if ':' in cidr else
                          constants.IP_VERSION_4)
            # Save generated id in incoming dict to simplify validations
            network_id = uuidutils.generate_uuid()
            network_dict = dict(
                id=network_id,
                standard_attr_id=self._gen_attr_id(engine, 'networks'))
            engine.execute(networks.insert().values(network_dict))

            data[cidr]['id'] = uuidutils.generate_uuid()
            subnet_dict = dict(id=data[cidr]['id'],
                               cidr=cidr,
                               ip_version=ip_version,
                               standard_attr_id=self._gen_attr_id(engine,
                                                                  'subnets'),
                               network_id=network_id)
            engine.execute(subnets.insert().values(subnet_dict))

            if data[cidr].get('pools'):
                for pool in data[cidr]['pools']:
                    pool_dict = dict(id=uuidutils.generate_uuid(),
                                     first_ip=pool['first_ip'],
                                     last_ip=pool['last_ip'],
                                     subnet_id=data[cidr]['id'])
                    engine.execute(pools.insert().values(pool_dict))

            if data[cidr].get('allocations'):
                for ip in data[cidr]['allocations']:
                    ip_dict = dict(ip_address=ip,
                                   subnet_id=data[cidr]['id'],
                                   network_id=network_id)
                    engine.execute(allocations.insert().values(ip_dict))

    def _pre_upgrade_3b935b28e7a0(self, engine):
        data = {
            '172.23.0.0/16': {
                'pools': [{'first_ip': '172.23.0.2',
                           'last_ip': '172.23.255.254'}],
                'allocations': ('172.23.0.2', '172.23.245.2')},
            '192.168.40.0/24': {
                'pools': [{'first_ip': '192.168.40.2',
                           'last_ip': '192.168.40.100'},
                          {'first_ip': '192.168.40.105',
                           'last_ip': '192.168.40.150'},
                          {'first_ip': '192.168.40.155',
                           'last_ip': '192.168.40.157'},
                          ],
                'allocations': ('192.168.40.2', '192.168.40.3',
                                '192.168.40.15', '192.168.40.60')},
            'fafc:babc::/64': {
                'pools': [{'first_ip': 'fafc:babc::2',
                           'last_ip': 'fafc:babc::6:fe00',
                           }],
                'allocations': ('fafc:babc::3',)}}
        self._create_subnets(engine, data)
        return data

    def _check_3b935b28e7a0(self, engine, data):
        subnets = db_utils.get_table(engine, 'ipamsubnets')
        pools = db_utils.get_table(engine, 'ipamallocationpools')
        allocations = db_utils.get_table(engine, 'ipamallocations')

        ipam_subnets = engine.execute(subnets.select()).fetchall()
        # Count of ipam subnets should match count of usual subnets
        self.assertEqual(len(data), len(ipam_subnets))
        neutron_to_ipam_id = {subnet.neutron_subnet_id: subnet.id
                              for subnet in ipam_subnets}
        for cidr in data:
            self.assertIn(data[cidr]['id'], neutron_to_ipam_id)

            ipam_subnet_id = neutron_to_ipam_id[data[cidr]['id']]
            # Validate ip allocations are migrated correctly
            ipam_allocations = engine.execute(allocations.select().where(
                allocations.c.ipam_subnet_id == ipam_subnet_id)).fetchall()
            for ipam_allocation in ipam_allocations:
                self.assertIn(ipam_allocation.ip_address,
                              data[cidr]['allocations'])
            self.assertEqual(len(data[cidr]['allocations']),
                             len(ipam_allocations))

            # Validate allocation pools are migrated correctly
            ipam_pools = engine.execute(pools.select().where(
                pools.c.ipam_subnet_id == ipam_subnet_id)).fetchall()
            # Covert to dict for easier lookup
            pool_dict = {pool.first_ip: pool.last_ip for pool in ipam_pools}
            for p in data[cidr]['pools']:
                self.assertIn(p['first_ip'], pool_dict)
                self.assertEqual(p['last_ip'], pool_dict[p['first_ip']])
            self.assertEqual(len(data[cidr]['pools']),
                             len(ipam_pools))


class TestMigrationToPluggableIpamMysql(MigrationToPluggableIpamMixin,
                                    test_migrations.TestWalkMigrationsMysql):
    pass


class TestMigrationToPluggableIpamPsql(MigrationToPluggableIpamMixin,
                                    test_migrations.TestWalkMigrationsPsql):
    pass
