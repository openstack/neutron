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

from designateclient import exceptions as d_exc
from neutron_lib.exceptions import dns as dns_exc
from oslo_config import cfg

from neutron.services.externaldns.drivers.designate import driver
from neutron.tests import base


class TestDesignateDriver(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.context = mock.Mock()
        self.client = mock.Mock()
        self.admin_client = mock.Mock()
        self.all_projects_client = mock.Mock()
        mock.patch.object(driver, 'get_clients', return_value=(
            self.client, self.admin_client)).start()
        mock.patch.object(driver, 'get_all_projects_client',
                          return_value=self.all_projects_client).start()
        self.driver = driver.Designate()

    def test_create_record_set(self):
        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate'
        )

        self.driver.create_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1']
        )

        self.client.recordsets.create.assert_has_calls(
            [
                mock.call('example.test.', 'test', 'A', ['192.168.0.10']),
                mock.call('example.test.', 'test', 'AAAA', ['2001:db8:0:1::1'])
            ]
        )
        self.admin_client.recordsets.create.assert_not_called()

    def test_create_record_set_with_reverse_dns(self):
        self.driver.create_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1']
        )

        self.client.recordsets.create.assert_has_calls(
            [
                mock.call('example.test.', 'test', 'A', ['192.168.0.10']),
                mock.call('example.test.', 'test', 'AAAA', ['2001:db8:0:1::1'])
            ]
        )

        self.admin_client.recordsets.create.assert_has_calls(
            [
                mock.call(
                    '0.168.192.in-addr.arpa.', '10.0.168.192.in-addr.arpa.',
                    'PTR', ['test.example.test.']
                ),
                mock.call(
                    '0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.'
                    '0.2.ip6.arpa.',
                    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.'
                    '1.0.0.2.ip6.arpa.',
                    'PTR', ['test.example.test.']
                ),
            ]
        )

    def test_create_record_set_with_reverse_zone_conflict(self):
        self.admin_client.recordsets.create.side_effect = [
            d_exc.NotFound, None,
        ]
        self.admin_client.zones.create.side_effect = d_exc.Conflict

        self.driver.create_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10']
        )

        self.assertEqual(1, self.client.recordsets.create.call_count)
        self.assertEqual(1, self.admin_client.zones.create.call_count)
        self.assertEqual(2, self.admin_client.recordsets.create.call_count)

    def test_create_new_zone_when_missing(self):
        self.admin_client.recordsets.create.side_effect = [
            d_exc.NotFound, None, d_exc.NotFound, None
        ]

        self.driver.create_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1']
        )

        self.admin_client.zones.create.assert_has_calls(
            [
                mock.call(
                    '0.168.192.in-addr.arpa.', email='admin@example.test',
                    description='An in-addr.arpa. zone for reverse lookups '
                                'set up by Neutron.'
                ),
                mock.call(
                    '0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.'
                    '0.2.ip6.arpa.',
                    email='admin@example.test',
                    description='An ip6.arpa. zone for reverse lookups set up '
                                'by Neutron.'
                )
            ]
        )

    def test_create_new_zone_with_custom_email(self):
        self.admin_client.recordsets.create.side_effect = [
            d_exc.NotFound, None, d_exc.NotFound, None
        ]

        cfg.CONF.set_override(
            'ptr_zone_email', 'ptr@example.test', group='designate'
        )

        self.driver.create_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10']
        )

        self.admin_client.zones.create.assert_has_calls(
            [
                mock.call(
                    '0.168.192.in-addr.arpa.', email='ptr@example.test',
                    description='An in-addr.arpa. zone for reverse lookups '
                                'set up by Neutron.'
                ),
            ]
        )

    def test_delete_record_set(self):
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 456, 'records': ['2001:db8:0:1::1']}
        ]

        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate'
        )

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1']
        )

        self.client.recordsets.delete.assert_has_calls(
            [
                mock.call('example.test.', 123),
                mock.call('example.test.', 456)
            ]
        )
        self.admin_client.recordsets.delete.assert_not_called()

    def test_delete_single_record_from_two_records(self):
        # Set up two records similar to test_delete_record_set
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 456, 'records': ['2001:db8:0:1::1']}
        ]

        cfg.CONF.set_override(
            'allow_reverse_dns_lookup', False, group='designate'
        )

        # Delete only the first record (IPv4) out of the two
        self.driver.delete_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10']
        )

        # Verify that only the IPv4 record was deleted
        self.client.recordsets.delete.assert_called_once_with(
            'example.test.', 123
        )

        # Admin client should not be called since reverse DNS is disabled
        self.admin_client.recordsets.delete.assert_not_called()

    def test_delete_record_set_with_reverse_dns(self):
        self.client.recordsets.list.return_value = [
            {'id': 123, 'records': ['192.168.0.10']},
            {'id': 456, 'records': ['2001:db8:0:1::1']}
        ]

        self.driver.delete_record_set(
            self.context, 'example.test.', 'test',
            ['192.168.0.10', '2001:db8:0:1::1']
        )

        self.client.recordsets.delete.assert_has_calls(
            [
                mock.call('example.test.', 123),
                mock.call('example.test.', 456)
            ]
        )

        self.admin_client.recordsets.delete.assert_has_calls(
            [
                mock.call(
                    '0.168.192.in-addr.arpa.', '10.0.168.192.in-addr.arpa.'
                ),
                mock.call(
                    '0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.'
                    '0.2.ip6.arpa.',
                    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.'
                    '1.0.0.2.ip6.arpa.'
                )
            ]
        )

    def test_create_record_set_zone_not_found(self):
        self.client.recordsets.create.side_effect = d_exc.NotFound

        self.assertRaisesRegex(
            dns_exc.DNSDomainNotFound,
            'Domain example.test. not found in the external DNS service',
            self.driver.create_record_set, self.context, 'example.test.',
            'test', ['192.168.0.10']
        )

    def test_create_record_set_duplicate_recordset(self):
        self.client.recordsets.create.side_effect = d_exc.Conflict

        self.assertRaisesRegex(
            dns_exc.DuplicateRecordSet,
            'Name test is duplicated in the external DNS service',
            self.driver.create_record_set, self.context, 'example.test.',
            'test', ['192.168.0.10']
        )

    def test_create_record_set_over_quota(self):
        self.client.recordsets.create.side_effect = d_exc.OverQuota

        self.assertRaisesRegex(
            dns_exc.ExternalDNSOverQuota,
            'External DNS Quota exceeded for resources: recordset.',
            self.driver.create_record_set, self.context, 'example.test.',
            'test', ['192.168.0.10']
        )

    def test_create_reverse_zone_over_quota(self):
        self.admin_client.recordsets.create.side_effect = d_exc.NotFound
        self.admin_client.zones.create.side_effect = d_exc.OverQuota

        self.assertRaisesRegex(
            dns_exc.ExternalDNSOverQuota,
            'External DNS Quota exceeded for resources: zone.',
            self.driver.create_record_set, self.context, 'example.test.',
            'test', ['192.168.0.10']
        )

    def test_delete_record_set_zone_not_found(self):
        self.client.recordsets.list.side_effect = d_exc.NotFound
        self.all_projects_client.recordsets.list.side_effect = d_exc.NotFound

        self.assertRaisesRegex(
            dns_exc.DNSDomainNotFound,
            'Domain example.test. not found in the external DNS service',
            self.driver.delete_record_set, self.context, 'example.test.',
            'test', ['192.168.0.10']
        )

    def test_ipv4_ptr_is_misconfigured(self):
        self.assertRaises(
            ValueError,
            cfg.CONF.set_override,
            'ipv4_ptr_zone_prefix_size', 0, group='designate'
        )
        self.assertRaises(
            ValueError,
            cfg.CONF.set_override,
            'ipv4_ptr_zone_prefix_size', 32, group='designate'
        )
        self.assertRaisesRegex(
            ValueError,
            'Should be multiple of 8',
            cfg.CONF.set_override,
            'ipv4_ptr_zone_prefix_size', 9, group='designate'
        )

    def test_ipv6_ptr_is_misconfigured(self):
        self.assertRaises(
            ValueError,
            cfg.CONF.set_override,
            'ipv6_ptr_zone_prefix_size', 0, group='designate'
        )
        self.assertRaises(
            ValueError,
            cfg.CONF.set_override,
            'ipv6_ptr_zone_prefix_size', 128, group='designate'
        )
        self.assertRaisesRegex(
            ValueError,
            'Should be multiple of 4',
            cfg.CONF.set_override,
            'ipv6_ptr_zone_prefix_size', 5, group='designate'
        )
