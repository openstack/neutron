# Copyright (c) 2016 IBM
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

import uuid

from keystoneauth1 import loading
from keystoneauth1 import session
import mock
import netaddr
from neutron_lib import constants
from neutron_lib.plugins import directory
import testtools

from neutron import context
from neutron.extensions import dns
from neutron.extensions import providernet as pnet
from neutron.objects import ports as port_obj
from neutron.plugins.ml2 import config
from neutron.plugins.ml2.extensions import dns_integration
from neutron.services.externaldns.drivers.designate import driver
from neutron.tests.unit.plugins.ml2 import test_plugin


mock_client = mock.Mock()
mock_admin_client = mock.Mock()
mock_config = {'return_value': (mock_client, mock_admin_client)}
DNSNAME = 'port-dns-name'
NEWDNSNAME = 'new-port-dns-name'
V4UUID = 'v4_uuid'
V6UUID = 'v6_uuid'


@mock.patch(
    'neutron.services.externaldns.drivers.designate.driver.get_clients',
    **mock_config)
class DNSIntegrationTestCase(test_plugin.Ml2PluginV2TestCase):
    _extension_drivers = ['dns']
    _domain = 'domain.com.'

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        config.cfg.CONF.set_override('external_dns_driver', 'designate')
        mock_client.reset_mock()
        mock_admin_client.reset_mock()
        super(DNSIntegrationTestCase, self).setUp()
        dns_integration.DNS_DRIVER = None
        dns_integration.subscribe()
        self.plugin = directory.get_plugin()
        config.cfg.CONF.set_override('dns_domain', self._domain)

    def _create_port_for_test(self, provider_net=True, dns_domain=True,
                              dns_name=True, ipv4=True, ipv6=True):
        net_kwargs = {}
        if provider_net:
            net_kwargs = {
                'arg_list': (pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID,),
                pnet.NETWORK_TYPE: 'vxlan',
                pnet.SEGMENTATION_ID: '2016',
            }
        if dns_domain:
            net_kwargs[dns.DNSDOMAIN] = self._domain
            net_kwargs['arg_list'] = \
                net_kwargs.get('arg_list', ()) + (dns.DNSDOMAIN,)
        res = self._create_network(self.fmt, 'test_network', True,
                                   **net_kwargs)
        network = self.deserialize(self.fmt, res)
        if ipv4:
            cidr = '10.0.0.0/24'
            self._create_subnet_for_test(network['network']['id'], cidr)

        if ipv6:
            cidr = 'fd3d:bdd4:da60::/64'
            self._create_subnet_for_test(network['network']['id'], cidr)

        port_kwargs = {}
        if dns_name:
            port_kwargs = {
                'arg_list': (dns.DNSNAME,),
                dns.DNSNAME: DNSNAME
            }
        res = self._create_port('json', network['network']['id'],
                                **port_kwargs)
        self.assertEqual(201, res.status_int)
        port = self.deserialize(self.fmt, res)['port']
        ctx = context.get_admin_context()
        dns_data_db = port_obj.PortDNS.get_object(ctx, port_id=port['id'])
        return network['network'], port, dns_data_db

    def _create_subnet_for_test(self, network_id, cidr):
        ip_net = netaddr.IPNetwork(cidr)
        # initialize the allocation_pool to the lower half of the subnet
        subnet_size = ip_net.last - ip_net.first
        subnet_mid_point = int(ip_net.first + subnet_size / 2)
        start, end = (netaddr.IPAddress(ip_net.first + 2),
                      netaddr.IPAddress(subnet_mid_point))
        allocation_pools = [{'start': str(start),
                             'end': str(end)}]
        return self._create_subnet(self.fmt, network_id,
                                   str(ip_net), ip_version=ip_net.ip.version,
                                   allocation_pools=allocation_pools)

    def _update_port_for_test(self, port, new_dns_name=NEWDNSNAME,
                              **kwargs):
        mock_client.reset_mock()
        ip_addresses = [netaddr.IPAddress(ip['ip_address'])
                        for ip in port['fixed_ips']]
        records_v4 = [ip for ip in ip_addresses if ip.version == 4]
        records_v6 = [ip for ip in ip_addresses if ip.version == 6]
        recordsets = []
        if records_v4:
            recordsets.append({'id': V4UUID, 'records': records_v4})
        if records_v6:
            recordsets.append({'id': V6UUID, 'records': records_v6})
        mock_client.recordsets.list.return_value = recordsets
        mock_admin_client.reset_mock()
        body = {}
        if new_dns_name is not None:
            body['dns_name'] = new_dns_name
        body.update(kwargs)
        data = {'port': body}
        req = self.new_update_request('ports', data, port['id'])
        res = req.get_response(self.api)
        self.assertEqual(200, res.status_int)
        port = self.deserialize(self.fmt, res)['port']
        ctx = context.get_admin_context()
        dns_data_db = port_obj.PortDNS.get_object(ctx, port_id=port['id'])
        return port, dns_data_db

    def _verify_port_dns(self, net, port, dns_data_db, dns_name=True,
                         dns_domain=True, ptr_zones=True, delete_records=False,
                         provider_net=True, dns_driver=True, original_ips=None,
                         current_dns_name=DNSNAME, previous_dns_name=''):
        if dns_name:
            self.assertEqual(current_dns_name, port[dns.DNSNAME])
        if dns_name and dns_domain and provider_net and dns_driver:
            self.assertEqual(current_dns_name, dns_data_db['current_dns_name'])
            self.assertEqual(previous_dns_name,
                             dns_data_db['previous_dns_name'])
            if current_dns_name:
                self.assertEqual(net[dns.DNSDOMAIN],
                                 dns_data_db['current_dns_domain'])
            else:
                self.assertFalse(dns_data_db['current_dns_domain'])
            records_v4 = [ip['ip_address'] for ip in port['fixed_ips']
                          if netaddr.IPAddress(ip['ip_address']).version
                          == 4]
            records_v6 = [ip['ip_address'] for ip in port['fixed_ips']
                          if netaddr.IPAddress(ip['ip_address']).version
                          == 6]
            expected = []
            expected_delete = []
            if records_v4:
                if current_dns_name:
                    expected.append(
                        mock.call(net[dns.DNSDOMAIN], current_dns_name, 'A',
                                  records_v4))
                if delete_records:
                    expected_delete.append(mock.call(net[dns.DNSDOMAIN],
                                           V4UUID))
            if records_v6:
                if current_dns_name:
                    expected.append(
                        mock.call(net[dns.DNSDOMAIN], current_dns_name, 'AAAA',
                                  records_v6))
                if delete_records:
                    expected_delete.append(mock.call(net[dns.DNSDOMAIN],
                                           V6UUID))
            mock_client.recordsets.create.assert_has_calls(expected,
                                                           any_order=True)
            self.assertEqual(
                len(mock_client.recordsets.create.call_args_list),
                len(expected))
            mock_client.recordsets.delete.assert_has_calls(expected_delete,
                                                           any_order=True)
            self.assertEqual(
                len(mock_client.recordsets.delete.call_args_list),
                len(expected_delete))
            expected = []
            expected_delete = []
            if ptr_zones:
                records = records_v4 + records_v6
                recordset_name = '%s.%s' % (current_dns_name,
                                            net[dns.DNSDOMAIN])
                for record in records:
                    in_addr_name = netaddr.IPAddress(record).reverse_dns
                    in_addr_zone_name = self._get_in_addr_zone_name(
                        in_addr_name)
                    if current_dns_name:
                        expected.append(mock.call(in_addr_zone_name,
                                                  in_addr_name, 'PTR',
                                                  [recordset_name]))
                    if delete_records and not original_ips:
                        expected_delete.append(mock.call(in_addr_zone_name,
                                                         in_addr_name))
                if delete_records and original_ips:
                    for record in original_ips:
                        in_addr_name = netaddr.IPAddress(record).reverse_dns
                        in_addr_zone_name = self._get_in_addr_zone_name(
                            in_addr_name)
                        expected_delete.append(mock.call(in_addr_zone_name,
                                                         in_addr_name))
            mock_admin_client.recordsets.create.assert_has_calls(
                expected, any_order=True)
            self.assertEqual(
                len(mock_admin_client.recordsets.create.call_args_list),
                len(expected))
            mock_admin_client.recordsets.delete.assert_has_calls(
                expected_delete, any_order=True)
            self.assertEqual(
                len(mock_admin_client.recordsets.delete.call_args_list),
                len(expected_delete))
        else:
            if not dns_name:
                self.assertEqual('', port[dns.DNSNAME])
                self.assertIsNone(dns_data_db)
            self.assertFalse(mock_client.recordsets.create.call_args_list)
            self.assertFalse(
                mock_admin_client.recordsets.create.call_args_list)
            self.assertFalse(mock_client.recordsets.delete.call_args_list)
            self.assertFalse(
                mock_admin_client.recordsets.delete.call_args_list)

    def _get_in_addr_zone_name(self, in_addr_name):
        units = self._get_bytes_or_nybles_to_skip(in_addr_name)
        return '.'.join(in_addr_name.split('.')[int(units):])

    def _get_bytes_or_nybles_to_skip(self, in_addr_name):
        if 'in-addr.arpa' in in_addr_name:
            return ((
                constants.IPv4_BITS -
                config.cfg.CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return (constants.IPv6_BITS -
                config.cfg.CONF.designate.ipv6_ptr_zone_prefix_size) / 4

    def test_create_port(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        self._verify_port_dns(net, port, dns_data_db)

    def test_create_port_tenant_network(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(provider_net=False)
        self._verify_port_dns(net, port, dns_data_db, provider_net=False)

    def test_create_port_no_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(dns_name=False)
        self._verify_port_dns(net, port, dns_data_db, dns_name=False)

    def test_create_port_no_dns_domain(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(dns_domain=False)
        self._verify_port_dns(net, port, dns_data_db, dns_domain=False)

    def test_create_port_no_dns_driver(self, *mocks):
        config.cfg.CONF.set_override('external_dns_driver', '')
        net, port, dns_data_db = self._create_port_for_test()
        self._verify_port_dns(net, port, dns_data_db, dns_driver=False)

    def test_create_port_no_ipv6(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(ipv6=False)
        self._verify_port_dns(net, port, dns_data_db)

    def test_create_port_no_ipv4(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(ipv4=False)
        self._verify_port_dns(net, port, dns_data_db)

    def test_create_port_no_ptr_zones(self, *mocks):
        config.cfg.CONF.set_override('allow_reverse_dns_lookup', False,
                                     group='designate')
        net, port, dns_data_db = self._create_port_for_test()
        self._verify_port_dns(net, port, dns_data_db, ptr_zones=False)
        config.cfg.CONF.set_override('allow_reverse_dns_lookup', True,
                                     group='designate')

    def test_update_port(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db = self._update_port_for_test(port)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=NEWDNSNAME,
                              previous_dns_name=DNSNAME)

    def test_update_port_with_current_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=DNSNAME)
        self.assertEqual(DNSNAME, dns_data_db['current_dns_name'])
        self.assertEqual(self._domain, dns_data_db['current_dns_domain'])
        self.assertEqual('', dns_data_db['previous_dns_name'])
        self.assertEqual('', dns_data_db['previous_dns_domain'])
        self.assertFalse(mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.create.call_args_list)
        self.assertFalse(mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.delete.call_args_list)

    def test_update_port_tenant_network(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(provider_net=False)
        port, dns_data_db = self._update_port_for_test(port)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=NEWDNSNAME,
                              previous_dns_name=DNSNAME, provider_net=False)

    def test_update_port_no_dns_domain(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(dns_domain=False)
        port, dns_data_db = self._update_port_for_test(port)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=NEWDNSNAME,
                              previous_dns_name=DNSNAME, dns_domain=False)

    def test_update_port_add_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test(dns_name=False)
        port, dns_data_db = self._update_port_for_test(port)
        self._verify_port_dns(net, port, dns_data_db, delete_records=False,
                              current_dns_name=NEWDNSNAME,
                              previous_dns_name='')

    def test_update_port_clear_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db = self._update_port_for_test(port, new_dns_name='')
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name='', previous_dns_name=DNSNAME)

    def test_update_port_non_dns_name_attribute(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port_name = 'port_name'
        kwargs = {'name': port_name}
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=None,
                                                       **kwargs)
        self.assertEqual(DNSNAME, dns_data_db['current_dns_name'])
        self.assertEqual(self._domain, dns_data_db['current_dns_domain'])
        self.assertEqual('', dns_data_db['previous_dns_name'])
        self.assertEqual('', dns_data_db['previous_dns_domain'])
        self.assertFalse(mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.create.call_args_list)
        self.assertFalse(mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.delete.call_args_list)
        self.assertEqual(port_name, port['name'])

    def test_update_port_fixed_ips(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        original_ips = [ip['ip_address'] for ip in port['fixed_ips']]
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address': str(netaddr.IPAddress(ip['ip_address']) + 1)})
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=None,
                                                       **kwargs)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=DNSNAME,
                              previous_dns_name=DNSNAME,
                              original_ips=original_ips)

    def test_update_port_fixed_ips_with_new_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        original_ips = [ip['ip_address'] for ip in port['fixed_ips']]
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address': str(netaddr.IPAddress(ip['ip_address']) + 1)})
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=NEWDNSNAME,
                                                       **kwargs)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=NEWDNSNAME,
                              previous_dns_name=DNSNAME,
                              original_ips=original_ips)

    def test_update_port_fixed_ips_with_current_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        original_ips = [ip['ip_address'] for ip in port['fixed_ips']]
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address': str(netaddr.IPAddress(ip['ip_address']) + 1)})
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=DNSNAME,
                                                       **kwargs)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name=DNSNAME,
                              previous_dns_name=DNSNAME,
                              original_ips=original_ips)

    def test_update_port_fixed_ips_clearing_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        original_ips = [ip['ip_address'] for ip in port['fixed_ips']]
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address': str(netaddr.IPAddress(ip['ip_address']) + 1)})
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name='',
                                                       **kwargs)
        self._verify_port_dns(net, port, dns_data_db, delete_records=True,
                              current_dns_name='', previous_dns_name=DNSNAME,
                              original_ips=original_ips)

    def test_update_fixed_ips_no_effect_after_clearing_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db_1 = self._update_port_for_test(port,
                                                         new_dns_name='')
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address': str(netaddr.IPAddress(ip['ip_address']) + 1)})
        mock_client.reset_mock()
        mock_admin_client.reset_mock()
        port, dns_data_db_2 = self._update_port_for_test(port,
                                                         new_dns_name='',
                                                         **kwargs)
        self.assertEqual('', dns_data_db_2['current_dns_name'])
        self.assertEqual('', dns_data_db_2['current_dns_domain'])
        self.assertEqual(dns_data_db_1['current_dns_name'],
                         dns_data_db_2['current_dns_name'])
        self.assertEqual(dns_data_db_1['current_dns_domain'],
                         dns_data_db_2['current_dns_domain'])
        self.assertEqual(dns_data_db_1['previous_dns_name'],
                         dns_data_db_2['previous_dns_name'])
        self.assertEqual(dns_data_db_1['previous_dns_domain'],
                         dns_data_db_2['previous_dns_domain'])
        self.assertFalse(mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.create.call_args_list)
        self.assertFalse(mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.delete.call_args_list)

    def test_create_port_dns_name_field_missing(self, *mocks):
        res = self._create_network(self.fmt, 'test_network', True)
        net = self.deserialize(self.fmt, res)['network']
        cidr = '10.0.0.0/24'
        self._create_subnet_for_test(net['id'], cidr)
        port_request = {
            'port': {
                'network_id': net['id'],
                'tenant_id': net['tenant_id'],
                'name': 'mugsie',
                'admin_state_up': True,
                'device_id': '',
                'device_owner': '',
                'fixed_ips': ''
            }
        }
        self.plugin.create_port(self.context, port_request)

    def test_dns_driver_loaded_after_server_restart(self, *mocks):
        dns_integration.DNS_DRIVER = None
        net, port, dns_data_db = self._create_port_for_test()
        self._verify_port_dns(net, port, dns_data_db)


class DNSIntegrationTestCaseDefaultDomain(DNSIntegrationTestCase):
    _domain = 'openstacklocal.'

    def _generate_dns_assignment(self, port):
        fqdn = []
        for ip in port['fixed_ips']:
            hostname = 'host-%s' % ip['ip_address'].replace(
                '.', '-').replace(':', '-')
            fqdn.append('%s.%s' % (hostname, self._domain))
        return set(fqdn)

    def _verify_port_dns(self, net, port, dns_data_db, dns_name=True,
                         dns_domain=True, ptr_zones=True, delete_records=False,
                         provider_net=True, dns_driver=True, original_ips=None,
                         current_dns_name=DNSNAME, previous_dns_name=''):
        self.assertEqual('', port[dns.DNSNAME])
        fqdn_set = self._generate_dns_assignment(port)
        port_fqdn_set = set([each['fqdn'] for each in port['dns_assignment']])
        self.assertEqual(fqdn_set, port_fqdn_set)
        self.assertIsNone(dns_data_db, "dns data should be none")
        self.assertFalse(mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.create.call_args_list)
        self.assertFalse(mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            mock_admin_client.recordsets.delete.call_args_list)

    def test_update_fixed_ips_no_effect_after_clearing_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db_1 = self._update_port_for_test(port,
                                                         new_dns_name='')
        kwargs = {'fixed_ips': []}
        for ip in port['fixed_ips']:
            kwargs['fixed_ips'].append(
                {'subnet_id': ip['subnet_id'],
                 'ip_address':
                     str(netaddr.IPAddress(ip['ip_address']) + 1)})
        mock_client.reset_mock()
        mock_admin_client.reset_mock()
        port, dns_data_db_2 = self._update_port_for_test(port,
                                                         new_dns_name='',
                                                         **kwargs)
        self._verify_port_dns(net, port, dns_data_db_2)

    def test_update_port_non_dns_name_attribute(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port_name = 'port_name'
        kwargs = {'name': port_name}
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=None,
                                                       **kwargs)
        self._verify_port_dns(net, port, dns_data_db)

    def test_update_port_with_current_dns_name(self, *mocks):
        net, port, dns_data_db = self._create_port_for_test()
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=DNSNAME)
        self._verify_port_dns(net, port, dns_data_db)


class TestDesignateClientKeystoneV2(testtools.TestCase):
    """Test case for designate clients """

    TEST_URL = 'http://127.0.0.1:9001/v2'
    TEST_ADMIN_USERNAME = uuid.uuid4().hex
    TEST_ADMIN_PASSWORD = uuid.uuid4().hex
    TEST_ADMIN_TENANT_NAME = uuid.uuid4().hex
    TEST_ADMIN_TENANT_ID = uuid.uuid4().hex
    TEST_ADMIN_AUTH_URL = 'http://127.0.0.1:35357/v2.0'
    TEST_CA_CERT = uuid.uuid4().hex

    TEST_CONTEXT = mock.Mock()
    TEST_CONTEXT.auth_token = uuid.uuid4().hex

    def setUp(self):
        super(TestDesignateClientKeystoneV2, self).setUp()
        config.cfg.CONF.set_override('url',
                                     self.TEST_URL,
                                     group='designate')
        config.cfg.CONF.set_override('admin_username',
                                     self.TEST_ADMIN_USERNAME,
                                     group='designate')
        config.cfg.CONF.set_override('admin_password',
                                     self.TEST_ADMIN_PASSWORD,
                                     group='designate')
        config.cfg.CONF.set_override('admin_auth_url',
                                     self.TEST_ADMIN_AUTH_URL,
                                     group='designate')
        config.cfg.CONF.set_override('admin_tenant_id',
                                     self.TEST_ADMIN_TENANT_ID,
                                     group='designate')
        config.cfg.CONF.set_override('admin_tenant_name',
                                     self.TEST_ADMIN_TENANT_NAME,
                                     group='designate')

        # enforce session recalculation
        mock.patch.object(driver, '_SESSION', new=None).start()
        self.driver_session = (
            mock.patch.object(session, 'Session').start())
        self.load_auth = (
            mock.patch.object(driver.loading,
                'load_auth_from_conf_options').start())
        self.password = (
            mock.patch.object(driver.password, 'Password').start())

    def test_insecure_client(self):
        config.cfg.CONF.set_override('insecure',
                                     True,
                                     group='designate')
        driver.get_clients(self.TEST_CONTEXT)
        self.driver_session.assert_called_with(cert=None,
                                               timeout=None,
                                               verify=False)

    def test_secure_client(self):
        config.cfg.CONF.set_override('insecure',
                                     False,
                                     group='designate')
        config.cfg.CONF.set_override('cafile',
                                     self.TEST_CA_CERT,
                                     group='designate')
        driver.get_clients(self.TEST_CONTEXT)
        self.driver_session.assert_called_with(cert=None,
                                               timeout=None,
                                               verify=self.TEST_CA_CERT)

    def test_auth_type_not_defined(self):
        driver.get_clients(self.TEST_CONTEXT)
        self.load_auth.assert_not_called()
        self.password.assert_called_with(
            auth_url=self.TEST_ADMIN_AUTH_URL,
            password=self.TEST_ADMIN_PASSWORD,
            tenant_id=self.TEST_ADMIN_TENANT_ID,
            tenant_name=self.TEST_ADMIN_TENANT_NAME,
            username=self.TEST_ADMIN_USERNAME)


class TestDesignateClientKeystoneV3(testtools.TestCase):
    """Test case for designate clients """

    TEST_URL = 'http://127.0.0.1:9001/v2'
    TEST_ADMIN_USERNAME = uuid.uuid4().hex
    TEST_ADMIN_PASSWORD = uuid.uuid4().hex
    TEST_ADMIN_USER_DOMAIN_ID = 'Default'
    TEST_ADMIN_PROJECT_ID = uuid.uuid4().hex
    TEST_ADMIN_PROJECT_DOMAIN_ID = 'Default'
    TEST_ADMIN_AUTH_URL = 'http://127.0.0.1:35357/v3'
    TEST_CA_CERT = uuid.uuid4().hex

    TEST_CONTEXT = mock.Mock()
    TEST_CONTEXT.auth_token = uuid.uuid4().hex

    def setUp(self):
        super(TestDesignateClientKeystoneV3, self).setUp()
        # Register the Password auth plugin options,
        # so we can use CONF.set_override
        password_option = loading.get_auth_plugin_conf_options('password')
        config.cfg.CONF.register_opts(password_option, group='designate')
        self.addCleanup(
            config.cfg.CONF.unregister_opts,
            password_option, group='designate')

        config.cfg.CONF.set_override('url',
                                     self.TEST_URL,
                                     group='designate')
        config.cfg.CONF.set_override('auth_type',
                                     'password',
                                     group='designate')
        config.cfg.CONF.set_override('username',
                                     self.TEST_ADMIN_USERNAME,
                                     group='designate')
        config.cfg.CONF.set_override('password',
                                     self.TEST_ADMIN_PASSWORD,
                                     group='designate')
        config.cfg.CONF.set_override('user_domain_id',
                                     self.TEST_ADMIN_USER_DOMAIN_ID,
                                     group='designate')
        config.cfg.CONF.set_override('project_domain_id',
                                     self.TEST_ADMIN_PROJECT_DOMAIN_ID,
                                     group='designate')
        config.cfg.CONF.set_override('auth_url',
                                     self.TEST_ADMIN_AUTH_URL,
                                     group='designate')

        # enforce session recalculation
        mock.patch.object(driver, '_SESSION', new=None).start()
        self.driver_session = (
            mock.patch.object(session, 'Session').start())
        self.load_auth = (
            mock.patch.object(driver.loading,
                'load_auth_from_conf_options').start())
        self.password = (
            mock.patch.object(driver.password, 'Password').start())

    def test_insecure_client(self):
        config.cfg.CONF.set_override('insecure',
                                     True,
                                     group='designate')
        driver.get_clients(self.TEST_CONTEXT)
        self.driver_session.assert_called_with(cert=None,
                                               timeout=None,
                                               verify=False)

    def test_secure_client(self):
        config.cfg.CONF.set_override('insecure',
                                     False,
                                     group='designate')
        config.cfg.CONF.set_override('cafile',
                                     self.TEST_CA_CERT,
                                     group='designate')
        driver.get_clients(self.TEST_CONTEXT)
        self.driver_session.assert_called_with(cert=None,
                                               timeout=None,
                                               verify=self.TEST_CA_CERT)

    def test_auth_type_password(self):
        driver.get_clients(self.TEST_CONTEXT)
        self.load_auth.assert_called_with(config.cfg.CONF, 'designate')
        self.password.assert_not_called()
