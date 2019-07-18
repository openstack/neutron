# Copyright 2015 Rackspace
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

import math

import netaddr
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import l3 as l3_apdef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import constants as db_const
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.extensions import dns
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.ml2 import test_plugin


class DnsExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return dns.Dns().get_extended_resources(version)


class DnsExtensionTestPlugin(db_base_plugin_v2.NeutronDbPluginV2):
    """Test plugin to mixin the DNS Integration extensions.
    """

    supported_extension_aliases = [dns_apidef.ALIAS, l3_apdef.ALIAS]


class DnsExtensionTestCase(test_plugin.Ml2PluginV2TestCase):
    """Test API extension dns attributes.
    """

    _extension_drivers = ['dns']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(DnsExtensionTestCase, self).setUp()

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, set_context=False, tenant_id=None,
                        **kwargs):
        new_arg_list = ('dns_domain',)
        if arg_list is not None:
            new_arg_list = arg_list + new_arg_list
        return super(DnsExtensionTestCase,
                     self)._create_network(fmt, name, admin_state_up,
                                           arg_list=new_arg_list,
                                           set_context=set_context,
                                           tenant_id=tenant_id,
                                           **kwargs)

    def _create_port(self, fmt, net_id, expected_res_status=None,
                     arg_list=None, set_context=False, tenant_id=None,
                     **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'port': {'network_id': net_id,
                         'tenant_id': tenant_id}}

        for arg in (('admin_state_up', 'device_id',
                    'mac_address', 'name', 'fixed_ips',
                    'tenant_id', 'device_owner', 'security_groups',
                    'dns_name') + (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['port'][arg] = kwargs[arg]
        # create a dhcp port device id if one hasn't been supplied
        if ('device_owner' in kwargs and
                kwargs['device_owner'] == constants.DEVICE_OWNER_DHCP and
                'host' in kwargs and
                'device_id' not in kwargs):
            device_id = utils.get_dhcp_agent_device_id(net_id, kwargs['host'])
            data['port']['device_id'] = device_id
        port_req = self.new_create_request('ports', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            port_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        port_res = port_req.get_response(self.api)
        if expected_res_status:
            self.assertEqual(expected_res_status, port_res.status_int)
        return port_res

    def _test_list_resources(self, resource, items, neutron_context=None,
                             query_params=None):
        res = self._list('%ss' % resource,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertItemsEqual([i['id'] for i in res['%ss' % resource]],
                              [i[resource]['id'] for i in items])
        return res

    def test_create_port_json(self):
        keys = [('admin_state_up', True), ('status', self.port_create_status)]
        with self.port(name='myname') as port:
            for k, v in keys:
                self.assertEqual(port['port'][k], v)
            self.assertIn('mac_address', port['port'])
            ips = port['port']['fixed_ips']
            self.assertEqual(1, len(ips))
            subnet_db = directory.get_plugin().get_subnet(
                    context.get_admin_context(), ips[0]['subnet_id'])
            self.assertIn(netaddr.IPAddress(ips[0]['ip_address']),
                          netaddr.IPSet(netaddr.IPNetwork(subnet_db['cidr'])))
            self.assertEqual('myname', port['port']['name'])
            self._verify_dns_assigment(port['port'],
                                       ips_list=[ips[0]['ip_address']])

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.port() as v1, self.port() as v2, self.port() as v3:
            ports = (v1, v2, v3)
            res = self._test_list_resources('port', ports)
            for port in res['ports']:
                self._verify_dns_assigment(
                    port, ips_list=[port['fixed_ips'][0]['ip_address']])

    def test_show_port(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(port['port']['id'], sport['port']['id'])
            self._verify_dns_assigment(
                sport['port'],
                ips_list=[sport['port']['fixed_ips'][0]['ip_address']])

    def test_update_port_non_default_dns_domain_with_dns_name(self):
        with self.port() as port:
            port_ip = port['port']['fixed_ips'][0]['ip_address']
            cfg.CONF.set_override('dns_domain', 'example.com')
            data = {'port': {'admin_state_up': False, 'dns_name': 'vm1'}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(data['port']['admin_state_up'],
                             res['port']['admin_state_up'])
            self._verify_dns_assigment(res['port'],
                                       ips_list=[port_ip],
                                       dns_name='vm1')

    def test_update_port_default_dns_domain_with_dns_name(self):
        with self.port() as port:
            port_ip = port['port']['fixed_ips'][0]['ip_address']
            data = {'port': {'admin_state_up': False, 'dns_name': 'vm1'}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(data['port']['admin_state_up'],
                             res['port']['admin_state_up'])
            self._verify_dns_assigment(res['port'],
                                       ips_list=[port_ip])

    def _verify_dns_assigment(self, port, ips_list=None, exp_ips_ipv4=0,
                              exp_ips_ipv6=0, ipv4_cidrs=None, ipv6_cidrs=None,
                              dns_name=''):
        ips_list = ips_list or []
        ipv4_cidrs = ipv4_cidrs or []
        ipv6_cidrs = ipv6_cidrs or []
        self.assertEqual(dns_name, port['dns_name'])
        dns_assignment = port['dns_assignment']
        if ips_list:
            self.assertEqual(len(dns_assignment), len(ips_list))
            ips_set = set(ips_list)
        else:
            self.assertEqual(len(dns_assignment), exp_ips_ipv4 + exp_ips_ipv6)
            ipv4_count = 0
            ipv6_count = 0
            subnets_v4 = [netaddr.IPNetwork(cidr) for cidr in ipv4_cidrs]
            subnets_v6 = [netaddr.IPNetwork(cidr) for cidr in ipv6_cidrs]

        request_dns_name, request_fqdn = self._get_request_hostname_and_fqdn(
            dns_name)
        for assignment in dns_assignment:
            if ips_list:
                self.assertIn(assignment['ip_address'], ips_set)
                ips_set.remove(assignment['ip_address'])
            else:
                ip = netaddr.IPAddress(assignment['ip_address'])
                if ip.version == 4:
                    self.assertTrue(self._verify_ip_in_subnet(ip, subnets_v4))
                    ipv4_count += 1
                else:
                    self.assertTrue(self._verify_ip_in_subnet(ip, subnets_v6))
                    ipv6_count += 1
            hostname, fqdn = self._get_hostname_and_fqdn(request_dns_name,
                                                         request_fqdn,
                                                         assignment)
            self.assertEqual(assignment['hostname'], hostname)
            self.assertEqual(assignment['fqdn'], fqdn)
        if ips_list:
            self.assertFalse(ips_set)
        else:
            self.assertEqual(ipv4_count, exp_ips_ipv4)
            self.assertEqual(ipv6_count, exp_ips_ipv6)

    def _get_dns_domain(self):
        if not cfg.CONF.dns_domain:
            return ''
        if cfg.CONF.dns_domain.endswith('.'):
            return cfg.CONF.dns_domain
        return '%s.' % cfg.CONF.dns_domain

    def _get_request_hostname_and_fqdn(self, dns_name):
        request_dns_name = ''
        request_fqdn = ''
        dns_domain = self._get_dns_domain()
        if dns_name and dns_domain and dns_domain != 'openstacklocal.':
            request_dns_name = dns_name
            request_fqdn = request_dns_name
            if not request_dns_name.endswith('.'):
                request_fqdn = '%s.%s' % (dns_name, dns_domain)
        return request_dns_name, request_fqdn

    def _get_hostname_and_fqdn(self, request_dns_name, request_fqdn,
                               assignment):
        dns_domain = self._get_dns_domain()
        if request_dns_name:
            hostname = request_dns_name
            fqdn = request_fqdn
        else:
            hostname = 'host-%s' % assignment['ip_address'].replace(
                '.', '-').replace(':', '-')
            fqdn = hostname
            if dns_domain:
                fqdn = '%s.%s' % (hostname, dns_domain)
        return hostname, fqdn

    def _verify_ip_in_subnet(self, ip, subnets_list):
        for subnet in subnets_list:
            if ip in subnet:
                return True
        return False

    def test_update_port_update_ip(self):
        """Test update of port IP.

        Check that a configured IP 10.0.0.2 is replaced by 10.0.0.10.
        """
        with self.subnet() as subnet:
            fixed_ip_data = [{'ip_address': '10.0.0.2'}]
            with self.port(subnet=subnet, fixed_ips=fixed_ip_data) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['ip_address'], '10.0.0.10')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._verify_dns_assigment(res['port'], ips_list=['10.0.0.10'])

    def test_update_port_update_ip_address_only(self):
        with self.subnet() as subnet:
            fixed_ip_data = [{'ip_address': '10.0.0.2'}]
            with self.port(subnet=subnet, fixed_ips=fixed_ip_data) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"},
                                               {'ip_address': "10.0.0.2"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(2, len(ips))
                self.assertIn({'ip_address': '10.0.0.2',
                               'subnet_id': subnet['subnet']['id']}, ips)
                self.assertIn({'ip_address': '10.0.0.10',
                               'subnet_id': subnet['subnet']['id']}, ips)
                self._verify_dns_assigment(res['port'],
                                           ips_list=['10.0.0.10',
                                                     '10.0.0.2'])

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets()
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_pqdn_and_dns_domain_no_period(
            self):
        cfg.CONF.set_override('dns_domain', 'example.com')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name='vm1')
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_pqdn_and_dns_domain_period(
            self):
        cfg.CONF.set_override('dns_domain', 'example.com.')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name='vm1')
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_pqdn_and_no_dns_domain(
            self):
        cfg.CONF.set_override('dns_domain', '')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets()
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_fqdn_and_dns_domain_no_period(
            self):
        cfg.CONF.set_override('dns_domain', 'example.com')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name='vm1.example.com.')
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_fqdn_and_dns_domain_period(
            self):
        cfg.CONF.set_override('dns_domain', 'example.com.')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name='vm1.example.com.')
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_fqdn_default_domain_period(
            self):
        cfg.CONF.set_override('dns_domain', 'openstacklocal.')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets()
        self.assertEqual(201, res.status_code)

    def test_create_port_multiple_v4_v6_subnets_bad_fqdn_and_dns_domain(self):
        cfg.CONF.set_override('dns_domain', 'example.com')
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name='vm1.bad-domain.com.')
        self.assertEqual(400, res.status_code)
        expected_error = ('The dns_name passed is a FQDN. Its higher level '
                          'labels must be equal to the dns_domain option in '
                          'neutron.conf')
        self.assertIn(expected_error, res.text)

    def test_create_port_multiple_v4_v6_subnets_bad_pqdn_and_dns_domain(self):
        cfg.CONF.set_override('dns_domain', 'example.com')
        num_labels = int(
            math.floor(db_const.FQDN_FIELD_SIZE / constants.DNS_LABEL_MAX_LEN))
        filler_len = int(
            math.floor(db_const.FQDN_FIELD_SIZE % constants.DNS_LABEL_MAX_LEN))
        dns_name = (('a' * (constants.DNS_LABEL_MAX_LEN - 1) + '.') *
                    num_labels + 'a' * filler_len)
        res = self._test_create_port_with_multiple_ipv4_and_ipv6_subnets(
            dns_name=dns_name)
        self.assertEqual(400, res.status_code)
        expected_error = ("When the two are concatenated to form a FQDN "
                          "(with a '.' at the end), the resulting length "
                          "exceeds the maximum size")
        self.assertIn(expected_error, res.text)

    def _test_create_port_with_multiple_ipv4_and_ipv6_subnets(self,
                                                              dns_name=''):
        """Test port create with multiple IPv4, IPv6 DHCP/SLAAC subnets."""
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        sub_dicts = [
            {'gateway': '10.0.0.1', 'cidr': '10.0.0.0/24',
             'ip_version': constants.IP_VERSION_4, 'ra_addr_mode': None},
            {'gateway': '10.0.1.1', 'cidr': '10.0.1.0/24',
             'ip_version': constants.IP_VERSION_4, 'ra_addr_mode': None},
            {'gateway': 'fe80::1', 'cidr': 'fe80::/64',
             'ip_version': constants.IP_VERSION_6,
             'ra_addr_mode': constants.IPV6_SLAAC},
            {'gateway': 'fe81::1', 'cidr': 'fe81::/64',
             'ip_version': constants.IP_VERSION_6,
             'ra_addr_mode': constants.IPV6_SLAAC},
            {'gateway': 'fe82::1', 'cidr': 'fe82::/64',
             'ip_version': constants.IP_VERSION_6,
             'ra_addr_mode': constants.DHCPV6_STATEFUL},
            {'gateway': 'fe83::1', 'cidr': 'fe83::/64',
             'ip_version': constants.IP_VERSION_6,
             'ra_addr_mode': constants.DHCPV6_STATEFUL}]
        subnets = {}
        for sub_dict in sub_dicts:
            subnet = self._make_subnet(
                self.fmt, network,
                gateway=sub_dict['gateway'],
                cidr=sub_dict['cidr'],
                ip_version=sub_dict['ip_version'],
                ipv6_ra_mode=sub_dict['ra_addr_mode'],
                ipv6_address_mode=sub_dict['ra_addr_mode'])
            subnets[subnet['subnet']['id']] = sub_dict
        res = self._create_port(self.fmt, net_id=network['network']['id'],
                                dns_name=dns_name)
        if res.status_code != 201:
            return res
        port = self.deserialize(self.fmt, res)
        # Since the create port request was made without a list of fixed IPs,
        # the port should be associated with addresses for one of the
        # IPv4 subnets, one of the DHCPv6 subnets, and both of the IPv6
        # SLAAC subnets.
        self.assertEqual(4, len(port['port']['fixed_ips']))
        addr_mode_count = {None: 0, constants.DHCPV6_STATEFUL: 0,
                           constants.IPV6_SLAAC: 0}
        for fixed_ip in port['port']['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            if subnet_id in subnets:
                addr_mode_count[subnets[subnet_id]['ra_addr_mode']] += 1
        self.assertEqual(1, addr_mode_count[None])
        self.assertEqual(1, addr_mode_count[constants.DHCPV6_STATEFUL])
        self.assertEqual(2, addr_mode_count[constants.IPV6_SLAAC])
        self._verify_dns_assigment(port['port'], exp_ips_ipv4=1,
                                   exp_ips_ipv6=3,
                                   ipv4_cidrs=[sub_dicts[0]['cidr'],
                                               sub_dicts[1]['cidr']],
                                   ipv6_cidrs=[sub_dicts[2]['cidr'],
                                               sub_dicts[3]['cidr'],
                                               sub_dicts[4]['cidr'],
                                               sub_dicts[5]['cidr']],
                                   dns_name=dns_name)
        return res

    def test_api_extension_validation_with_bad_dns_names(self):
        num_labels = int(
            math.floor(db_const.FQDN_FIELD_SIZE / constants.DNS_LABEL_MAX_LEN))
        filler_len = int(
            math.floor(db_const.FQDN_FIELD_SIZE % constants.DNS_LABEL_MAX_LEN))
        dns_names = [555, '\f\n\r', '.', '-vm01', '_vm01', 'vm01-',
                    '-vm01.test1', 'vm01.-test1', 'vm01._test1',
                    'vm01.test1-', 'vm01.te$t1', 'vm0#1.test1.',
                    'vm01.123.', '-' + 'a' * constants.DNS_LABEL_MAX_LEN,
                    'a' * (constants.DNS_LABEL_MAX_LEN + 1),
                    ('a' * (constants.DNS_LABEL_MAX_LEN - 1) + '.') *
                    num_labels + 'a' * (filler_len + 1)]
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        sub_dict = {'gateway': '10.0.0.1', 'cidr': '10.0.0.0/24',
                    'ip_version': constants.IP_VERSION_4, 'ra_addr_mode': None}
        self._make_subnet(self.fmt, network, gateway=sub_dict['gateway'],
                          cidr=sub_dict['cidr'],
                          ip_version=sub_dict['ip_version'],
                          ipv6_ra_mode=sub_dict['ra_addr_mode'],
                          ipv6_address_mode=sub_dict['ra_addr_mode'])
        for dns_name in dns_names:
            res = self._create_port(self.fmt, net_id=network['network']['id'],
                                    dns_name=dns_name)
            self.assertEqual(400, res.status_code)
            error_message = res.json['NeutronError']['message']
            is_expected_message = (
                'cannot be converted to lowercase string' in error_message or
                'not a valid PQDN or FQDN. Reason:' in error_message or
                'must be string type' in error_message)
            self.assertTrue(is_expected_message)

    def test_api_extension_validation_with_good_dns_names(self):
        cfg.CONF.set_override('dns_domain', 'example.com')
        higher_labels_len = len('example.com.')
        num_labels = int(
            math.floor((db_const.FQDN_FIELD_SIZE - higher_labels_len) /
                       constants.DNS_LABEL_MAX_LEN))
        filler_len = int(
            math.floor((db_const.FQDN_FIELD_SIZE - higher_labels_len) %
                       constants.DNS_LABEL_MAX_LEN))
        dns_names = ['', 'www.1000.com', 'vM01', 'vm01.example.com.',
                     '8vm01', 'vm-01.example.com.', 'vm01.test',
                     'vm01.test.example.com.', 'vm01.test-100',
                     'vm01.test-100.example.com.',
                     'a' * constants.DNS_LABEL_MAX_LEN,
                     ('a' * constants.DNS_LABEL_MAX_LEN) + '.example.com.',
                     ('a' * (constants.DNS_LABEL_MAX_LEN - 1) + '.') *
                     num_labels + 'a' * (filler_len - 1)]
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        sub_dict = {'gateway': '10.0.0.1', 'cidr': '10.0.0.0/24',
                    'ip_version': constants.IP_VERSION_4, 'ra_addr_mode': None}
        self._make_subnet(self.fmt, network, gateway=sub_dict['gateway'],
                          cidr=sub_dict['cidr'],
                          ip_version=sub_dict['ip_version'],
                          ipv6_ra_mode=sub_dict['ra_addr_mode'],
                          ipv6_address_mode=sub_dict['ra_addr_mode'])
        for dns_name in dns_names:
            res = self._create_port(self.fmt, net_id=network['network']['id'],
                                    dns_name=dns_name)
            self.assertEqual(201, res.status_code)


class DnsExtensionTestNetworkDnsDomain(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_dns.' +
                  'DnsExtensionTestPlugin')
        ext_mgr = DnsExtensionManager()
        super(DnsExtensionTestNetworkDnsDomain, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)

    def test_update_network_dns_domain(self):
        with self.network() as network:
            data = {'network': {'dns_domain': 'my-domain.org.'}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(200, res.status_code)
            self.assertNotIn('dns_domain',
                             self.deserialize(self.fmt, res)['network'])
