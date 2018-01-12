# Copyright 2016 GoDaddy.
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from neutron_lib import constants

import neutron.api.extensions as api_ext
import neutron.common.config as config
import neutron.extensions
import neutron.services.network_ip_availability.plugin as plugin_module
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_db_base_plugin_v2

API_RESOURCE = 'network-ip-availabilities'
IP_AVAIL_KEY = 'network_ip_availability'
IP_AVAILS_KEY = 'network_ip_availabilities'
EXTENSIONS_PATH = ':'.join(neutron.extensions.__path__)
PLUGIN_NAME = '%s.%s' % (plugin_module.NetworkIPAvailabilityPlugin.__module__,
                         plugin_module.NetworkIPAvailabilityPlugin.__name__)


class TestNetworkIPAvailabilityAPI(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    def setUp(self):
        svc_plugins = {'plugin_name': PLUGIN_NAME}
        super(TestNetworkIPAvailabilityAPI, self).setUp(
                service_plugins=svc_plugins)
        self.plugin = plugin_module.NetworkIPAvailabilityPlugin()
        ext_mgr = api_ext.PluginAwareExtensionManager(
            EXTENSIONS_PATH, {"network-ip-availability": self.plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _validate_availability(self, network, availability, expected_used_ips,
                               expected_total_ips=253):
        self.assertEqual(network['name'], availability['network_name'])
        self.assertEqual(network['id'], availability['network_id'])
        self.assertEqual(expected_used_ips, availability['used_ips'])
        self.assertEqual(expected_total_ips, availability['total_ips'])

    def _validate_from_availabilities(self, availabilities, wrapped_network,
                                      expected_used_ips,
                                      expected_total_ips=253):
        network = wrapped_network['network']
        availability = self._find_availability(availabilities, network['id'])
        self.assertIsNotNone(availability)
        self._validate_availability(network, availability,
                                    expected_used_ips=expected_used_ips,
                                    expected_total_ips=expected_total_ips)

    def test_usages_query_list_with_fields_total_ips(self):
        with self.network() as net:
            with self.subnet(network=net):
                # list by query fields: total_ips
                params = 'fields=total_ips'
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                availability = response[IP_AVAILS_KEY][0]
                self.assertIn('total_ips', availability)
                self.assertEqual(253, availability['total_ips'])
                self.assertNotIn('network_id', availability)

    def test_usages_query_show_with_fields_total_ips(self):
        with self.network() as net:
            with self.subnet(network=net):
                network = net['network']
                # Show by query fields: total_ips
                params = ['total_ips']
                request = self.new_show_request(API_RESOURCE,
                                                network['id'],
                                                fields=params)
                response = self.deserialize(
                    self.fmt, request.get_response(self.ext_api))
                self.assertIn(IP_AVAIL_KEY, response)
                availability = response[IP_AVAIL_KEY]
                self.assertIn('total_ips', availability)
                self.assertEqual(253, availability['total_ips'])
                self.assertNotIn('network_id', availability)

    @staticmethod
    def _find_availability(availabilities, net_id):
        for ip_availability in availabilities:
            if net_id == ip_availability['network_id']:
                return ip_availability

    def test_basic(self):
        with self.network() as net:
            with self.subnet(network=net):
                network = net['network']
                # Get ALL
                request = self.new_list_request(API_RESOURCE, self.fmt)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)

                # Get single via id
                request = self.new_show_request(API_RESOURCE, network['id'])
                response = self.deserialize(
                    self.fmt, request.get_response(self.ext_api))
                self.assertIn(IP_AVAIL_KEY, response)
                usage = response[IP_AVAIL_KEY]
                self._validate_availability(network, usage, 0)

    def test_usages_multi_nets_subnets(self):
        with self.network(name='net1') as n1,\
                self.network(name='net2') as n2,\
                self.network(name='net3') as n3:
            # n1 should have 2 subnets, n2 should have none, n3 has 1
            with self.subnet(network=n1) as subnet1_1, \
                    self.subnet(cidr='40.0.0.0/24', network=n3) as subnet3_1:
                # Consume 3 ports n1, none n2, 2 ports on n3
                with self.port(subnet=subnet1_1),\
                        self.port(subnet=subnet1_1),\
                        self.port(subnet=subnet1_1),\
                        self.port(subnet=subnet3_1),\
                        self.port(subnet=subnet3_1):

                    # Test get ALL
                    request = self.new_list_request(API_RESOURCE)
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    self.assertIn(IP_AVAILS_KEY, response)
                    self.assertEqual(3, len(response[IP_AVAILS_KEY]))

                    data = response[IP_AVAILS_KEY]
                    self._validate_from_availabilities(data, n1, 3, 253)
                    self._validate_from_availabilities(data, n2, 0, 0)
                    self._validate_from_availabilities(data, n3, 2, 253)

                    # Test get single via network id
                    network = n1['network']
                    request = self.new_show_request(API_RESOURCE,
                                                    network['id'])
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    self.assertIn(IP_AVAIL_KEY, response)
                    self._validate_availability(network,
                                                response[IP_AVAIL_KEY], 3, 253)

    def test_usages_multi_nets_subnets_sums(self):
        with self.network(name='net1') as n1:
            # n1 has 2 subnets
            with self.subnet(network=n1) as subnet1_1, \
                    self.subnet(cidr='40.0.0.0/24', network=n1) as subnet1_2:
                # Consume 3 ports n1: 1 on subnet 1 and 2 on subnet 2
                with self.port(subnet=subnet1_1),\
                        self.port(subnet=subnet1_2),\
                        self.port(subnet=subnet1_2):
                    # Get ALL
                    request = self.new_list_request(API_RESOURCE)
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    self.assertIn(IP_AVAILS_KEY, response)
                    self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                    self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                       n1, 3, 506)

                    # Get single via network id
                    network = n1['network']
                    request = self.new_show_request(API_RESOURCE,
                                                    network['id'])
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    self.assertIn(IP_AVAIL_KEY, response)
                    self._validate_availability(network,
                                                response[IP_AVAIL_KEY], 3, 506)

    def test_usages_port_consumed_v4(self):
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                request = self.new_list_request(API_RESOURCE)
                # Consume 2 ports
                with self.port(subnet=subnet), self.port(subnet=subnet):
                    response = self.deserialize(self.fmt,
                                                request.get_response(
                                                    self.ext_api))
                    self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                       net, 2)

    def test_usages_query_ip_version_v4(self):
        with self.network() as net:
            with self.subnet(network=net):
                # Get IPv4
                params = 'ip_version=%s' % constants.IP_VERSION_4
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)

                # Get IPv6 should return empty array
                params = 'ip_version=%s' % constants.IP_VERSION_6
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_query_ip_version_v6(self):
        with self.network() as net:
            with self.subnet(
                    network=net, cidr='2607:f0d0:1002:51::/64',
                    ip_version=constants.IP_VERSION_6,
                    ipv6_address_mode=constants.DHCPV6_STATELESS):
                # Get IPv6
                params = 'ip_version=%s' % constants.IP_VERSION_6
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(
                        response[IP_AVAILS_KEY], net, 0, 18446744073709551614)

                # Get IPv4 should return empty array
                params = 'ip_version=%s' % constants.IP_VERSION_4
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_ports_consumed_v6(self):
        with self.network() as net:
            with self.subnet(
                    network=net, cidr='2607:f0d0:1002:51::/64',
                    ip_version=constants.IP_VERSION_6,
                    ipv6_address_mode=constants.DHCPV6_STATELESS) as subnet:
                request = self.new_list_request(API_RESOURCE)
                # Consume 3 ports
                with self.port(subnet=subnet),\
                        self.port(subnet=subnet), \
                        self.port(subnet=subnet):
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))

                    self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                       net, 3,
                                                       18446744073709551614)

    def test_usages_query_network_id(self):
        with self.network() as net:
            with self.subnet(network=net):
                network = net['network']
                test_id = network['id']
                # Get by query param: network_id
                params = 'network_id=%s' % test_id
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)

                # Get by NON-matching query param: network_id
                params = 'network_id=clearlywontmatch'
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_query_network_name(self):
        test_name = 'net_name_1'
        with self.network(name=test_name) as net:
            with self.subnet(network=net):
                # Get by query param: network_name
                params = 'network_name=%s' % test_name
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)

                # Get by NON-matching query param: network_name
                params = 'network_name=clearly-wont-match'
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_query_tenant_id(self):
        test_tenant_id = 'a-unique-test-id'
        with self.network(tenant_id=test_tenant_id) as net:
            with self.subnet(network=net):
                # Get by query param: tenant_id
                params = 'tenant_id=%s' % test_tenant_id
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)
                for net_avail in response[IP_AVAILS_KEY]:
                    self.assertEqual(test_tenant_id, net_avail['tenant_id'])

                # Get by NON-matching query param: tenant_id
                params = 'tenant_id=clearly-wont-match'
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_query_project_id(self):
        test_project_id = 'a-unique-project-id'
        with self.network(tenant_id=test_project_id) as net:
            with self.subnet(network=net):
                # Get by query param: project_id
                params = 'project_id=%s' % test_project_id
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertIn(IP_AVAILS_KEY, response)
                self.assertEqual(1, len(response[IP_AVAILS_KEY]))
                self._validate_from_availabilities(response[IP_AVAILS_KEY],
                                                   net, 0)
                for net_avail in response[IP_AVAILS_KEY]:
                    self.assertEqual(test_project_id, net_avail['project_id'])

                # Get by NON-matching query param: project_id
                params = 'project_id=clearly-wont-match'
                request = self.new_list_request(API_RESOURCE, params=params)
                response = self.deserialize(self.fmt,
                                            request.get_response(self.ext_api))
                self.assertEqual(0, len(response[IP_AVAILS_KEY]))

    def test_usages_multi_net_multi_subnet_46(self):
        # Setup mixed v4/v6 networks with IPs consumed on each
        with self.network(name='net-v6-1') as net_v6_1, \
                self.network(name='net-v6-2') as net_v6_2, \
                self.network(name='net-v4-1') as net_v4_1, \
                self.network(name='net-v4-2') as net_v4_2:
            with self.subnet(network=net_v6_1, cidr='2607:f0d0:1002:51::/64',
                             ip_version=constants.IP_VERSION_6) as s61, \
                    self.subnet(network=net_v6_2,
                                cidr='2607:f0d0:1003:52::/64',
                                ip_version=constants.IP_VERSION_6) as s62, \
                    self.subnet(network=net_v4_1, cidr='10.0.0.0/24') as s41, \
                    self.subnet(network=net_v4_2, cidr='10.0.1.0/24') as s42:
                with self.port(subnet=s61),\
                        self.port(subnet=s62), self.port(subnet=s62), \
                        self.port(subnet=s41), \
                        self.port(subnet=s42), self.port(subnet=s42):

                    # Verify consumption across all
                    request = self.new_list_request(API_RESOURCE)
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    avails_list = response[IP_AVAILS_KEY]
                    self._validate_from_availabilities(
                            avails_list, net_v6_1, 1, 18446744073709551614)
                    self._validate_from_availabilities(
                            avails_list, net_v6_2, 2, 18446744073709551614)
                    self._validate_from_availabilities(
                            avails_list, net_v4_1, 1, 253)
                    self._validate_from_availabilities(
                            avails_list, net_v4_2, 2, 253)

                    # Query by IP versions. Ensure subnet versions match
                    for ip_ver in [constants.IP_VERSION_4,
                                   constants.IP_VERSION_6]:
                        params = 'ip_version=%i' % ip_ver
                        request = self.new_list_request(API_RESOURCE,
                                                        params=params)
                        response = self.deserialize(
                                self.fmt, request.get_response(self.ext_api))
                        for net_avail in response[IP_AVAILS_KEY]:
                            for sub in net_avail['subnet_ip_availability']:
                                self.assertEqual(ip_ver, sub['ip_version'])

                    # Verify consumption querying 2 network ids (IN clause)
                    request = self.new_list_request(
                            API_RESOURCE,
                            params='network_id=%s&network_id=%s'
                                   % (net_v4_2['network']['id'],
                                      net_v6_2['network']['id']))
                    response = self.deserialize(
                        self.fmt, request.get_response(self.ext_api))
                    avails_list = response[IP_AVAILS_KEY]
                    self._validate_from_availabilities(
                            avails_list, net_v6_2, 2, 18446744073709551614)
                    self._validate_from_availabilities(
                            avails_list, net_v4_2, 2, 253)
