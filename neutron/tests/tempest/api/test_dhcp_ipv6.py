# Copyright 2014 OpenStack Foundation
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
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config

CONF = config.CONF


class NetworksTestDHCPv6(base.BaseNetworkTest):
    _ip_version = 6

    def setUp(self):
        super(NetworksTestDHCPv6, self).setUp()
        self.addCleanup(self._clean_network)

    @classmethod
    def skip_checks(cls):
        super(NetworksTestDHCPv6, cls).skip_checks()
        msg = None
        if not CONF.network_feature_enabled.ipv6:
            msg = "IPv6 is not enabled"
        elif not CONF.network_feature_enabled.ipv6_subnet_attributes:
            msg = "DHCPv6 attributes are not enabled."
        if msg:
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NetworksTestDHCPv6, cls).resource_setup()
        cls.network = cls.create_network()

    def _remove_from_list_by_index(self, things_list, elem):
        for index, i in enumerate(things_list):
            if i['id'] == elem['id']:
                break
        del things_list[index]

    def _clean_network(self):
        body = self.client.list_ports()
        ports = body['ports']
        for port in ports:
            if (port['device_owner'].startswith(
                    constants.DEVICE_OWNER_ROUTER_INTF)
                and port['device_id'] in [r['id'] for r in self.routers]):
                self.client.remove_router_interface_with_port_id(
                    port['device_id'], port['id']
                )
            else:
                if port['id'] in [p['id'] for p in self.ports]:
                    self.client.delete_port(port['id'])
                    self._remove_from_list_by_index(self.ports, port)
        body = self.client.list_subnets()
        subnets = body['subnets']
        for subnet in subnets:
            if subnet['id'] in [s['id'] for s in self.subnets]:
                self.client.delete_subnet(subnet['id'])
                self._remove_from_list_by_index(self.subnets, subnet)
        body = self.client.list_routers()
        routers = body['routers']
        for router in routers:
            if router['id'] in [r['id'] for r in self.routers]:
                self.client.delete_router(router['id'])
                self._remove_from_list_by_index(self.routers, router)

    @decorators.idempotent_id('98244d88-d990-4570-91d4-6b25d70d08af')
    def test_dhcp_stateful_fixedips_outrange(self):
        """When port gets IP address from fixed IP range it
        shall be checked if it's from subnets range.
        """
        kwargs = {'ipv6_ra_mode': 'dhcpv6-stateful',
                  'ipv6_address_mode': 'dhcpv6-stateful'}
        subnet = self.create_subnet(self.network, **kwargs)
        ip_range = netaddr.IPRange(subnet["allocation_pools"][0]["start"],
                                   subnet["allocation_pools"][0]["end"])
        for i in range(1, 3):
            ip = netaddr.IPAddress(ip_range.last + i).format()
            self.assertRaises(lib_exc.BadRequest,
                              self.create_port,
                              self.network,
                              fixed_ips=[{'subnet_id': subnet['id'],
                                          'ip_address': ip}])
