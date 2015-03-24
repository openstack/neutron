# Copyright 2013 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils

from neutron.tests.api import base
from neutron.tests.tempest import test


class ExtraDHCPOptionsTestJSON(base.BaseNetworkTest):

    """
    Tests the following operations with the Extra DHCP Options Neutron API
    extension:

        port create
        port list
        port show
        port update

    v2.0 of the Neutron API is assumed. It is also assumed that the Extra
    DHCP Options extension is enabled in the [network-feature-enabled]
    section of etc/tempest.conf
    """

    @classmethod
    def resource_setup(cls):
        super(ExtraDHCPOptionsTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('extra_dhcp_opt', 'network'):
            msg = "Extra DHCP Options extension not enabled."
            raise cls.skipException(msg)
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.port = cls.create_port(cls.network)
        cls.ip_tftp = ('123.123.123.123' if cls._ip_version == 4
                       else '2015::dead')
        cls.ip_server = ('123.123.123.45' if cls._ip_version == 4
                         else '2015::badd')
        cls.extra_dhcp_opts = [
            {'opt_value': 'pxelinux.0', 'opt_name': 'bootfile-name'},
            {'opt_value': cls.ip_tftp, 'opt_name': 'tftp-server'},
            {'opt_value': cls.ip_server, 'opt_name': 'server-ip-address'}
        ]

    @test.attr(type='smoke')
    @test.idempotent_id('d2c17063-3767-4a24-be4f-a23dbfa133c9')
    def test_create_list_port_with_extra_dhcp_options(self):
        # Create a port with Extra DHCP Options
        body = self.client.create_port(
            network_id=self.network['id'],
            extra_dhcp_opts=self.extra_dhcp_opts)
        port_id = body['port']['id']
        self.addCleanup(self.client.delete_port, port_id)

        # Confirm port created has Extra DHCP Options
        body = self.client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        self.assertTrue(port)
        self._confirm_extra_dhcp_options(port[0], self.extra_dhcp_opts)

    @test.attr(type='smoke')
    @test.idempotent_id('9a6aebf4-86ee-4f47-b07a-7f7232c55607')
    def test_update_show_port_with_extra_dhcp_options(self):
        # Update port with extra dhcp options
        name = data_utils.rand_name('new-port-name')
        body = self.client.update_port(
            self.port['id'],
            name=name,
            extra_dhcp_opts=self.extra_dhcp_opts)
        # Confirm extra dhcp options were added to the port
        body = self.client.show_port(self.port['id'])
        self._confirm_extra_dhcp_options(body['port'], self.extra_dhcp_opts)

    def _confirm_extra_dhcp_options(self, port, extra_dhcp_opts):
        retrieved = port['extra_dhcp_opts']
        self.assertEqual(len(retrieved), len(extra_dhcp_opts))
        for retrieved_option in retrieved:
            for option in extra_dhcp_opts:
                if (retrieved_option['opt_value'] == option['opt_value'] and
                    retrieved_option['opt_name'] == option['opt_name']):
                    break
            else:
                self.fail('Extra DHCP option not found in port %s' %
                          str(retrieved_option))


class ExtraDHCPOptionsIpV6TestJSON(ExtraDHCPOptionsTestJSON):
    _ip_version = 6
