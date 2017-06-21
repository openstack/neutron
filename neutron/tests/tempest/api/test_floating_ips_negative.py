# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config

CONF = config.CONF


class FloatingIPNegativeTestJSON(base.BaseNetworkTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(FloatingIPNegativeTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create a network with a subnet connected to a router.
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router'))
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = cls.create_port(cls.network)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('0b5b8797-6de7-4191-905c-a48b888eb429')
    def test_associate_floatingip_with_port_with_floatingip(self):
        net = self.create_network()
        subnet = self.create_subnet(net)
        r = self.create_router('test')
        self.create_router_interface(r['id'], subnet['id'])
        self.client.update_router(
            r['id'],
            external_gateway_info={
                'network_id': self.ext_net_id})
        self.addCleanup(self.client.update_router, self.router['id'],
                        external_gateway_info={})
        port = self.create_port(net)
        body1 = self.client.create_floatingip(
            floating_network_id=self.ext_net_id)
        floating_ip1 = body1['floatingip']
        self.addCleanup(self.client.delete_floatingip, floating_ip1['id'])
        body2 = self.client.create_floatingip(
            floating_network_id=self.ext_net_id)
        floating_ip2 = body2['floatingip']
        self.addCleanup(self.client.delete_floatingip, floating_ip2['id'])
        self.client.update_floatingip(floating_ip1['id'],
                                      port_id=port['id'])
        self.assertRaises(lib_exc.Conflict, self.client.update_floatingip,
                          floating_ip2['id'], port_id=port['id'])
