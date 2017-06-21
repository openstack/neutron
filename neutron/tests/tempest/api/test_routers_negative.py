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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron.tests.tempest.api import base_routers as base


class RoutersNegativeTestBase(base.BaseRouterTest):

    required_extensions = ['router']

    @classmethod
    def resource_setup(cls):
        super(RoutersNegativeTestBase, cls).resource_setup()
        cls.router = cls.create_router(data_utils.rand_name('router'))
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)


class RoutersNegativeTest(RoutersNegativeTestBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('e3e751af-15a2-49cc-b214-a7154579e94f')
    def test_delete_router_in_use(self):
        # This port is deleted after a test by remove_router_interface.
        port = self.client.create_port(network_id=self.network['id'])
        self.client.add_router_interface_with_port_id(
            self.router['id'], port['port']['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_router(self.router['id'])


class RoutersNegativePolicyTest(RoutersNegativeTestBase):

    credentials = ['admin', 'primary', 'alt']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('159f576d-a423-46b5-b501-622694c02f6b')
    def test_add_interface_wrong_tenant(self):
        client2 = self.os_alt.network_client
        network = client2.create_network()['network']
        self.addCleanup(client2.delete_network, network['id'])
        subnet = self.create_subnet(network, client=client2)
        # This port is deleted after a test by remove_router_interface.
        port = client2.create_port(network_id=network['id'])['port']
        self.addCleanup(client2.delete_port, port['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            client2.add_router_interface_with_port_id(
                self.router['id'], port['id'])
        with testtools.ExpectedException(lib_exc.NotFound):
            client2.add_router_interface_with_subnet_id(
                self.router['id'], subnet['id'])


class DvrRoutersNegativeTest(RoutersNegativeTestBase):

    required_extensions = ['dvr']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('4990b055-8fc7-48ab-bba7-aa28beaad0b9')
    def test_router_create_tenant_distributed_returns_forbidden(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_router(
                data_utils.rand_name('router'), distributed=True)


class HaRoutersNegativeTest(RoutersNegativeTestBase):

    required_extensions = ['l3-ha']

    @decorators.attr(type='negative')
    @decorators.idempotent_id('821b85b9-9c51-40f3-831f-bf223a7e0084')
    def test_router_create_tenant_ha_returns_forbidden(self):
        with testtools.ExpectedException(lib_exc.Forbidden):
            self.create_router(
                data_utils.rand_name('router'), ha=True)
