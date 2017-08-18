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
import testtools

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config

CONF = config.CONF


class FloatingIPAdminTestJSON(base.BaseAdminNetworkTest):
    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def resource_setup(cls):
        super(FloatingIPAdminTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        cls.floating_ip = cls.create_floatingip(cls.ext_net_id)
        cls.alt_client = cls.os_alt.network_client
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = cls.create_port(cls.network)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('11116ee9-4e99-5b15-b8e1-aa7df92ca589')
    def test_associate_floating_ip_with_port_from_another_project(self):
        body = self.client.create_floatingip(
            floating_network_id=self.ext_net_id)
        floating_ip = body['floatingip']
        test_project = data_utils.rand_name('test_project_')
        test_description = data_utils.rand_name('desc_')
        project = self.identity_admin_client.create_project(
            name=test_project, description=test_description)['project']
        project_id = project['id']
        self.addCleanup(self.identity_admin_client.delete_project, project_id)

        port = self.admin_client.create_port(network_id=self.network['id'],
                                             project_id=project_id)
        self.addCleanup(self.admin_client.delete_port, port['port']['id'])
        self.assertRaises(lib_exc.BadRequest,
                          self.client.update_floatingip,
                          floating_ip['id'], port_id=port['port']['id'])

    @testtools.skipUnless(
        CONF.neutron_plugin_options.specify_floating_ip_address_available,
        "Feature for specifying floating IP address is disabled")
    @decorators.idempotent_id('332a8ae4-402e-4b98-bb6f-532e5a87b8e0')
    def test_create_floatingip_with_specified_ip_address(self):
        # other tests may end up stealing the IP before we can use it
        # since it's on the external network so we need to retry if it's
        # in use.
        for i in range(100):
            fip = self.get_unused_ip(self.ext_net_id, ip_version=4)
            try:
                body = self.admin_client.create_floatingip(
                    floating_network_id=self.ext_net_id,
                    floating_ip_address=fip)
                break
            except lib_exc.Conflict:
                pass
        else:
            self.fail("Could not get an unused IP after 100 attempts")
        created_floating_ip = body['floatingip']
        self.addCleanup(self.admin_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertEqual(created_floating_ip['floating_ip_address'], fip)
