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

from neutron.tests.api import base


class BaseRouterTest(base.BaseAdminNetworkTest):
    # NOTE(salv-orlando): This class inherits from BaseAdminNetworkTest
    # as some router operations, such as enabling or disabling SNAT
    # require admin credentials by default

    @classmethod
    def resource_setup(cls):
        super(BaseRouterTest, cls).resource_setup()

    def _cleanup_router(self, router):
        self.delete_router(router)
        self.routers.remove(router)

    def _create_router(self, name, admin_state_up=False,
                       external_network_id=None, enable_snat=None):
        # associate a cleanup with created routers to avoid quota limits
        router = self.create_router(name, admin_state_up,
                                    external_network_id, enable_snat)
        self.addCleanup(self._cleanup_router, router)
        return router

    def _delete_router(self, router_id, network_client=None):
        client = network_client or self.client
        client.delete_router(router_id)
        # Asserting that the router is not found in the list
        # after deletion
        list_body = self.client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertNotIn(router_id, routers_list)

    def _add_router_interface_with_subnet_id(self, router_id, subnet_id):
        interface = self.client.add_router_interface_with_subnet_id(
            router_id, subnet_id)
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router_id, subnet_id)
        self.assertEqual(subnet_id, interface['subnet_id'])
        return interface

    def _remove_router_interface_with_subnet_id(self, router_id, subnet_id):
        body = self.client.remove_router_interface_with_subnet_id(
            router_id, subnet_id)
        self.assertEqual(subnet_id, body['subnet_id'])

    def _remove_router_interface_with_port_id(self, router_id, port_id):
        body = self.client.remove_router_interface_with_port_id(router_id,
                                                                port_id)
        self.assertEqual(port_id, body['port_id'])
