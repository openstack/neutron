# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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
#

import mock
from oslo_serialization import jsonutils

from neutron.plugins.oneconvergence.lib import nvsdlib
from neutron.tests import base

NETWORKS_URI = "/pluginhandler/ocplugin/tenant/%s/lnetwork/"
NETWORK_URI = NETWORKS_URI + "%s"
GET_ALL_NETWORKS = "/pluginhandler/ocplugin/tenant/getallnetworks"

SUBNETS_URI = NETWORK_URI + "/lsubnet/"
SUBNET_URI = SUBNETS_URI + "%s"
GET_ALL_SUBNETS = "/pluginhandler/ocplugin/tenant/getallsubnets"

PORTS_URI = NETWORK_URI + "/lport/"
PORT_URI = PORTS_URI + "%s"

EXT_URI = "/pluginhandler/ocplugin/ext/tenant/%s"
FLOATING_IPS_URI = EXT_URI + "/floatingip/"
FLOATING_IP_URI = FLOATING_IPS_URI + "%s"

ROUTERS_URI = EXT_URI + "/lrouter/"
ROUTER_URI = ROUTERS_URI + "%s"

TEST_NET = 'test-network'
TEST_SUBNET = 'test-subnet'
TEST_PORT = 'test-port'
TEST_FIP = 'test-floatingip'
TEST_ROUTER = 'test-router'
TEST_TENANT = 'test-tenant'


class TestNVSDApi(base.BaseTestCase):

    def setUp(self):
        super(TestNVSDApi, self).setUp()
        self.nvsdlib = nvsdlib.NVSDApi()

    def test_create_network(self):
        network_obj = {
            "name": 'test-net',
            "tenant_id": TEST_TENANT,
            "shared": False,
            "admin_state_up": True,
            "router:external": False
        }
        resp = mock.Mock()
        resp.json.return_value = {'id': 'uuid'}
        with mock.patch.object(self.nvsdlib, 'send_request',
                               return_value=resp) as send_request:
            uri = NETWORKS_URI % TEST_TENANT
            net = self.nvsdlib.create_network(network_obj)
            send_request.assert_called_once_with(
                "POST", uri,
                body=jsonutils.dumps(network_obj),
                resource='network',
                tenant_id=TEST_TENANT)
            self.assertEqual(net, {'id': 'uuid'})

    def test_update_network(self):
        network = {'id': TEST_NET,
                   'tenant_id': TEST_TENANT}
        update_network = {'name': 'new_name'}
        uri = NETWORK_URI % (TEST_TENANT, TEST_NET)
        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.update_network(network, update_network)
            send_request.assert_called_once_with(
                "PUT", uri, body=jsonutils.dumps(update_network),
                resource='network', tenant_id=TEST_TENANT,
                resource_id=TEST_NET)

    def test_delete_network(self):
        network = {'id': TEST_NET,
                   'tenant_id': TEST_TENANT}

        uri = NETWORK_URI % (TEST_TENANT, TEST_NET)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            with mock.patch.object(self.nvsdlib, '_get_ports'):
                self.nvsdlib.delete_network(network)
                send_request.assert_called_once_with(
                    "DELETE", uri, resource='network',
                    tenant_id=TEST_TENANT, resource_id=TEST_NET)

    def test_create_port(self):
        path = PORTS_URI % (TEST_TENANT, TEST_NET)
        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            fixed_ips = [{'ip_address': '10.0.0.2',
                          'subnet_id': TEST_SUBNET}]

            lport = {
                "id": TEST_PORT,
                "name": 'test',
                "device_id": "device_id",
                "device_owner": "device_owner",
                "mac_address": "mac_address",
                "fixed_ips": fixed_ips,
                "admin_state_up": True,
                "network_id": TEST_NET,
                "status": 'ACTIVE'
            }
            self.nvsdlib.create_port(TEST_TENANT, lport)
            expected = {"id": TEST_PORT, "name": 'test',
                        "device_id": "device_id",
                        "device_owner": "device_owner",
                        "mac_address": "mac_address",
                        "ip_address": '10.0.0.2',
                        "subnet_id": TEST_SUBNET,
                        "admin_state_up": True,
                        "network_id": TEST_NET,
                        "status": 'ACTIVE'}
            send_request.assert_called_once_with(
                "POST", path,
                body=jsonutils.dumps(expected),
                resource='port',
                tenant_id=TEST_TENANT)

    def test_update_port(self):
        port = {'id': TEST_PORT,
                'network_id': TEST_NET}

        port_update = {'name': 'new-name'}
        uri = PORT_URI % (TEST_TENANT, TEST_NET, TEST_PORT)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.update_port(TEST_TENANT, port, port_update)
            send_request.assert_called_once_with(
                "PUT", uri,
                body=jsonutils.dumps(port_update),
                resource='port',
                resource_id='test-port',
                tenant_id=TEST_TENANT)

    def test_delete_port(self):
        port = {'network_id': TEST_NET,
                'tenant_id': TEST_TENANT}
        uri = PORT_URI % (TEST_TENANT, TEST_NET, TEST_PORT)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.delete_port(TEST_PORT, port)
            send_request.assert_called_once_with("DELETE", uri,
                                                 resource='port',
                                                 tenant_id=TEST_TENANT,
                                                 resource_id=TEST_PORT)

    def test_create_subnet(self):
        subnet = {'id': TEST_SUBNET,
                  'tenant_id': TEST_TENANT,
                  'network_id': TEST_NET}
        uri = SUBNETS_URI % (TEST_TENANT, TEST_NET)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.create_subnet(subnet)
            send_request.assert_called_once_with("POST", uri,
                                                 body=jsonutils.dumps(subnet),
                                                 resource='subnet',
                                                 tenant_id=TEST_TENANT)

    def test_update_subnet(self):
        subnet = {'id': TEST_SUBNET,
                  'tenant_id': TEST_TENANT,
                  'network_id': TEST_NET}
        subnet_update = {'name': 'new-name'}
        uri = SUBNET_URI % (TEST_TENANT, TEST_NET, TEST_SUBNET)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.update_subnet(subnet, subnet_update)
            send_request.assert_called_once_with(
                "PUT", uri,
                body=jsonutils.dumps(subnet_update), resource='subnet',
                tenant_id=TEST_TENANT, resource_id=TEST_SUBNET)

    def test_delete_subnet(self):
        subnet = {'id': TEST_SUBNET,
                  'tenant_id': TEST_TENANT,
                  'network_id': TEST_NET}
        uri = SUBNET_URI % (TEST_TENANT, TEST_NET, TEST_SUBNET)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.delete_subnet(subnet)
            send_request.assert_called_once_with("DELETE", uri,
                                                 resource='subnet',
                                                 tenant_id=TEST_TENANT,
                                                 resource_id=TEST_SUBNET)

    def test_create_floatingip(self):
        floatingip = {'id': TEST_FIP,
                      'tenant_id': TEST_TENANT}
        uri = FLOATING_IPS_URI % TEST_TENANT

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.create_floatingip(floatingip)
            send_request.assert_called_once_with(
                "POST", uri,
                body=jsonutils.dumps(floatingip),
                resource='floating_ip',
                tenant_id=TEST_TENANT)

    def test_update_floatingip(self):
        floatingip = {'id': TEST_FIP,
                      'tenant_id': TEST_TENANT}
        uri = FLOATING_IP_URI % (TEST_TENANT, TEST_FIP)

        floatingip_update = {'floatingip': {'router_id': TEST_ROUTER}}
        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.update_floatingip(floatingip, floatingip_update)
            send_request.assert_called_once_with(
                "PUT", uri,
                body=jsonutils.dumps(floatingip_update['floatingip']),
                resource='floating_ip', tenant_id=TEST_TENANT,
                resource_id=TEST_FIP)

    def test_delete_floatingip(self):
        floatingip = {'id': TEST_FIP,
                      'tenant_id': TEST_TENANT}
        uri = FLOATING_IP_URI % (TEST_TENANT, TEST_FIP)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.delete_floatingip(floatingip)
            send_request.assert_called_once_with(
                "DELETE", uri, resource='floating_ip', tenant_id=TEST_TENANT,
                resource_id=TEST_FIP)

    def test_create_router(self):
        router = {'id': TEST_ROUTER, 'tenant_id': TEST_TENANT}
        uri = ROUTERS_URI % TEST_TENANT

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.create_router(router)
            send_request.assert_called_once_with(
                "POST", uri, body=jsonutils.dumps(router), resource='router',
                tenant_id=TEST_TENANT)

    def test_update_router(self):
        router = {'id': TEST_ROUTER, 'tenant_id': TEST_TENANT}
        uri = ROUTER_URI % (TEST_TENANT, TEST_ROUTER)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.update_router(router)
            send_request.assert_called_once_with(
                "PUT", uri, body=jsonutils.dumps(router),
                resource='router', tenant_id=TEST_TENANT,
                resource_id=TEST_ROUTER)

    def test_delete_router(self):
        uri = ROUTER_URI % (TEST_TENANT, TEST_ROUTER)

        with mock.patch.object(self.nvsdlib, 'send_request') as send_request:
            self.nvsdlib.delete_router(TEST_TENANT, TEST_ROUTER)
            send_request.assert_called_once_with(
                "DELETE", uri, resource='router',
                tenant_id=TEST_TENANT, resource_id=TEST_ROUTER)
