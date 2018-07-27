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

import mock
from neutron_lib.api.definitions import floating_ip_port_forwarding as apidef
from neutron_lib import exceptions as lib_exc
from oslo_utils import uuidutils

from neutron.services.portforwarding.common import exceptions as pf_exc
from neutron.services.portforwarding import pf_plugin
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


class PortForwardingTestCaseBase(ml2_test_base.ML2TestFramework):
    def setUp(self):
        super(PortForwardingTestCaseBase, self).setUp()
        self.pf_plugin = pf_plugin.PortForwardingPlugin()

    def _create_floatingip(self, network_id, port_id=None,
                           fixed_ip_address=None):
        body = {"floating_network_id": network_id,
                "port_id": port_id,
                "fixed_ip_address": fixed_ip_address,
                "tenant_id": self._tenant_id,
                "project_id": self._tenant_id}

        return self.l3_plugin.create_floatingip(
            self.context,
            {"floatingip": body})

    def _get_floatingip(self, floatingip_id):
        return self.l3_plugin.get_floatingip(self.context, floatingip_id)

    def _add_router_interface(self, router_id, subnet_id):
        interface_info = {"subnet_id": subnet_id}
        self.l3_plugin.add_router_interface(
            self.context, router_id, interface_info=interface_info)

    def _set_router_gw(self, router_id, ext_net_id):
        body = {
            'router':
                {'external_gateway_info': {'network_id': ext_net_id}}}
        self.l3_plugin.update_router(self.context, router_id, body)


class PortForwardingTestCase(PortForwardingTestCaseBase):
    def setUp(self):
        super(PortForwardingTestCase, self).setUp()
        self._prepare_env()

    def _prepare_env(self):
        self.router = self._create_router()
        self.ext_net = self._create_network(
            self.fmt, 'ext-net', True, arg_list=("router:external",),
            **{"router:external": True}).json['network']
        self.ext_subnet = self._create_subnet(
            self.fmt, self.ext_net['id'], '172.24.2.0/24').json['subnet']
        self.net = self._create_network(self.fmt, 'private', True).json[
            'network']
        self.subnet = self._create_subnet(self.fmt, self.net['id'],
                                          '10.0.0.0/24').json['subnet']
        self._set_router_gw(self.router['id'], self.ext_net['id'])
        self._add_router_interface(self.router['id'], self.subnet['id'])
        self.fip = self._create_floatingip(self.ext_net['id'])
        self.port = self._create_port(self.fmt, self.net['id']).json['port']
        self.port_forwarding = {
            apidef.RESOURCE_NAME:
                {apidef.EXTERNAL_PORT: 2225,
                 apidef.INTERNAL_PORT: 25,
                 apidef.INTERNAL_PORT_ID: self.port['id'],
                 apidef.PROTOCOL: "tcp",
                 apidef.INTERNAL_IP_ADDRESS:
                     self.port['fixed_ips'][0]['ip_address']}}

    def test_create_floatingip_port_forwarding(self):
        res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)
        expect = {
            "external_port": 2225,
            "internal_port": 25,
            "internal_port_id": self.port['id'],
            "protocol": "tcp",
            "internal_ip_address": self.port['fixed_ips'][0]['ip_address'],
            'id': mock.ANY,
            'router_id': self.router['id'],
            'floating_ip_address': self.fip['floating_ip_address'],
            'floatingip_id': self.fip['id']}
        self.assertEqual(expect, res)

    def test_negative_create_floatingip_port_forwarding(self):
        self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        # This will be fail with the same params
        self.assertRaises(lib_exc.BadRequest,
                          self.pf_plugin.create_floatingip_port_forwarding,
                          self.context, self.fip['id'], self.port_forwarding)

    def test_update_floatingip_port_forwarding(self):
        # create a test port forwarding
        res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        # update the socket port only
        update_body = {
            apidef.RESOURCE_NAME: {
                "external_port": 2226,
                "internal_port": 26,
                "protocol": "udp"
            }
        }
        update_res = self.pf_plugin.update_floatingip_port_forwarding(
            self.context, res['id'], self.fip['id'], update_body)
        expect = {
            "external_port": 2226,
            "internal_port": 26,
            "internal_port_id": self.port['id'],
            "protocol": "udp",
            "internal_ip_address": self.port['fixed_ips'][0]['ip_address'],
            'id': res['id'],
            'router_id': self.router['id'],
            'floating_ip_address': self.fip['floating_ip_address'],
            'floatingip_id': self.fip['id']}
        self.assertEqual(expect, update_res)

        # update the neutron port and success
        new_port = self._create_port(self.fmt, self.net['id']).json['port']
        update_body = {
            apidef.RESOURCE_NAME: {
                "external_port": 2227,
                "internal_port": 27,
                "protocol": "tcp",
                "internal_port_id": new_port['id'],
                "internal_ip_address": new_port['fixed_ips'][0]['ip_address']
            }
        }
        update_res = self.pf_plugin.update_floatingip_port_forwarding(
            self.context, res['id'], self.fip['id'], update_body)
        expect = {
            "external_port": 2227,
            "internal_port": 27,
            "internal_port_id": new_port['id'],
            "protocol": "tcp",
            "internal_ip_address": new_port['fixed_ips'][0]['ip_address'],
            'id': res['id'],
            'router_id': self.router['id'],
            'floating_ip_address': self.fip['floating_ip_address'],
            'floatingip_id': self.fip['id']}
        self.assertEqual(expect, update_res)

    def test_negative_update_floatingip_port_forwarding(self):
        # prepare a port forwarding
        res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        # prepare another port and make its gateway set on other router
        new_router = self._create_router()
        new_subnet = self._create_subnet(self.fmt, self.net['id'],
                                         '11.0.0.0/24').json['subnet']
        self._set_router_gw(new_router['id'], self.ext_net['id'])
        self._add_router_interface(new_router['id'], new_subnet['id'])
        # create a port based on the new subnet
        new_port = self._create_port(
            self.fmt, self.net['id'],
            fixed_ips=[{'subnet_id': new_subnet['id']}]).json['port']

        update_body = {
            apidef.RESOURCE_NAME: {
                "external_port": 2227,
                "internal_port": 27,
                "protocol": "tcp",
                "internal_port_id": new_port['id'],
                "internal_ip_address": new_port['fixed_ips'][0]['ip_address']
            }
        }

        # This will be fail, as the new found router_id not match.
        self.assertRaises(lib_exc.BadRequest,
                          self.pf_plugin.update_floatingip_port_forwarding,
                          self.context, res['id'], self.fip['id'], update_body)

        # There is already a port forwarding. We create another port forwarding
        # with the new_port, and update the new one with the same params of the
        # existing one.
        new_port = self._create_port(self.fmt, self.net['id']).json['port']
        self.port_forwarding[apidef.RESOURCE_NAME].update({
            'internal_port_id': new_port['id'],
            'internal_ip_address': new_port['fixed_ips'][0]['ip_address'],
            'external_port': self.port_forwarding[
                                 apidef.RESOURCE_NAME]['external_port'] + 1
        })
        new_res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        self.port_forwarding[apidef.RESOURCE_NAME].update({
            'internal_port_id': self.port['id'],
            'internal_ip_address': self.port['fixed_ips'][0]['ip_address'],
            'external_port': self.port_forwarding[
                                 apidef.RESOURCE_NAME]['external_port'] - 1
        })
        # This will be fail, as the duplicate record.
        self.assertRaises(lib_exc.BadRequest,
                          self.pf_plugin.update_floatingip_port_forwarding,
                          self.context, new_res['id'], self.fip['id'],
                          update_body)

    def test_delete_floatingip_port_forwarding(self):
        # create two port forwardings for a floatingip
        pf_1 = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)
        new_port = self._create_port(self.fmt, self.net['id']).json['port']
        self.port_forwarding[apidef.RESOURCE_NAME].update({
            'external_port': 2226,
            'internal_port_id': new_port['id'],
            'internal_ip_address': new_port['fixed_ips'][0]['ip_address']
        })
        pf_2 = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)
        floatingip = self._get_floatingip(self.fip['id'])
        self.assertEqual(self.router['id'], floatingip['router_id'])

        # delete pf_1, check the router_id of floatingip is not change.
        self.pf_plugin.delete_floatingip_port_forwarding(
            self.context, pf_1['id'], self.fip['id'])
        exist_pfs = self.pf_plugin.get_floatingip_port_forwardings(
            self.context, floatingip_id=self.fip['id'])
        self.assertEqual(1, len(exist_pfs))
        self.assertEqual(pf_2['id'], exist_pfs[0]['id'])

        # delete pf_2, it's the last port forwarding of floatingip.
        self.pf_plugin.delete_floatingip_port_forwarding(
            self.context, pf_2['id'], self.fip['id'])
        exist_pfs = self.pf_plugin.get_floatingip_port_forwardings(
            self.context, floatingip_id=self.fip['id'])
        self.assertEqual(0, len(exist_pfs))
        floatingip = self._get_floatingip(self.fip['id'])
        self.assertIsNone(floatingip['router_id'])

    def test_negative_delete_floatingip_port_forwarding(self):
        # prepare a good port forwarding
        res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        # pass non-existing port forwarding id
        self.assertRaises(pf_exc.PortForwardingNotFound,
                          self.pf_plugin.delete_floatingip_port_forwarding,
                          self.context, uuidutils.generate_uuid(),
                          self.fip['id'])

        # pass existing port forwarding but non-existing floatingip_id
        self.assertRaises(pf_exc.PortForwardingNotFound,
                          self.pf_plugin.delete_floatingip_port_forwarding,
                          self.context, res['id'], uuidutils.generate_uuid())
