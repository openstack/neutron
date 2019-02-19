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

import threading

import mock
from neutron_lib.api.definitions import floating_ip_port_forwarding as apidef
from neutron_lib.callbacks import exceptions as c_exc
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import l3 as lib_l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
from six.moves import queue

from neutron.services.portforwarding.common import exceptions as pf_exc
from neutron.services.portforwarding import pf_plugin
from neutron.tests.functional import base as functional_base
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


class PortForwardingTestCaseBase(ml2_test_base.ML2TestFramework,
                                 functional_base.BaseLoggingTestCase):
    def setUp(self):
        super(PortForwardingTestCaseBase, self).setUp()
        self.pf_plugin = pf_plugin.PortForwardingPlugin()
        directory.add_plugin(plugin_constants.PORTFORWARDING, self.pf_plugin)

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

    def _update_floatingip(self, fip_id, update_info):
        return self.l3_plugin.update_floatingip(
            self.context, fip_id, {"floatingip": update_info})

    def _delete_floatingip(self, fip_id):
        return self.l3_plugin.delete_floatingip(self.context, fip_id)

    def _update_port(self, port_id, update_info):
        return self.core_plugin.update_port(
            self.context, port_id, {'port': update_info})

    def _delete_port(self, port_id):
        return self.core_plugin.delete_port(self.context, port_id)

    def _add_router_interface(self, router_id, subnet_id):
        interface_info = {"subnet_id": subnet_id}
        self.l3_plugin.add_router_interface(
            self.context, router_id, interface_info=interface_info)

    def _remove_router_interface(self, router_id, subnet_id):
        interface_info = {"subnet_id": subnet_id}
        self.l3_plugin.remove_router_interface(
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
        self.router = self._create_router(distributed=True)
        self.ext_net = self._create_network(
            self.fmt, 'ext-net', True, arg_list=("router:external",),
            **{"router:external": True}).json['network']
        self.ext_subnet = self._create_subnet(
            self.fmt, self.ext_net['id'], '172.24.2.0/24').json['subnet']
        self.net = self._create_network(self.fmt, 'private', True).json[
            'network']
        self.subnet = self._create_subnet(
            self.fmt, self.net['id'], '10.0.0.0/24',
            enable_dhcp=False).json['subnet']
        self._set_router_gw(self.router['id'], self.ext_net['id'])
        self._add_router_interface(self.router['id'], self.subnet['id'])
        self.fip = self._create_floatingip(self.ext_net['id'])
        self.port = self._create_port(
            self.fmt, self.net['id'],
            fixed_ips=[{'subnet_id': self.subnet['id']}]).json['port']
        self.port_forwarding = {
            apidef.RESOURCE_NAME:
                {apidef.EXTERNAL_PORT: 2225,
                 apidef.INTERNAL_PORT: 25,
                 apidef.INTERNAL_PORT_ID: self.port['id'],
                 apidef.PROTOCOL: "tcp",
                 apidef.INTERNAL_IP_ADDRESS:
                     self.port['fixed_ips'][0]['ip_address']}}

    def test_create_floatingip_port_forwarding_and_remove_subnets(self):
        subnet_2 = self._create_subnet(self.fmt, self.net['id'],
                                       '10.0.2.0/24').json['subnet']
        self._add_router_interface(self.router['id'], subnet_2['id'])
        subnet_3 = self._create_subnet(self.fmt, self.net['id'],
                                       '10.0.3.0/24').json['subnet']
        self._add_router_interface(self.router['id'], subnet_3['id'])

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

        self.assertRaises(lib_l3_exc.RouterInterfaceInUseByFloatingIP,
                          self._remove_router_interface,
                          self.router['id'], self.subnet['id'])

        self._remove_router_interface(self.router['id'], subnet_2['id'])
        self._remove_router_interface(self.router['id'], subnet_3['id'])

    def test_create_floatingip_port_forwarding_external_port_0(self):
        self.port_forwarding[apidef.RESOURCE_NAME][apidef.EXTERNAL_PORT] = 0

        self.assertRaises(ValueError,
                          self.pf_plugin.create_floatingip_port_forwarding,
                          self.context, self.fip['id'], self.port_forwarding)

    def test_create_floatingip_port_forwarding_internal_port_0(self):
        self.port_forwarding[apidef.RESOURCE_NAME][apidef.INTERNAL_PORT] = 0

        self.assertRaises(ValueError,
                          self.pf_plugin.create_floatingip_port_forwarding,
                          self.context, self.fip['id'], self.port_forwarding)

    def test_negative_create_floatingip_port_forwarding(self):
        self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)

        # This will be fail with the same params
        self.assertRaises(lib_exc.BadRequest,
                          self.pf_plugin.create_floatingip_port_forwarding,
                          self.context, self.fip['id'], self.port_forwarding)

    def test_create_port_forwarding_port_in_used_by_fip(self):
        normal_fip = self._create_floatingip(self.ext_net['id'])
        self._update_floatingip(normal_fip['id'], {'port_id': self.port['id']})
        self.assertRaises(
            pf_exc.PortHasBindingFloatingIP,
            self.pf_plugin.create_floatingip_port_forwarding,
            self.context, self.fip['id'], self.port_forwarding)

    def test_update_port_forwarding_port_in_used_by_fip(self):
        normal_fip = self._create_floatingip(self.ext_net['id'])
        normal_port = self._create_port(
            self.fmt, self.net['id']).json['port']
        self._update_floatingip(
            normal_fip['id'], {'port_id': normal_port['id']})

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

        # Directly update port forwarding to a port which already has
        # bound floating IP.
        self.port_forwarding[apidef.RESOURCE_NAME].update(
            {apidef.INTERNAL_PORT_ID: normal_port['id'],
             apidef.INTERNAL_IP_ADDRESS:
                 normal_port['fixed_ips'][0]['ip_address']})
        self.assertRaises(
            pf_exc.PortHasBindingFloatingIP,
            self.pf_plugin.update_floatingip_port_forwarding,
            self.context, res['id'], self.fip['id'], self.port_forwarding)

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

    def _simulate_concurrent_requests_process_and_raise(
            self, funcs, args_list):

        class SimpleThread(threading.Thread):
            def __init__(self, q):
                super(SimpleThread, self).__init__()
                self.q = q
                self.exception = None

            def run(self):
                try:
                    while not self.q.empty():
                        item = None
                        try:
                            item = self.q.get(False)
                            func, func_args = item[0], item[1]
                            func(*func_args)
                        except queue.Empty:
                            pass
                        finally:
                            if item:
                                self.q.task_done()
                except Exception as e:
                    self.exception = e

            def get_exception(self):
                return self.exception

        q = queue.Queue()
        for func, func_args in zip(funcs, args_list):
            q.put_nowait((func, func_args))
        threads = []
        for _ in range(len(funcs)):
            t = SimpleThread(q)
            threads.append(t)
            t.start()
        q.join()

        for t in threads:
            e = t.get_exception()
            if e:
                raise e

    def test_concurrent_create_port_forwarding_delete_fip(self):

        func1 = self.pf_plugin.create_floatingip_port_forwarding
        func2 = self._delete_floatingip
        funcs = [func1, func2]
        args_list = [(self.context, self.fip['id'], self.port_forwarding),
                     (self.fip['id'],)]
        self.assertRaises(c_exc.CallbackFailure,
                          self._simulate_concurrent_requests_process_and_raise,
                          funcs, args_list)

        port_forwardings = self.pf_plugin.get_floatingip_port_forwardings(
            self.context, floatingip_id=self.fip['id'], fields=['id'])
        self.pf_plugin.delete_floatingip_port_forwarding(
            self.context, port_forwardings[0][apidef.ID],
            floatingip_id=self.fip['id'])

        funcs.reverse()
        args_list.reverse()
        self.assertRaises(lib_l3_exc.FloatingIPNotFound,
                          self._simulate_concurrent_requests_process_and_raise,
                          funcs, args_list)

    def test_concurrent_create_port_forwarding_update_fip(self):
        newport = self._create_port(self.fmt, self.net['id']).json['port']
        func1 = self.pf_plugin.create_floatingip_port_forwarding
        func2 = self._update_floatingip
        funcs = [func1, func2]
        args_list = [(self.context, self.fip['id'], self.port_forwarding),
                     (self.fip['id'], {'port_id': newport['id']})]
        self.assertRaises(c_exc.CallbackFailure,
                          self._simulate_concurrent_requests_process_and_raise,
                          funcs, args_list)

        funcs.reverse()
        args_list.reverse()
        self.assertRaises(c_exc.CallbackFailure,
                          self._simulate_concurrent_requests_process_and_raise,
                          funcs, args_list)

    def test_concurrent_create_port_forwarding_update_port(self):
        new_ip = self._find_ip_address(self.subnet)
        funcs = [self.pf_plugin.create_floatingip_port_forwarding,
                 self._update_port]
        args_list = [(self.context, self.fip['id'], self.port_forwarding),
                     (self.port['id'], {
                         'fixed_ips': [{'subnet_id': self.subnet['id'],
                                        'ip_address': new_ip}]})]
        self._simulate_concurrent_requests_process_and_raise(funcs, args_list)
        self.assertEqual([], self.pf_plugin.get_floatingip_port_forwardings(
            self.context, floatingip_id=self.fip['id']))

    def test_concurrent_create_port_forwarding_delete_port(self):
        funcs = [self.pf_plugin.create_floatingip_port_forwarding,
                 self._delete_port]
        args_list = [(self.context, self.fip['id'], self.port_forwarding),
                     (self.port['id'],)]
        self._simulate_concurrent_requests_process_and_raise(funcs, args_list)
        self.assertEqual([], self.pf_plugin.get_floatingip_port_forwardings(
            self.context, floatingip_id=self.fip['id']))

    def test_create_floatingip_port_forwarding_port_in_use(self):
        res = self.pf_plugin.create_floatingip_port_forwarding(
            self.context, self.fip['id'], self.port_forwarding)
        expected = {
            "external_port": 2225,
            "internal_port": 25,
            "internal_port_id": self.port['id'],
            "protocol": "tcp",
            "internal_ip_address": self.port['fixed_ips'][0]['ip_address'],
            'id': mock.ANY,
            'router_id': self.router['id'],
            'floating_ip_address': self.fip['floating_ip_address'],
            'floatingip_id': self.fip['id']}
        self.assertEqual(expected, res)

        fip_2 = self._create_floatingip(self.ext_net['id'])
        self.assertRaises(
            pf_exc.PortHasPortForwarding,
            self._update_floatingip,
            fip_2['id'], {'port_id': self.port['id']})
