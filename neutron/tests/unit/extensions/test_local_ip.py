# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

import contextlib
from unittest import mock

import netaddr
from neutron_lib.api.definitions import local_ip as apidef
from neutron_lib import constants
import webob.exc

from neutron.extensions import local_ip as lip_ext
from neutron.tests.common import test_db_base_plugin_v2


class LocalIPTestExtensionManager:

    def get_resources(self):
        return lip_ext.Local_ip.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class LocalIPTestBase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_local_ip(self, **kwargs):
        kwargs.setdefault('project_id', self._tenant_id)
        local_ip = {'local_ip': {}}
        for k, v in kwargs.items():
            local_ip['local_ip'][k] = v

        req = self.new_create_request('local-ips', local_ip,
                                      tenant_id=self._tenant_id, as_admin=True)
        res = req.get_response(self.ext_api)
        self._check_http_response(res)
        return self.deserialize(self.fmt, res)

    def _update_local_ip(self, lip_id, data):
        update_req = self.new_update_request(
            'local-ips', data, lip_id, tenant_id=self._tenant_id)
        res = update_req.get_response(self.ext_api)
        self._check_http_response(res)
        return self.deserialize(self.fmt, res)

    def _create_local_ip_association(self, local_ip_id, fixed_port_id,
                                     fixed_ip=None):
        local_ip_assoc = {'port_association': {'fixed_port_id': fixed_port_id,
                                               'fixed_ip': fixed_ip}}

        req = self.new_create_request('local_ips',
                                      data=local_ip_assoc,
                                      id=local_ip_id,
                                      subresource='port_associations',
                                      tenant_id=self._tenant_id)
        res = req.get_response(self.ext_api)
        self._check_http_response(res)
        return self.deserialize(self.fmt, res)

    @contextlib.contextmanager
    def local_ip(self, **kwargs):
        yield self._create_local_ip(**kwargs)

    @contextlib.contextmanager
    def local_ip_assoc(self, local_ip_id, fixed_port_id,
                       fixed_ip=None):
        yield self._create_local_ip_association(
            local_ip_id, fixed_port_id, fixed_ip)


class TestLocalIP(LocalIPTestBase):

    def setUp(self):
        ext_mgr = LocalIPTestExtensionManager()
        svc_plugins = (
            'neutron.services.local_ip.local_ip_plugin.LocalIPPlugin',)
        mock.patch("neutron.api.rpc.handlers.resources_rpc."
                   "ResourcesPushRpcApi.push").start()
        super().setUp(ext_mgr=ext_mgr,
                      service_plugins=svc_plugins)

    def test_create_local_ip_with_local_port_id(self):
        with self.port() as p:
            local_port = p['port']
            with self.local_ip(local_port_id=local_port['id'],
                               name='testname',
                               description='testdescr') as lip:
                lip = lip['local_ip']
                self.assertEqual('testname', lip['name'])
                self.assertEqual('testdescr', lip['description'])
                self.assertEqual(local_port['id'], lip['local_port_id'])
                self.assertEqual(local_port['fixed_ips'][0]['ip_address'],
                                 lip['local_ip_address'])
                self.assertEqual(apidef.IP_MODE_TRANSLATE,
                                 lip['ip_mode'])

    def test_create_local_ip_with_local_port_id_and_ip(self):
        with self.port() as p:
            local_port = p['port']
            ip_addr = local_port['fixed_ips'][0]['ip_address']
            with self.local_ip(local_port_id=local_port['id'],
                               local_ip_address=ip_addr) as lip:
                lip = lip['local_ip']
                self.assertEqual(local_port['id'], lip['local_port_id'])
                self.assertEqual(ip_addr, lip['local_ip_address'])

    def test_create_local_ip_with_local_port_id_and_wrong_ip(self):
        with self.port() as p:
            local_port = p['port']
            try:
                self._create_local_ip(local_port_id=local_port['id'],
                                      local_ip_address='100.0.0.100')
                self.fail("Local IP created with IP "
                          "not belonging to local port")
            except webob.exc.HTTPClientError as e:
                self.assertEqual(400, e.code)

    def test_create_local_ip_with_local_port_id_no_ip(self):
        with self.port() as p:
            local_port = p['port']
            data = {'port': {'fixed_ips': []}}
            req = self.new_update_request('ports', data, local_port['id'])
            req.get_response(self.api)

            try:
                self._create_local_ip(local_port_id=local_port['id'])
                self.fail("Local IP created with Port "
                          "having no IPs")
            except webob.exc.HTTPClientError as e:
                self.assertEqual(400, e.code)

    def _port_add_new_ip(self, port):
        subnet_id = port['fixed_ips'][0]['subnet_id']
        cur_ip = port['fixed_ips'][0]['ip_address']
        data = {'port': {}}
        data['port']['fixed_ips'] = [
            {'subnet_id': subnet_id, 'ip_address': cur_ip},
            {'subnet_id': subnet_id}]
        req = self.new_update_request('ports', data, port['id'])
        port = self.deserialize(self.fmt, req.get_response(self.api))['port']
        for ip in port['fixed_ips']:
            if ip['ip_address'] != cur_ip:
                return ip['ip_address']

    def test_create_local_ip_with_local_port_id_and_multiple_ips(self):
        with self.port() as p:
            local_port = p['port']
            new_ip = self._port_add_new_ip(local_port)
            with self.local_ip(local_port_id=local_port['id'],
                               local_ip_address=new_ip) as lip:
                lip = lip['local_ip']
                self.assertEqual(local_port['id'], lip['local_port_id'])
                self.assertEqual(new_ip, lip['local_ip_address'])

    def test_create_local_ip_with_local_port_id_and_mult_ips_wrong_ip(self):
        with self.port() as p:
            local_port = p['port']
            self._port_add_new_ip(local_port)
            try:
                self._create_local_ip(local_port_id=local_port['id'],
                                      local_ip_address='100.0.0.100')
                self.fail("Local IP created with IP "
                          "not belonging to local port")
            except webob.exc.HTTPClientError as e:
                self.assertEqual(400, e.code)

    def test_create_local_ip_with_network_id(self):
        with self.subnet() as s:
            subnet = s['subnet']
            with self.local_ip(network_id=subnet['network_id'],
                               ip_mode=apidef.IP_MODE_PASSTHROUGH) as lip:
                lip = lip['local_ip']
                self.assertEqual(subnet['network_id'], lip['network_id'])
                self.assertEqual(apidef.IP_MODE_PASSTHROUGH, lip['ip_mode'])

                req = self.new_show_request(
                    'ports', lip['local_port_id'], self.fmt)
                local_port = self.deserialize(
                    self.fmt, req.get_response(self.api))['port']
                self.assertEqual(constants.DEVICE_OWNER_LOCAL_IP,
                                 local_port['device_owner'])
                self.assertEqual(lip['id'], local_port['device_id'])
                self.assertEqual(lip['local_ip_address'],
                                 local_port['fixed_ips'][0]['ip_address'])

    def test_create_local_ip_with_network_id_and_ip(self):
        with self.subnet() as s:
            subnet = s['subnet']
            ip_addr = str(netaddr.IPNetwork(subnet['cidr']).ip + 10)
            with self.local_ip(network_id=subnet['network_id'],
                               local_ip_address=ip_addr) as lip:
                lip = lip['local_ip']
                self.assertEqual(subnet['network_id'], lip['network_id'])
                self.assertEqual(ip_addr, lip['local_ip_address'])

                req = self.new_show_request(
                    'ports', lip['local_port_id'], self.fmt)
                local_port = self.deserialize(
                    self.fmt, req.get_response(self.api))['port']
                self.assertEqual(lip['local_ip_address'],
                                 local_port['fixed_ips'][0]['ip_address'])

    def test_update_local_ip(self):
        with self.subnet() as s:
            subnet = s['subnet']
            with self.local_ip(network_id=subnet['network_id']) as lip:
                data = {'local_ip': {'name': 'bar', 'description': 'bar'}}
                lip = self._update_local_ip(lip['local_ip']['id'], data)
                self.assertEqual(lip['local_ip']['name'],
                                 data['local_ip']['name'])
                self.assertEqual(lip['local_ip']['description'],
                                 data['local_ip']['description'])

    def test_list_local_ips(self):
        with self.subnet() as s:
            subnet = s['subnet']
            with self.local_ip(network_id=subnet['network_id']),\
                    self.local_ip(network_id=subnet['network_id']):
                res = self._list('local-ips')
                self.assertEqual(2, len(res['local_ips']))

    def test_get_local_ip(self):
        with self.subnet() as s:
            subnet = s['subnet']
            with self.local_ip(network_id=subnet['network_id']) as lip:
                req = self.new_show_request('local-ips',
                                            lip['local_ip']['id'])
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                self.assertEqual(lip['local_ip']['id'],
                                 res['local_ip']['id'])

    def test_delete_local_ip(self):
        with self.subnet() as s:
            subnet = s['subnet']
            lip = self._create_local_ip(network_id=subnet['network_id'])
            self._delete('local-ips', lip['local_ip']['id'])
            self._show('local-ips', lip['local_ip']['id'],
                       expected_code=webob.exc.HTTPNotFound.code)

    def test_create_local_ip_association(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            with self.local_ip(network_id=subnet['network_id'],
                               ip_mode=apidef.IP_MODE_PASSTHROUGH) as lip:
                lip = lip['local_ip']
                with self.local_ip_assoc(lip['id'], fixed_port['id']) as assoc:
                    assoc = assoc['port_association']
                    self.assertEqual(fixed_port['id'], assoc['fixed_port_id'])
                    self.assertEqual(fixed_port['fixed_ips'][0]['ip_address'],
                                     assoc['fixed_ip'])

    def test_create_local_ip_association_request_ip(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            fixed_ip = fixed_port['fixed_ips'][0]['ip_address']
            with self.local_ip(network_id=subnet['network_id']) as lip:
                lip = lip['local_ip']
                with self.local_ip_assoc(lip['id'], fixed_port['id'],
                                         fixed_ip=fixed_ip) as assoc:
                    assoc = assoc['port_association']
                    self.assertEqual(fixed_port['id'], assoc['fixed_port_id'])
                    self.assertEqual(fixed_ip, assoc['fixed_ip'])

    def test_create_local_ip_association_request_ip_not_found(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            with self.local_ip(network_id=subnet['network_id']) as lip:
                lip = lip['local_ip']
                try:
                    self._create_local_ip_association(
                        lip['id'], fixed_port['id'], fixed_ip='100.0.0.100')
                    self.fail("Local IP associated with IP "
                              "not belonging to fixed port")
                except webob.exc.HTTPClientError as e:
                    self.assertEqual(400, e.code)

    def test_create_local_ip_association_multiple_ips(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            new_ip = self._port_add_new_ip(fixed_port)
            lip = self._create_local_ip(network_id=subnet['network_id'])
            lip = lip['local_ip']
            assoc = self._create_local_ip_association(
                lip['id'], fixed_port['id'], new_ip)['port_association']
            self.assertEqual(new_ip, assoc['fixed_ip'])

    def test_create_local_ip_association_multiple_ips_negative(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            self._port_add_new_ip(fixed_port)
            lip = self._create_local_ip(network_id=subnet['network_id'])
            lip = lip['local_ip']
            try:
                self._create_local_ip_association(lip['id'], fixed_port['id'])
                self.fail("Local IP associated with Port "
                          "with multiple IPs and no IP specified")
            except webob.exc.HTTPClientError as e:
                self.assertEqual(400, e.code)

    def test_create_local_ip_association_no_ips(self):
        with self.subnet() as s, self.port() as p:
            subnet = s['subnet']
            fixed_port = p['port']
            data = {'port': {'fixed_ips': []}}
            req = self.new_update_request('ports', data, fixed_port['id'])
            req.get_response(self.api)

            lip = self._create_local_ip(network_id=subnet['network_id'])
            lip = lip['local_ip']
            try:
                self._create_local_ip_association(
                    lip['id'], fixed_port['id'])
                self.fail("Local IP associated with Port "
                          "with no IPs")
            except webob.exc.HTTPClientError as e:
                self.assertEqual(400, e.code)

    def test_list_local_ip_associations(self):
        with self.subnet() as s, self.port() as p1, self.port() as p2:
            subnet = s['subnet']
            port1 = p1['port']
            port2 = p2['port']
            lip = self._create_local_ip(network_id=subnet['network_id'])
            lip = lip['local_ip']
            self._create_local_ip_association(lip['id'], port1['id'])
            self._create_local_ip_association(lip['id'], port2['id'])
            res = self._list('local_ips', parent_id=lip['id'],
                             subresource='port_associations')
            self.assertEqual(2, len(res['port_associations']))

    def test_delete_local_ip_association(self):
        with self.subnet() as s, self.port() as p1, self.port() as p2:
            subnet = s['subnet']
            port1 = p1['port']
            port2 = p2['port']
            lip = self._create_local_ip(network_id=subnet['network_id'])
            lip = lip['local_ip']
            self._create_local_ip_association(lip['id'], port1['id'])
            self._create_local_ip_association(lip['id'], port2['id'])
            res = self._list('local_ips', parent_id=lip['id'],
                             subresource='port_associations')
            self.assertEqual(2, len(res['port_associations']))
            self._delete('local_ips', lip['id'],
                         subresource='port_associations',
                         sub_id=port1['id'])
            res = self._list('local_ips', parent_id=lip['id'],
                             subresource='port_associations')
            self.assertEqual(1, len(res['port_associations']))
