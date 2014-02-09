# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mock import patch
from oslo.config import cfg
import webob.exc

from neutron import context
from neutron.extensions import portbindings
from neutron.manager import NeutronManager
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.bigswitch import fake_server
from neutron.tests.unit.bigswitch import test_base
from neutron.tests.unit import test_api_v2
import neutron.tests.unit.test_db_plugin as test_plugin


class BigSwitchProxyPluginV2TestCase(test_base.BigSwitchTestBase,
                                     test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, plugin_name=None):
        self.setup_config_files()
        self.setup_patches()
        if plugin_name:
            self._plugin_name = plugin_name
        super(BigSwitchProxyPluginV2TestCase,
              self).setUp(self._plugin_name)


class TestBigSwitchProxyBasicGet(test_plugin.TestBasicGet,
                                 BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxyV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                       BigSwitchProxyPluginV2TestCase):

    def test_failover_memory(self):
        # first request causes failover so next shouldn't hit bad server
        with self.network() as net:
            kwargs = {'tenant_id': 'ExceptOnBadServer'}
            with self.network(**kwargs) as net:
                req = self.new_show_request('networks', net['network']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 200)


class TestBigSwitchProxyPortsV2(test_plugin.TestPortsV2,
                                BigSwitchProxyPluginV2TestCase,
                                test_bindings.PortBindingsTestCase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    def _get_ports(self, netid):
        return self.deserialize('json',
                                self._list_ports('json', netid=netid))['ports']

    def test_rollback_for_port_create(self):
        with self.network(no_delete=True) as n:
            self.httpPatch = patch('httplib.HTTPConnection', create=True,
                                   new=fake_server.HTTPConnectionMock500)
            self.httpPatch.start()
            kwargs = {'device_id': 'somedevid',
                      'tenant_id': n['network']['tenant_id']}
            self._create_port('json', n['network']['id'],
                              expected_code=
                              webob.exc.HTTPInternalServerError.code,
                              **kwargs)
            self.httpPatch.stop()
            ports = self._get_ports(n['network']['id'])
            #failure to create should result in no ports
            self.assertEqual(0, len(ports))

    def test_rollback_for_port_update(self):
        with self.network() as n:
            with self.port(network_id=n['network']['id'],
                           device_id='66') as port:
                port = self._get_ports(n['network']['id'])[0]
                data = {'port': {'name': 'aNewName', 'device_id': '99'}}
                self.httpPatch = patch('httplib.HTTPConnection', create=True,
                                       new=fake_server.HTTPConnectionMock500)
                self.httpPatch.start()
                self.new_update_request('ports',
                                        data,
                                        port['id']).get_response(self.api)
                self.httpPatch.stop()
                uport = self._get_ports(n['network']['id'])[0]
                # name should have stayed the same
                self.assertEqual(port['name'], uport['name'])

    def test_rollback_for_port_delete(self):
        with self.network() as n:
            with self.port(network_id=n['network']['id'],
                           device_id='somedevid') as port:
                self.httpPatch = patch('httplib.HTTPConnection', create=True,
                                       new=fake_server.HTTPConnectionMock500)
                self.httpPatch.start()
                self._delete('ports', port['port']['id'],
                             expected_code=
                             webob.exc.HTTPInternalServerError.code)
                self.httpPatch.stop()
                port = self._get_ports(n['network']['id'])[0]
                self.assertEqual('ACTIVE', port['status'])

    def test_correct_shared_net_tenant_id(self):
        # tenant_id in port requests should match network tenant_id instead
        # of port tenant_id
        def rest_port_op(self, ten_id, netid, port):
            if ten_id != 'SHARED':
                raise Exception('expecting tenant_id SHARED. got %s' % ten_id)
        with self.network(tenant_id='SHARED', shared=True) as net:
            with self.subnet(network=net) as sub:
                pref = 'neutron.plugins.bigswitch.servermanager.ServerPool.%s'
                tomock = [pref % 'rest_create_port',
                          pref % 'rest_update_port',
                          pref % 'rest_delete_port']
                patches = [patch(f, create=True, new=rest_port_op)
                           for f in tomock]
                for restp in patches:
                    restp.start()
                with self.port(subnet=sub, tenant_id='port-owner') as port:
                    data = {'port': {'binding:host_id': 'someotherhost',
                            'device_id': 'override_dev'}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(res.status_int, 200)


class TestBigSwitchProxyPortsV2IVS(test_plugin.TestPortsV2,
                                   BigSwitchProxyPluginV2TestCase,
                                   test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_IVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestBigSwitchProxyPortsV2IVS,
              self).setUp()
        cfg.CONF.set_override('vif_type', 'ivs', 'NOVA')


class TestNoHostIDVIFOverride(test_plugin.TestPortsV2,
                              BigSwitchProxyPluginV2TestCase,
                              test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestNoHostIDVIFOverride, self).setUp()
        cfg.CONF.set_override('vif_type', 'ovs', 'NOVA')

    def test_port_vif_details(self):
        kwargs = {'name': 'name', 'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_OVS)


class TestBigSwitchVIFOverride(test_plugin.TestPortsV2,
                               BigSwitchProxyPluginV2TestCase,
                               test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestBigSwitchVIFOverride,
              self).setUp()
        cfg.CONF.set_override('vif_type', 'ovs', 'NOVA')

    def test_port_vif_details(self):
        kwargs = {'name': 'name', 'binding:host_id': 'ivshost',
                  'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_IVS)
        kwargs = {'name': 'name2', 'binding:host_id': 'someotherhost',
                  'device_id': 'other_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'], self.VIF_TYPE)

    def test_port_move(self):
        kwargs = {'name': 'name', 'binding:host_id': 'ivshost',
                  'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            data = {'port': {'binding:host_id': 'someotherhost',
                             'device_id': 'override_dev'}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['port']['binding:vif_type'], self.VIF_TYPE)

    def _make_port(self, fmt, net_id, expected_res_status=None, arg_list=None,
                   **kwargs):
        arg_list = arg_list or ()
        arg_list += ('binding:host_id', )
        res = self._create_port(fmt, net_id, expected_res_status,
                                arg_list, **kwargs)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)


class TestBigSwitchProxyNetworksV2(test_plugin.TestNetworksV2,
                                   BigSwitchProxyPluginV2TestCase):

    def _get_networks(self, tenant_id):
        ctx = context.Context('', tenant_id)
        return NeutronManager.get_plugin().get_networks(ctx)

    def test_rollback_on_network_create(self):
        tid = test_api_v2._uuid()
        kwargs = {'tenant_id': tid}
        self.httpPatch = patch('httplib.HTTPConnection', create=True,
                               new=fake_server.HTTPConnectionMock500)
        self.httpPatch.start()
        self._create_network('json', 'netname', True, **kwargs)
        self.httpPatch.stop()
        self.assertFalse(self._get_networks(tid))

    def test_rollback_on_network_update(self):
        with self.network() as n:
            data = {'network': {'name': 'aNewName'}}
            self.httpPatch = patch('httplib.HTTPConnection', create=True,
                                   new=fake_server.HTTPConnectionMock500)
            self.httpPatch.start()
            self.new_update_request('networks', data,
                                    n['network']['id']).get_response(self.api)
            self.httpPatch.stop()
            updatedn = self._get_networks(n['network']['tenant_id'])[0]
            # name should have stayed the same due to failure
            self.assertEqual(n['network']['name'], updatedn['name'])

    def test_rollback_on_network_delete(self):
        with self.network() as n:
            self.httpPatch = patch('httplib.HTTPConnection', create=True,
                                   new=fake_server.HTTPConnectionMock500)
            self.httpPatch.start()
            self._delete('networks', n['network']['id'],
                         expected_code=webob.exc.HTTPInternalServerError.code)
            self.httpPatch.stop()
            # network should still exist in db
            self.assertEqual(n['network']['id'],
                             self._get_networks(n['network']['tenant_id']
                                                )[0]['id'])


class TestBigSwitchProxySubnetsV2(test_plugin.TestSubnetsV2,
                                  BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxySync(BigSwitchProxyPluginV2TestCase):

    def test_send_data(self):
        plugin_obj = NeutronManager.get_plugin()
        result = plugin_obj._send_all_data()
        self.assertEqual(result[0], 200)
