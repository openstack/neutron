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

import contextlib
import mock
from oslo_config import cfg
import webob.exc

from neutron.common import constants
from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.bigswitch import fake_server
from neutron.tests.unit.bigswitch import test_base
from neutron.tests.unit import test_api_v2
import neutron.tests.unit.test_db_plugin as test_plugin
import neutron.tests.unit.test_extension_allowedaddresspairs as test_addr_pair

patch = mock.patch
HTTPCON = 'neutron.plugins.bigswitch.servermanager.httplib.HTTPConnection'


class BigSwitchProxyPluginV2TestCase(test_base.BigSwitchTestBase,
                                     test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, plugin_name=None):
        if hasattr(self, 'HAS_PORT_FILTER'):
            cfg.CONF.set_override(
                'enable_security_group', self.HAS_PORT_FILTER, 'SECURITYGROUP')
        self.setup_config_files()
        self.setup_patches()
        if plugin_name:
            self._plugin_name = plugin_name
        service_plugins = {'L3_ROUTER_NAT': self._l3_plugin_name}
        super(BigSwitchProxyPluginV2TestCase,
              self).setUp(self._plugin_name, service_plugins=service_plugins)
        self.setup_db()
        self.port_create_status = 'BUILD'
        self.startHttpPatch()


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

    def setUp(self, plugin_name=None):
        super(TestBigSwitchProxyPortsV2,
              self).setUp(self._plugin_name)

    def test_get_ports_no_id(self):
        with self.port(name='test'):
            ports = manager.NeutronManager.get_plugin().get_ports(
                context.get_admin_context(), fields=['name'])
            self.assertEqual(['name'], ports[0].keys())

    def test_router_port_status_active(self):
        # router ports screw up port auto-deletion so it has to be
        # disabled for this test
        with self.network() as net:
            with self.subnet(network=net) as sub:
                with self.port(
                    subnet=sub,
                    do_delete=False,
                    device_owner=constants.DEVICE_OWNER_ROUTER_INTF
                ) as port:
                    # router ports should be immediately active
                    self.assertEqual(port['port']['status'], 'ACTIVE')

    def test_update_port_status_build(self):
        # normal ports go into the pending build state for async creation
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'BUILD')
            self.assertEqual(self.port_create_status, 'BUILD')

    def _get_ports(self, netid):
        return self.deserialize('json',
                                self._list_ports('json', netid=netid))['ports']

    def test_rollback_for_port_create(self):
        plugin = manager.NeutronManager.get_plugin()
        with self.subnet() as s:
            # stop normal patch
            self.httpPatch.stop()
            # allow thread spawns for this test
            self.spawn_p.stop()
            kwargs = {'device_id': 'somedevid'}
            # put in a broken 'server'
            httpPatch = patch(HTTPCON, new=fake_server.HTTPConnectionMock500)
            httpPatch.start()
            with self.port(subnet=s, **kwargs):
                # wait for async port create request to finish
                plugin.evpool.waitall()
                # put good 'server' back in
                httpPatch.stop()
                self.httpPatch.start()
                ports = self._get_ports(s['subnet']['network_id'])
                #failure to create should result in port in error state
                self.assertEqual(ports[0]['status'], 'ERROR')

    def test_rollback_for_port_update(self):
        with self.network() as n:
            with self.port(network_id=n['network']['id'],
                           device_id='66') as port:
                port = self._get_ports(n['network']['id'])[0]
                data = {'port': {'name': 'aNewName', 'device_id': '99'}}
                # stop normal patch
                self.httpPatch.stop()
                with patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                    self.new_update_request(
                        'ports', data, port['id']).get_response(self.api)
                self.httpPatch.start()
                uport = self._get_ports(n['network']['id'])[0]
                # name should have stayed the same
                self.assertEqual(port['name'], uport['name'])

    def test_rollback_for_port_delete(self):
        with self.network() as n:
            with self.port(network_id=n['network']['id'],
                           device_id='somedevid') as port:
                # stop normal patch
                self.httpPatch.stop()
                with patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                    self._delete(
                        'ports',
                        port['port']['id'],
                        expected_code=webob.exc.HTTPInternalServerError.code)
                self.httpPatch.start()
                port = self._get_ports(n['network']['id'])[0]
                self.assertEqual('BUILD', port['status'])

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

    def test_create404_triggers_sync(self):
        # allow async port thread for this patch
        self.spawn_p.stop()
        with contextlib.nested(
            self.subnet(),
            patch(HTTPCON, create=True,
                  new=fake_server.HTTPConnectionMock404),
            patch(test_base.RESTPROXY_PKG_PATH
                  + '.NeutronRestProxyV2._send_all_data')
        ) as (s, mock_http, mock_send_all):
            with self.port(subnet=s, device_id='somedevid') as p:
                # wait for the async port thread to finish
                plugin = manager.NeutronManager.get_plugin()
                plugin.evpool.waitall()
        call = mock.call(
            send_routers=True, send_ports=True, send_floating_ips=True,
            triggered_by_tenant=p['port']['tenant_id']
        )
        mock_send_all.assert_has_calls([call])
        self.spawn_p.start()

    def test_port_vif_details_default(self):
        kwargs = {'name': 'name', 'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_OVS)

    def test_port_vif_details_override(self):
        # ivshost is in the test config to override to IVS
        kwargs = {'name': 'name', 'binding:host_id': 'ivshost',
                  'device_id': 'override_dev',
                  'arg_list': ('binding:host_id',)}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_IVS)
        self._delete('ports', port['port']['id'])
        self._delete('networks', port['port']['network_id'])
        kwargs = {'name': 'name2', 'binding:host_id': 'someotherhost',
                  'device_id': 'other_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'], self.VIF_TYPE)

    def test_port_move(self):
        # ivshost is in the test config to override to IVS
        kwargs = {'name': 'name', 'binding:host_id': 'ivshost',
                  'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            data = {'port': {'binding:host_id': 'someotherhost',
                             'device_id': 'override_dev'}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['port']['binding:vif_type'], self.VIF_TYPE)


class TestVifDifferentDefault(BigSwitchProxyPluginV2TestCase):

    def setup_config_files(self):
        super(TestVifDifferentDefault, self).setup_config_files()
        cfg.CONF.set_override('vif_type', 'ivs', 'NOVA')

    def test_default_viftype(self):
        with self.port() as port:
            self.assertEqual(port['port']['binding:vif_type'], 'ivs')


class TestBigSwitchProxyNetworksV2(test_plugin.TestNetworksV2,
                                   BigSwitchProxyPluginV2TestCase):

    def _get_networks(self, tenant_id):
        ctx = context.Context('', tenant_id)
        return manager.NeutronManager.get_plugin().get_networks(ctx)

    def test_rollback_on_network_create(self):
        tid = test_api_v2._uuid()
        kwargs = {'tenant_id': tid}
        self.httpPatch.stop()
        with patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
            self._create_network('json', 'netname', True, **kwargs)
        self.httpPatch.start()
        self.assertFalse(self._get_networks(tid))

    def test_rollback_on_network_update(self):
        with self.network() as n:
            data = {'network': {'name': 'aNewName'}}
            self.httpPatch.stop()
            with patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                self.new_update_request(
                    'networks', data, n['network']['id']
                ).get_response(self.api)
            self.httpPatch.start()
            updatedn = self._get_networks(n['network']['tenant_id'])[0]
            # name should have stayed the same due to failure
            self.assertEqual(n['network']['name'], updatedn['name'])

    def test_rollback_on_network_delete(self):
        with self.network() as n:
            self.httpPatch.stop()
            with patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                self._delete(
                    'networks', n['network']['id'],
                    expected_code=webob.exc.HTTPInternalServerError.code)
            self.httpPatch.start()
            # network should still exist in db
            self.assertEqual(n['network']['id'],
                             self._get_networks(n['network']['tenant_id']
                                                )[0]['id'])

    def test_notify_on_security_group_change(self):
        plugin = manager.NeutronManager.get_plugin()
        with self.port() as p:
            with contextlib.nested(
                mock.patch.object(plugin, 'notifier'),
                mock.patch.object(plugin, 'is_security_group_member_updated',
                                  return_value=True)
            ) as (n_mock, s_mock):
                # any port update should trigger a notification due to s_mock
                data = {'port': {'name': 'aNewName'}}
                self.new_update_request(
                    'ports', data, p['port']['id']).get_response(self.api)
                self.assertTrue(n_mock.port_update.called)


class TestBigSwitchProxySubnetsV2(test_plugin.TestSubnetsV2,
                                  BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxySync(BigSwitchProxyPluginV2TestCase):

    def test_send_data(self):
        plugin_obj = manager.NeutronManager.get_plugin()
        result = plugin_obj._send_all_data()
        self.assertEqual(result[0], 200)


class TestBigSwitchAddressPairs(test_addr_pair.TestAllowedAddressPairs,
                                BigSwitchProxyPluginV2TestCase):
    pass
