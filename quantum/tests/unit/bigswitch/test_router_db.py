# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Big Switch Networks, Inc.  All rights reserved.
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
# Adapted from quantum.tests.unit.test_l3_plugin
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com
#

import os

from mock import patch
from oslo.config import cfg
from webob import exc

from quantum.common.test_lib import test_config
from quantum.extensions import l3
from quantum.manager import QuantumManager
from quantum.openstack.common.notifier import api as notifier_api
from quantum.openstack.common.notifier import test_notifier
from quantum.tests.unit import test_l3_plugin


def new_L3_setUp(self):
    test_config['plugin_name_v2'] = (
        'quantum.plugins.bigswitch.plugin.QuantumRestProxyV2')
    etc_path = os.path.join(os.path.dirname(__file__), 'etc')
    rp_conf_file = os.path.join(etc_path, 'restproxy.ini.test')
    test_config['config_files'] = [rp_conf_file]
    cfg.CONF.set_default('allow_overlapping_ips', False)
    ext_mgr = L3TestExtensionManager()
    test_config['extension_manager'] = ext_mgr
    super(test_l3_plugin.L3NatTestCaseBase, self).setUp()

    # Set to None to reload the drivers
    notifier_api._drivers = None
    cfg.CONF.set_override("notification_driver", [test_notifier.__name__])


origSetUp = test_l3_plugin.L3NatDBTestCase.setUp


class HTTPResponseMock():
    status = 200
    reason = 'OK'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        pass

    def read(self):
        return "{'status': '200 OK'}"


class HTTPConnectionMock():

    def __init__(self, server, port, timeout):
        pass

    def request(self, action, uri, body, headers):
        return

    def getresponse(self):
        return HTTPResponseMock(None)

    def close(self):
        pass


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class RouterDBTestCase(test_l3_plugin.L3NatDBTestCase):

    def setUp(self):
        self.httpPatch = patch('httplib.HTTPConnection', create=True,
                               new=HTTPConnectionMock)
        self.httpPatch.start()
        test_l3_plugin.L3NatDBTestCase.setUp = new_L3_setUp
        super(RouterDBTestCase, self).setUp()
        self.plugin_obj = QuantumManager.get_plugin()

    def tearDown(self):
        self.httpPatch.stop()
        super(RouterDBTestCase, self).tearDown()
        del test_config['plugin_name_v2']
        del test_config['config_files']
        cfg.CONF.reset()
        test_l3_plugin.L3NatDBTestCase.setUp = origSetUp

    def test_router_remove_router_interface_wrong_subnet_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.subnet(cidr='10.0.10.0/24') as s1:
                    with self.port(subnet=s1, no_delete=True) as p:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      p['port']['id'],
                                                      exc.HTTPConflict.code)
                        #remove properly to clean-up
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])

    def test_router_remove_router_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s, no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet(cidr='10.0.10.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router():
                    res = self._create_floatingip(
                        'json',
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_router_update_gateway(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet(cidr='10.0.10.0/24') as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s2['subnet']['network_id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])

    def test_router_add_interface_overlapped_cidr(self):
        self.skipTest("Plugin does not support")

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        self.skipTest("Plugin does not support")

    def test_list_nets_external(self):
        self.skipTest("Plugin does not support")

    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet(cidr='10.0.10.0/24') as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    def test_router_remove_interface_wrong_subnet_returns_409(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.10.0/24') as s:
                with self.port(no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  exc.HTTPConflict.code)
                    #remove properly to clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_remove_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.10.0/24'):
                with self.port(no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def test_send_data(self):
        fmt = 'json'
        plugin_obj = QuantumManager.get_plugin()

        with self.router() as r:
            r_id = r['router']['id']

            with self.subnet(cidr='10.0.10.0/24') as s:
                s_id = s['subnet']['id']

                with self.router() as r1:
                    r1_id = r1['router']['id']
                    body = self._router_interface_action('add', r_id, s_id,
                                                         None)
                    self.assertTrue('port_id' in body)
                    r_port_id = body['port_id']
                    body = self._show('ports', r_port_id)
                    self.assertEqual(body['port']['device_id'], r_id)

                    with self.subnet(cidr='10.0.20.0/24') as s1:
                        s1_id = s1['subnet']['id']
                        body = self._router_interface_action('add', r1_id,
                                                             s1_id, None)
                        self.assertTrue('port_id' in body)
                        r1_port_id = body['port_id']
                        body = self._show('ports', r1_port_id)
                        self.assertEqual(body['port']['device_id'], r1_id)

                        with self.subnet(cidr='11.0.0.0/24') as public_sub:
                            public_net_id = public_sub['subnet']['network_id']
                            self._set_net_external(public_net_id)

                            with self.port() as prv_port:
                                prv_fixed_ip = prv_port['port']['fixed_ips'][0]
                                priv_sub_id = prv_fixed_ip['subnet_id']
                                self._add_external_gateway_to_router(
                                    r_id, public_net_id)
                                self._router_interface_action('add', r_id,
                                                              priv_sub_id,
                                                              None)

                                priv_port_id = prv_port['port']['id']
                                res = self._create_floatingip(
                                    fmt, public_net_id,
                                    port_id=priv_port_id)
                                self.assertEqual(res.status_int,
                                                 exc.HTTPCreated.code)
                                floatingip = self.deserialize(fmt, res)

                                result = plugin_obj._send_all_data()
                                self.assertEqual(result[0], 200)

                                self._delete('floatingips',
                                             floatingip['floatingip']['id'])
                                self._remove_external_gateway_from_router(
                                    r_id, public_net_id)
                                self._router_interface_action('remove', r_id,
                                                              priv_sub_id,
                                                              None)
                        self._router_interface_action('remove', r_id, s_id,
                                                      None)
                        self._show('ports', r_port_id,
                                   expected_code=exc.HTTPNotFound.code)
                        self._router_interface_action('remove', r1_id, s1_id,
                                                      None)
                        self._show('ports', r1_port_id,
                                   expected_code=exc.HTTPNotFound.code)
