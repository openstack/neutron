# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2014 Big Switch Networks, Inc.
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

from contextlib import nested
import mock
import webob.exc

from neutron.extensions import portbindings
from neutron.manager import NeutronManager
from neutron.plugins.bigswitch import servermanager
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
import neutron.tests.unit.bigswitch.test_restproxy_plugin as trp
from neutron.tests.unit.ml2.test_ml2_plugin import PLUGIN_NAME as ML2_PLUGIN
from neutron.tests.unit import test_db_plugin

PHYS_NET = 'physnet1'
VLAN_START = 1000
VLAN_END = 1100
SERVER_MANAGER = 'neutron.plugins.bigswitch.servermanager'
SERVER_POOL = SERVER_MANAGER + '.ServerPool'
DRIVER_MOD = 'neutron.plugins.ml2.drivers.mech_bigswitch.driver'
DRIVER = DRIVER_MOD + '.BigSwitchMechanismDriver'


class TestBigSwitchMechDriverBase(trp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['bigswitch'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                          [phys_vrange],
                                          'ml2_type_vlan')
        super(TestBigSwitchMechDriverBase,
              self).setUp(ML2_PLUGIN)


class TestBigSwitchMechDriverNetworksV2(test_db_plugin.TestNetworksV2,
                                        TestBigSwitchMechDriverBase):
    pass


class TestBigSwitchMechDriverPortsV2(test_db_plugin.TestPortsV2,
                                     TestBigSwitchMechDriverBase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS

    def setUp(self):
        super(TestBigSwitchMechDriverPortsV2, self).setUp()
        self.port_create_status = 'DOWN'

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')

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

    def test_create404_triggers_background_sync(self):
        # allow the async background thread to run for this test
        self.spawn_p.stop()
        with nested(
            mock.patch(SERVER_POOL + '.rest_create_port',
                       side_effect=servermanager.RemoteRestError(
                           reason=servermanager.NXNETWORK, status=404)),
            mock.patch(DRIVER + '._send_all_data'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host'})
        ) as (mock_http, mock_send_all, p):
            # wait for thread to finish
            mm = NeutronManager.get_plugin().mechanism_manager
            bigdriver = mm.mech_drivers['bigswitch'].obj
            bigdriver.evpool.waitall()
            mock_send_all.assert_has_calls([
                mock.call(
                    send_routers=False, send_ports=True,
                    send_floating_ips=False,
                    triggered_by_tenant=p['port']['tenant_id']
                )
            ])
        self.spawn_p.start()

    def test_backend_request_contents(self):
        with nested(
            mock.patch(SERVER_POOL + '.rest_create_port'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host'})
        ) as (mock_rest, p):
            # make sure basic expected keys are present in the port body
            pb = mock_rest.mock_calls[0][1][2]
            self.assertEqual('host', pb['binding:host_id'])
            self.assertIn('bound_segment', pb)
            self.assertIn('network', pb)

    def test_req_context_header_present(self):
        with nested(
            mock.patch(SERVER_MANAGER + '.ServerProxy.rest_call'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host'})
        ) as (mock_rest, p):
            headers = mock_rest.mock_calls[0][1][3]
            self.assertIn('X-REQ-CONTEXT', headers)
