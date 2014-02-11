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

import webob.exc

from neutron.extensions import portbindings
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
import neutron.tests.unit.bigswitch.test_restproxy_plugin as trp
from neutron.tests.unit.ml2.test_ml2_plugin import PLUGIN_NAME as ML2_PLUGIN
from neutron.tests.unit import test_db_plugin

PHYS_NET = 'physnet1'
VLAN_START = 1000
VLAN_END = 1100


class TestBigSwitchMechDriverBase(trp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['bigswitch'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                ml2_config.cfg.CONF.set_override(opt, val, 'ml2')
        self.addCleanup(ml2_config.cfg.CONF.reset)

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                          [phys_vrange],
                                          'ml2_type_vlan')
        self.addCleanup(vlan_config.cfg.CONF.reset)
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

    # exercise the host_id tracking code
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
