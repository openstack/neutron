# Copyright (c) 2013 OpenStack Foundation
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

from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import config as config
from neutron.tests.unit import test_db_plugin as test_plugin


PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class PortBindingTestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'test'],
                                     'ml2')
        self.addCleanup(config.cfg.CONF.reset)
        super(PortBindingTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.plugin = manager.NeutronManager.get_plugin()

    def _check_response(self, port, vif_type, has_port_filter):
        self.assertEqual(port['binding:vif_type'], vif_type)
        port_cap = port[portbindings.CAPABILITIES]
        self.assertEqual(port_cap[portbindings.CAP_PORT_FILTER],
                         has_port_filter)

    def _test_port_binding(self, host, vif_type, has_port_filter, bound):
        host_arg = {portbindings.HOST_ID: host}
        with self.port(name='name', arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            self._check_response(port['port'], vif_type, has_port_filter)
            port_id = port['port']['id']
            details = self.plugin.callbacks.get_device_details(
                None, agent_id="theAgentId", device=port_id)
            if bound:
                self.assertEqual(details['network_type'], 'local')
            else:
                self.assertNotIn('network_type', details)

    def test_unbound(self):
        self._test_port_binding("",
                                portbindings.VIF_TYPE_UNBOUND,
                                False, False)

    def test_binding_failed(self):
        self._test_port_binding("host-fail",
                                portbindings.VIF_TYPE_BINDING_FAILED,
                                False, False)

    def test_binding_no_filter(self):
        self._test_port_binding("host-ovs-no_filter",
                                portbindings.VIF_TYPE_OVS,
                                False, True)

    def test_binding_filter(self):
        self._test_port_binding("host-bridge-filter",
                                portbindings.VIF_TYPE_BRIDGE,
                                True, True)
