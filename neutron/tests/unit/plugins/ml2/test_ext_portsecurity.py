# Copyright (c) 2015 OpenStack Foundation.
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

from neutron import context
from neutron.extensions import portsecurity as psec
from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests.unit.extensions import test_portsecurity as test_psec
from neutron.tests.unit.plugins.ml2 import test_plugin


class PSExtDriverTestCase(test_plugin.Ml2PluginV2TestCase,
                          test_psec.TestPortSecurity):
    _extension_drivers = ['port_security']

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(PSExtDriverTestCase, self).setUp()

    def test_create_net_port_security_default(self):
        _core_plugin = manager.NeutronManager.get_plugin()
        admin_ctx = context.get_admin_context()
        args = {'network':
                {'name': 'test',
                 'tenant_id': '',
                 'shared': False,
                 'admin_state_up': True,
                 'status': 'ACTIVE'}}
        try:
            network = _core_plugin.create_network(admin_ctx, args)
            _value = network[psec.PORTSECURITY]
        finally:
            if network:
                _core_plugin.delete_network(admin_ctx, network['id'])
        self.assertEqual(psec.DEFAULT_PORT_SECURITY, _value)

    def test_create_port_with_secgroup_none_and_port_security_false(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        arg_list=('security_groups',
                                                  'port_security_enabled'),
                                        security_groups=[],
                                        port_security_enabled=False)
                self.assertEqual(201, res.status_int)
                port = self.deserialize('json', res)
                self.assertFalse(port['port'][psec.PORTSECURITY])
                self.assertEqual([], port['port']['security_groups'])
