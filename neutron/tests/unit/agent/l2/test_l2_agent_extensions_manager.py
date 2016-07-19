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
from oslo_config import cfg

from neutron.agent.l2 import l2_agent_extensions_manager as l2_ext_manager
from neutron.tests import base


class TestL2AgentExtensionsManager(base.BaseTestCase):

    def setUp(self):
        super(TestL2AgentExtensionsManager, self).setUp()
        mock.patch('neutron.agent.l2.extensions.qos.QosAgentExtension',
                   autospec=True).start()
        conf = cfg.CONF
        l2_ext_manager.register_opts(conf)
        cfg.CONF.set_override('extensions', ['qos'], 'agent')
        self.manager = l2_ext_manager.L2AgentExtensionsManager(conf)

    def _get_extension(self):
        return self.manager.extensions[0].obj

    def test_initialize(self):
        connection = object()
        self.manager.initialize(connection, 'fake_driver_type')
        ext = self._get_extension()
        ext.initialize.assert_called_once_with(connection, 'fake_driver_type')

    def test_handle_port(self):
        context = object()
        data = object()
        self.manager.handle_port(context, data)
        ext = self._get_extension()
        ext.handle_port.assert_called_once_with(context, data)

    def test_delete_port(self):
        context = object()
        data = object()
        self.manager.delete_port(context, data)
        ext = self._get_extension()
        ext.delete_port.assert_called_once_with(context, data)
