# Copyright (c) 2012 OpenStack Foundation.
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

import mock

from quantum.common import topics
from quantum import context as q_context
from quantum.extensions import portbindings
from quantum import manager
from quantum.plugins.nec import nec_plugin
from quantum.tests.unit import _test_extension_portbindings as test_bindings
from quantum.tests.unit import test_db_plugin as test_plugin
from quantum.tests.unit import test_security_groups_rpc as test_sg_rpc


OFC_MANAGER = 'quantum.plugins.nec.nec_plugin.ofc_manager.OFCManager'
PLUGIN_NAME = 'quantum.plugins.nec.nec_plugin.NECPluginV2'


class NecPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def setUp(self):
        super(NecPluginV2TestCase, self).setUp(self._plugin_name)


class TestNecBasicGet(test_plugin.TestBasicGet, NecPluginV2TestCase):
    pass


class TestNecV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            NecPluginV2TestCase):
    pass


class TestNecPortsV2(test_plugin.TestPortsV2, NecPluginV2TestCase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True


class TestNecNetworksV2(test_plugin.TestNetworksV2, NecPluginV2TestCase):
    pass


class TestNecPortBinding(test_bindings.PortBindingsTestCase,
                         NecPluginV2TestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        super(TestNecPortBinding, self).setUp()


class TestNecPortBindingNoSG(TestNecPortBinding):
    HAS_PORT_FILTER = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestNecPortsV2Callback(NecPluginV2TestCase):

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        ofc_manager_p = mock.patch(OFC_MANAGER)
        ofc_manager_cls = ofc_manager_p.start()
        self.ofc = mock.Mock()
        ofc_manager_cls.return_value = self.ofc
        self.ofc_port_exists = False
        self._setup_side_effects()

        super(TestNecPortsV2Callback, self).setUp()
        self.context = q_context.get_admin_context()
        self.plugin = manager.QuantumManager.get_plugin()
        self.callbacks = nec_plugin.NECPluginV2RPCCallbacks(self.plugin)

    def _setup_side_effects(self):
        def _create_ofc_port_called(*args, **kwargs):
            self.ofc_port_exists = True

        def _delete_ofc_port_called(*args, **kwargs):
            self.ofc_port_exists = False

        def _exists_ofc_port_called(*args, **kwargs):
            return self.ofc_port_exists

        self.ofc.create_ofc_port.side_effect = _create_ofc_port_called
        self.ofc.delete_ofc_port.side_effect = _delete_ofc_port_called
        self.ofc.exists_ofc_port.side_effect = _exists_ofc_port_called

    def _rpcapi_update_ports(self, agent_id='nec-q-agent.fake',
                             datapath_id="0xabc", added=[], removed=[]):
        kwargs = {'topic': topics.AGENT,
                  'agent_id': agent_id,
                  'datapath_id': datapath_id,
                  'port_added': added, 'port_removed': removed}
        self.callbacks.update_ports(self.context, **kwargs)

    def test_port_create(self):
        with self.port() as port:
            port_id = port['port']['id']
            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'DOWN')

            portinfo = {'id': port_id, 'port_no': 123}
            self._rpcapi_update_ports(added=[portinfo])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')

            expected = [
                mock.call.exists_ofc_port(mock.ANY, port_id),
                mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
            ]
            self.ofc.assert_has_calls(expected)

    def test_port_delete(self):
        with self.port() as port:
            port_id = port['port']['id']
            portinfo = {'id': port_id, 'port_no': 456}
            self._rpcapi_update_ports(added=[portinfo])

        expected = [
            mock.call.exists_ofc_port(mock.ANY, port_id),
            mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
            mock.call.exists_ofc_port(mock.ANY, port_id),
            mock.call.delete_ofc_port(mock.ANY, port_id, mock.ANY),
        ]
        self.ofc.assert_has_calls(expected)

    def test_port_migration(self):
        agent_id_a, datapath_id_a, port_no_a = 'nec-q-agent.aa', '0xaaa', 10
        agent_id_b, datapath_id_b, port_no_b = 'nec-q-agent.bb', '0xbbb', 11

        with self.port() as port:
            port_id = port['port']['id']
            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'DOWN')

            portinfo_a = {'id': port_id, 'port_no': port_no_a}
            self._rpcapi_update_ports(agent_id=agent_id_a,
                                      datapath_id=datapath_id_a,
                                      added=[portinfo_a])

            portinfo_b = {'id': port_id, 'port_no': port_no_b}
            self._rpcapi_update_ports(agent_id=agent_id_b,
                                      datapath_id=datapath_id_b,
                                      added=[portinfo_b])

            self._rpcapi_update_ports(agent_id=agent_id_a,
                                      datapath_id=datapath_id_a,
                                      removed=[port_id])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')
            self.assertTrue(self.ofc_port_exists)

            expected = [
                mock.call.exists_ofc_port(mock.ANY, port_id),
                mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
                mock.call.exists_ofc_port(mock.ANY, port_id),
                mock.call.delete_ofc_port(mock.ANY, port_id, mock.ANY),
                mock.call.exists_ofc_port(mock.ANY, port_id),
                mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
            ]
            self.ofc.assert_has_calls(expected)
            self.assertEqual(2, self.ofc.create_ofc_port.call_count)
            self.assertEqual(1, self.ofc.delete_ofc_port.call_count)
