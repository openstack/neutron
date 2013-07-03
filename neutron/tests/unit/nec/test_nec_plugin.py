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

from neutron.common import topics
from neutron import context as q_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec import nec_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


PLUGIN_NAME = 'neutron.plugins.nec.nec_plugin.NECPluginV2'
OFC_MANAGER = 'neutron.plugins.nec.nec_plugin.ofc_manager.OFCManager'
OFC_DRIVER = 'neutron.tests.unit.nec.stub_ofc_driver.StubOFCDriver'


class NecPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME
    PACKET_FILTER_ENABLE = False

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        ofc_manager_cls = mock.patch(OFC_MANAGER).start()
        ofc_driver = ofc_manager_cls.return_value.driver
        ofc_driver.filter_supported.return_value = self.PACKET_FILTER_ENABLE
        super(NecPluginV2TestCase, self).setUp(self._plugin_name)
        self.context = q_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()


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
        super(TestNecPortsV2Callback, self).setUp()
        self.callbacks = nec_plugin.NECPluginV2RPCCallbacks(self.plugin)

        self.ofc = self.plugin.ofc
        self.ofc_port_exists = False
        self._setup_side_effects()

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

    def _get_portinfo(self, port_id):
        return ndb.get_portinfo(self.context.session, port_id)

    def test_portinfo_create(self):
        with self.port() as port:
            port_id = port['port']['id']
            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'DOWN')
            self.assertEqual(self.ofc.create_ofc_port.call_count, 0)
            self.assertIsNone(self._get_portinfo(port_id))

            portinfo = {'id': port_id, 'port_no': 123}
            self._rpcapi_update_ports(added=[portinfo])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertIsNotNone(self._get_portinfo(port_id))

            expected = [
                mock.call.exists_ofc_port(mock.ANY, port_id),
                mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
            ]
            self.ofc.assert_has_calls(expected)

    def test_portinfo_delete_before_port_deletion(self):
        self._test_portinfo_delete()

    def test_portinfo_delete_after_port_deletion(self):
        self._test_portinfo_delete(portinfo_delete_first=False)

    def _test_portinfo_delete(self, portinfo_delete_first=True):
        with self.port() as port:
            port_id = port['port']['id']
            portinfo = {'id': port_id, 'port_no': 456}
            self.assertEqual(self.ofc.create_ofc_port.call_count, 0)
            self.assertIsNone(self._get_portinfo(port_id))

            self._rpcapi_update_ports(added=[portinfo])
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertIsNotNone(self._get_portinfo(port_id))

            # Before port-deletion, switch port removed message is sent.
            if portinfo_delete_first:
                self._rpcapi_update_ports(removed=[port_id])
                self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
                self.assertIsNone(self._get_portinfo(port_id))

        # The port is expected to delete when exiting with-clause.
        if not portinfo_delete_first:
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
            self.assertIsNotNone(self._get_portinfo(port_id))
            self._rpcapi_update_ports(removed=[port_id])

        # Ensure port deletion is called once.
        self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
        self.assertIsNone(self._get_portinfo(port_id))

        expected = [
            mock.call.exists_ofc_port(mock.ANY, port_id),
            mock.call.create_ofc_port(mock.ANY, port_id, mock.ANY),
            mock.call.exists_ofc_port(mock.ANY, port_id),
            mock.call.delete_ofc_port(mock.ANY, port_id, mock.ANY),
        ]
        self.ofc.assert_has_calls(expected)

    def test_portinfo_added_unknown_port(self):
        portinfo = {'id': 'dummy-p1', 'port_no': 123}
        self._rpcapi_update_ports(added=[portinfo])
        self.assertIsNotNone(ndb.get_portinfo(self.context.session,
                                              'dummy-p1'))
        self.assertEqual(self.ofc.exists_ofc_port.call_count, 0)
        self.assertEqual(self.ofc.create_ofc_port.call_count, 0)

    def _test_portinfo_change(self, portinfo_change_first=True):
        with self.port() as port:
            port_id = port['port']['id']
            self.assertEqual(self.ofc.create_ofc_port.call_count, 0)

            portinfo = {'id': port_id, 'port_no': 123}
            self._rpcapi_update_ports(added=[portinfo])
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertEqual(ndb.get_portinfo(self.context.session,
                                              port_id).port_no, 123)

            if portinfo_change_first:
                portinfo = {'id': port_id, 'port_no': 456}
                self._rpcapi_update_ports(added=[portinfo])
                # OFC port is recreated.
                self.assertEqual(self.ofc.create_ofc_port.call_count, 2)
                self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
                self.assertEqual(ndb.get_portinfo(self.context.session,
                                                  port_id).port_no, 456)

        if not portinfo_change_first:
            # The port is expected to delete when exiting with-clause.
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)

            portinfo = {'id': port_id, 'port_no': 456}
            self._rpcapi_update_ports(added=[portinfo])
            # No OFC operations are expected.
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
            self.assertEqual(ndb.get_portinfo(self.context.session,
                                              port_id).port_no, 456)

    def test_portinfo_change(self):
        self._test_portinfo_change()

    def test_portinfo_change_for_nonexisting_port(self):
        self._test_portinfo_change(portinfo_change_first=False)

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


class TestNecPluginDbTest(NecPluginV2TestCase):

    def test_update_resource(self):
        with self.network() as network:
            self.assertEqual("ACTIVE", network['network']['status'])
            net_id = network['network']['id']
            for status in ["DOWN", "BUILD", "ERROR", "ACTIVE"]:
                self.plugin._update_resource_status(
                    self.context, 'network', net_id,
                    getattr(nec_plugin.OperationalStatus, status))
                n = self.plugin._get_network(self.context, net_id)
                self.assertEqual(status, n.status)


class TestNecPluginOfcManager(NecPluginV2TestCase):
    def setUp(self):
        super(TestNecPluginOfcManager, self).setUp()
        self.ofc = self.plugin.ofc

    def _create_resource(self, resource, data):
        collection = resource + 's'
        data = {resource: data}
        req = self.new_create_request(collection, data)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        return res[resource]

    def _update_resource(self, resource, id, data):
        collection = resource + 's'
        data = {resource: data}
        req = self.new_update_request(collection, data, id)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        return res[resource]

    def _show_resource(self, resource, id):
        collection = resource + 's'
        req = self.new_show_request(collection, id)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        return res[resource]

    def _list_resource(self, resource):
        collection = resource + 's'
        req = self.new_list_request(collection)
        res = req.get_response(self.api)
        return res[collection]

    def _delete_resource(self, resource, id):
        collection = resource + 's'
        req = self.new_delete_request(collection, id)
        res = req.get_response(self.api)
        return res.status_int

    def test_create_network(self):
        self.ofc.exists_ofc_tenant.return_value = False
        net = None
        ctx = mock.ANY
        with self.network() as network:
            net = network['network']
            self.assertEqual(network['network']['status'], 'ACTIVE')

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_network_with_admin_state_down(self):
        self.ofc.exists_ofc_tenant.return_value = False
        net = None
        ctx = mock.ANY
        with self.network(admin_state_up=False) as network:
            net = network['network']

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_two_network(self):
        self.ofc.exists_ofc_tenant.side_effect = [False, True]
        nets = []
        ctx = mock.ANY
        with self.network() as net1:
            nets.append(net1['network'])
            self.assertEqual(net1['network']['status'], 'ACTIVE')
            with self.network() as net2:
                nets.append(net2['network'])
                self.assertEqual(net2['network']['status'], 'ACTIVE')

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, nets[0]['id'],
                                         nets[0]['name']),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, nets[1]['id'],
                                         nets[1]['name']),
            mock.call.delete_ofc_network(ctx, nets[1]['id'], mock.ANY),
            mock.call.delete_ofc_network(ctx, nets[0]['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_network_fail(self):
        self.ofc.exists_ofc_tenant.return_value = False
        self.ofc.create_ofc_network.side_effect = nexc.OFCException(
            reason='hoge')

        net = None
        ctx = mock.ANY
        with self.network() as network:
            net = network['network']

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_update_network(self):
        self.ofc.exists_ofc_tenant.return_value = False

        net = None
        ctx = mock.ANY
        with self.network() as network:
            net = network['network']
            self.assertEqual(network['network']['status'], 'ACTIVE')

            # Set admin_state_up to False
            res = self._update_resource('network', net['id'],
                                        {'admin_state_up': False})
            self.assertFalse(res['admin_state_up'])

            # Set admin_state_up to True
            res = self._update_resource('network', net['id'],
                                        {'admin_state_up': True})
            self.assertTrue(res['admin_state_up'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def _rpcapi_update_ports(self, agent_id='nec-q-agent.fake',
                             datapath_id="0xabc", added=[], removed=[]):
        kwargs = {'topic': topics.AGENT,
                  'agent_id': agent_id,
                  'datapath_id': datapath_id,
                  'port_added': added, 'port_removed': removed}
        self.plugin.callback_nec.update_ports(self.context, **kwargs)

    def test_create_port_no_ofc_creation(self):
        self.ofc.exists_ofc_tenant.return_value = False
        self.ofc.exists_ofc_port.return_value = False

        net = None
        p1 = None
        ctx = mock.ANY
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                p1 = port['port']
                net_id = port['port']['network_id']
                net = self._show_resource('network', net_id)
                self.assertEqual(net['status'], 'ACTIVE')
                self.assertEqual(p1['status'], 'ACTIVE')

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_port_with_ofc_creation(self):
        self.ofc.exists_ofc_tenant.return_value = False
        self.ofc.exists_ofc_port.side_effect = [False, True]

        net = None
        p1 = None
        ctx = mock.ANY
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                p1 = port['port']
                net_id = port['port']['network_id']
                net = self._show_resource('network', net_id)
                self.assertEqual(net['status'], 'ACTIVE')
                self.assertEqual(p1['status'], 'ACTIVE')

                # Check the port is not created on OFC
                self.assertFalse(self.ofc.create_ofc_port.call_count)

                # Register portinfo, then the port is created on OFC
                portinfo = {'id': p1['id'], 'port_no': 123}
                self._rpcapi_update_ports(added=[portinfo])
                self.assertEqual(self.ofc.create_ofc_port.call_count, 1)

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.create_ofc_port(ctx, p1['id'], mock.ANY),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.delete_ofc_port(ctx, p1['id'], mock.ANY),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_delete_network_with_dhcp_port(self):
        self.ofc.exists_ofc_tenant.return_value = False
        self.ofc.exists_ofc_port.side_effect = [False, True]

        ctx = mock.ANY
        with self.network() as network:
            with self.subnet(network=network):
                net = network['network']
                p = self._create_resource('port',
                                          {'network_id': net['id'],
                                           'tenant_id': net['tenant_id'],
                                           'device_owner': 'network:dhcp',
                                           'device_id': 'dhcp-port1'})
                # Make sure that the port is created on OFC.
                portinfo = {'id': p['id'], 'port_no': 123}
                self._rpcapi_update_ports(added=[portinfo])
                # In a case of dhcp port, the port is deleted automatically
                # when delete_network.

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id,
                                         net['id'], net['name']),
            mock.call.exists_ofc_port(ctx, p['id']),
            mock.call.create_ofc_port(ctx, p['id'], mock.ANY),
            mock.call.exists_ofc_port(ctx, p['id']),
            mock.call.delete_ofc_port(ctx, p['id'], mock.ANY),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_update_port(self):
        self._test_update_port_with_admin_state(resource='port')

    def test_update_network_with_ofc_port(self):
        self._test_update_port_with_admin_state(resource='network')

    def _test_update_port_with_admin_state(self, resource='port'):
        self.ofc.exists_ofc_tenant.return_value = False
        self.ofc.exists_ofc_port.side_effect = [False, True, False]

        net = None
        p1 = None
        ctx = mock.ANY

        if resource == 'network':
            net_ini_admin_state = False
            port_ini_admin_state = True
        else:
            net_ini_admin_state = True
            port_ini_admin_state = False

        with self.network(admin_state_up=net_ini_admin_state) as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet,
                               admin_state_up=port_ini_admin_state) as port:
                    p1 = port['port']
                    net_id = port['port']['network_id']
                    res_id = net_id if resource == 'network' else p1['id']

                    net = self._show_resource('network', net_id)

                    # Check the port is not created on OFC
                    self.assertFalse(self.ofc.create_ofc_port.call_count)

                    # Register portinfo, then the port is created on OFC
                    portinfo = {'id': p1['id'], 'port_no': 123}
                    self._rpcapi_update_ports(added=[portinfo])
                    self.assertFalse(self.ofc.create_ofc_port.call_count)

                    self._update_resource(resource, res_id,
                                          {'admin_state_up': True})
                    self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
                    self.assertFalse(self.ofc.delete_ofc_port.call_count)

                    self._update_resource(resource, res_id,
                                          {'admin_state_up': False})
                    self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.create_ofc_port(ctx, p1['id'], mock.ANY),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.delete_ofc_port(ctx, p1['id'], mock.ANY),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)
