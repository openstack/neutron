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
import webob.exc

from neutron.common import constants
from neutron.common import test_lib
from neutron.common import topics
from neutron import context
from neutron.db import db_base_plugin_v2
from neutron import manager
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec import nec_plugin
from neutron.tests.unit.nec import fake_ofc_manager
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_allowedaddresspairs as test_pair


PLUGIN_NAME = 'neutron.plugins.nec.nec_plugin.NECPluginV2'
OFC_MANAGER = 'neutron.plugins.nec.nec_plugin.ofc_manager.OFCManager'
NOTIFIER = 'neutron.plugins.nec.nec_plugin.NECPluginV2AgentNotifierApi'
NEC_PLUGIN_INI = """
[DEFAULT]
api_extensions_path = neutron/plugins/nec/extensions
[OFC]
driver = neutron.tests.unit.nec.stub_ofc_driver.StubOFCDriver
enable_packet_filter = False
"""


class NecPluginV2TestCaseBase(object):
    _nec_ini = NEC_PLUGIN_INI

    def _set_nec_ini(self):
        self.nec_ini_file = self.get_temp_file_path('nec.ini')
        with open(self.nec_ini_file, 'w') as f:
            f.write(self._nec_ini)
        if 'config_files' in test_lib.test_config.keys():
            for c in test_lib.test_config['config_files']:
                if c.rfind("/nec.ini") > -1:
                    test_lib.test_config['config_files'].remove(c)
            test_lib.test_config['config_files'].append(self.nec_ini_file)
        else:
            test_lib.test_config['config_files'] = [self.nec_ini_file]
        self.addCleanup(self._clean_nec_ini)

    def _clean_nec_ini(self):
        test_lib.test_config['config_files'].remove(self.nec_ini_file)
        self.nec_ini_file = None

    def patch_remote_calls(self):
        self.plugin_notifier_p = mock.patch(NOTIFIER)
        self.ofc_manager_p = mock.patch(OFC_MANAGER)
        self.plugin_notifier_p.start()
        self.ofc_manager_p.start()

    def setup_nec_plugin_base(self):
        self._set_nec_ini()
        self.patch_remote_calls()


class NecPluginV2TestCase(NecPluginV2TestCaseBase,
                          test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def rpcapi_update_ports(self, agent_id='nec-q-agent.fake',
                            datapath_id="0xabc", added=[], removed=[]):
        kwargs = {'topic': topics.AGENT,
                  'agent_id': agent_id,
                  'datapath_id': datapath_id,
                  'port_added': added, 'port_removed': removed}
        self.callback_nec.update_ports(self.context, **kwargs)

    def setUp(self, plugin=None, ext_mgr=None):

        self._set_nec_ini()
        plugin = plugin or self._plugin_name
        super(NecPluginV2TestCase, self).setUp(plugin, ext_mgr=ext_mgr)

        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.ofc = fake_ofc_manager.patch_ofc_manager()
        self.ofc = self.plugin.ofc
        self.callback_nec = nec_plugin.NECPluginV2RPCCallbacks(self.plugin)
        self.context = context.get_admin_context()
        self.net_create_status = 'ACTIVE'
        self.port_create_status = 'DOWN'


class TestNecBasicGet(test_plugin.TestBasicGet, NecPluginV2TestCase):
    pass


class TestNecV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            NecPluginV2TestCase):
    pass


class TestNecNetworksV2(test_plugin.TestNetworksV2, NecPluginV2TestCase):
    pass


class TestNecPortsV2Callback(NecPluginV2TestCase):

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
            self.rpcapi_update_ports(added=[portinfo])

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

            self.rpcapi_update_ports(added=[portinfo])
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertIsNotNone(self._get_portinfo(port_id))

            # Before port-deletion, switch port removed message is sent.
            if portinfo_delete_first:
                self.rpcapi_update_ports(removed=[port_id])
                self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
                self.assertIsNone(self._get_portinfo(port_id))
        self._delete('ports', port['port']['id'])

        # The port and portinfo is expected to delete when exiting with-clause.
        self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
        self.assertIsNone(self._get_portinfo(port_id))
        if not portinfo_delete_first:
            self.rpcapi_update_ports(removed=[port_id])

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
        self.rpcapi_update_ports(added=[portinfo])
        self.assertIsNone(ndb.get_portinfo(self.context.session,
                                           'dummy-p1'))
        self.assertEqual(self.ofc.exists_ofc_port.call_count, 0)
        self.assertEqual(self.ofc.create_ofc_port.call_count, 0)

    def _test_portinfo_change(self, portinfo_change_first=True):
        with self.port() as port:
            port_id = port['port']['id']
            self.assertEqual(self.ofc.create_ofc_port.call_count, 0)

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertEqual(ndb.get_portinfo(self.context.session,
                                              port_id).port_no, 123)

            if portinfo_change_first:
                portinfo = {'id': port_id, 'port_no': 456}
                self.rpcapi_update_ports(added=[portinfo])
                # OFC port is recreated.
                self.assertEqual(self.ofc.create_ofc_port.call_count, 2)
                self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
                self.assertEqual(ndb.get_portinfo(self.context.session,
                                                  port_id).port_no, 456)
        self._delete('ports', port['port']['id'])

        if not portinfo_change_first:
            # The port is expected to delete when exiting with-clause.
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)

            portinfo = {'id': port_id, 'port_no': 456}
            self.rpcapi_update_ports(added=[portinfo])
            # No OFC operations are expected.
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
            self.assertIsNone(ndb.get_portinfo(self.context.session, port_id))

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
            self.rpcapi_update_ports(agent_id=agent_id_a,
                                     datapath_id=datapath_id_a,
                                     added=[portinfo_a])

            portinfo_b = {'id': port_id, 'port_no': port_no_b}
            self.rpcapi_update_ports(agent_id=agent_id_b,
                                     datapath_id=datapath_id_b,
                                     added=[portinfo_b])

            self.rpcapi_update_ports(agent_id=agent_id_a,
                                     datapath_id=datapath_id_a,
                                     removed=[port_id])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')
            self.assertTrue(self.ofc.ofc_ports[port_id])

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

    def test_portinfo_readd(self):
        with self.port() as port:
            port_id = port['port']['id']
            self.plugin.get_port(self.context, port_id)

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertIsNotNone(self._get_portinfo(port_id))

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            sport = self.plugin.get_port(self.context, port_id)
            self.assertEqual(sport['status'], 'ACTIVE')
            self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_port.call_count, 0)
            self.assertIsNotNone(self._get_portinfo(port_id))


class TestNecPluginDbTest(NecPluginV2TestCase):

    def test_update_resource(self):
        with self.network() as network:
            self.assertEqual("ACTIVE", network['network']['status'])
            net_id = network['network']['id']
            for status in ["DOWN", "BUILD", "ERROR", "ACTIVE"]:
                self.plugin._update_resource_status(
                    self.context, 'network', net_id,
                    getattr(constants, 'NET_STATUS_%s' % status))
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
        net = None
        ctx = mock.ANY
        with self.network() as network:
            net = network['network']
            self.assertEqual(network['network']['status'], 'ACTIVE')
        self._delete('networks', network['network']['id'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_network_with_admin_state_down(self):
        net = None
        ctx = mock.ANY
        with self.network(admin_state_up=False) as network:
            net = network['network']
            self.assertEqual(network['network']['status'], 'DOWN')
        self._delete('networks', network['network']['id'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_two_network(self):
        nets = []
        ctx = mock.ANY
        with self.network() as net1:
            nets.append(net1['network'])
            self.assertEqual(net1['network']['status'], 'ACTIVE')
            with self.network() as net2:
                nets.append(net2['network'])
                self.assertEqual(net2['network']['status'], 'ACTIVE')
        self._delete('networks', net2['network']['id'])
        self._delete('networks', net1['network']['id'])
        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, nets[0]['id'],
                                         nets[0]['name']),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, nets[1]['id'],
                                         nets[1]['name']),
            mock.call.exists_ofc_network(ctx, nets[1]['id']),
            mock.call.delete_ofc_network(ctx, nets[1]['id'], mock.ANY),
            mock.call.exists_ofc_network(ctx, nets[0]['id']),
            mock.call.delete_ofc_network(ctx, nets[0]['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_network_fail(self):
        self.ofc.create_ofc_network.side_effect = nexc.OFCException(
            reason='hoge')

        net = None
        ctx = mock.ANY
        # NOTE: We don't delete network through api, but db will be cleaned in
        # tearDown(). When OFCManager has failed to create a network on OFC,
        # it does not keeps ofc_network entry and will fail to delete this
        # network from OFC. Deletion of network is not the scope of this test.
        with self.network() as network:
            net = network['network']
            self.assertEqual(net['status'], 'ERROR')
            net_ref = self._show('networks', net['id'])
            self.assertEqual(net_ref['network']['status'], 'ERROR')

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name'])
        ]
        self.ofc.assert_has_calls(expected)

    def test_update_network(self):
        net = None
        ctx = mock.ANY
        with self.network() as network:
            net = network['network']
            self.assertEqual(network['network']['status'], 'ACTIVE')

            net_ref = self._show('networks', net['id'])
            self.assertEqual(net_ref['network']['status'], 'ACTIVE')

            # Set admin_state_up to False
            res = self._update_resource('network', net['id'],
                                        {'admin_state_up': False})
            self.assertFalse(res['admin_state_up'])
            self.assertEqual(res['status'], 'DOWN')

            net_ref = self._show('networks', net['id'])
            self.assertEqual(net_ref['network']['status'], 'DOWN')

            # Set admin_state_up to True
            res = self._update_resource('network', net['id'],
                                        {'admin_state_up': True})
            self.assertTrue(res['admin_state_up'])
            self.assertEqual(res['status'], 'ACTIVE')

            net_ref = self._show('networks', net['id'])
            self.assertEqual(net_ref['network']['status'], 'ACTIVE')
        self._delete('networks', network['network']['id'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_port_no_ofc_creation(self):
        net = None
        p1 = None
        ctx = mock.ANY
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                p1 = port['port']
                net_id = port['port']['network_id']
                net = self._show_resource('network', net_id)
                self.assertEqual(net['status'], 'ACTIVE')
                self.assertEqual(p1['status'], 'DOWN')

                p1_ref = self._show('ports', p1['id'])
                self.assertEqual(p1_ref['port']['status'], 'DOWN')
        self._delete('ports', port['port']['id'])
        self._delete('networks', port['port']['network_id'])
        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_create_port_with_ofc_creation(self):
        net = None
        p1 = None
        ctx = mock.ANY
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                p1 = port['port']
                net_id = port['port']['network_id']
                net = self._show_resource('network', net_id)
                self.assertEqual(net['status'], 'ACTIVE')
                self.assertEqual(p1['status'], 'DOWN')

                p1_ref = self._show('ports', p1['id'])
                self.assertEqual(p1_ref['port']['status'], 'DOWN')

                # Check the port is not created on OFC
                self.assertFalse(self.ofc.create_ofc_port.call_count)

                # Register portinfo, then the port is created on OFC
                portinfo = {'id': p1['id'], 'port_no': 123}
                self.rpcapi_update_ports(added=[portinfo])
                self.assertEqual(self.ofc.create_ofc_port.call_count, 1)

                p1_ref = self._show('ports', p1['id'])
                self.assertEqual(p1_ref['port']['status'], 'ACTIVE')
        self._delete('ports', port['port']['id'])
        self._delete('networks', port['port']['network_id'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id, net['id'],
                                         net['name']),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.create_ofc_port(ctx, p1['id'], mock.ANY),

            mock.call.exists_ofc_port(ctx, p1['id']),
            mock.call.delete_ofc_port(ctx, p1['id'], mock.ANY),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_delete_network_with_dhcp_port(self):
        ctx = mock.ANY
        with self.network() as network:
            with self.subnet(network=network):
                net = network['network']
                p = self._create_resource(
                    'port',
                    {'network_id': net['id'],
                     'tenant_id': net['tenant_id'],
                     'device_owner': constants.DEVICE_OWNER_DHCP,
                     'device_id': 'dhcp-port1'})
                # Make sure that the port is created on OFC.
                portinfo = {'id': p['id'], 'port_no': 123}
                self.rpcapi_update_ports(added=[portinfo])
                # In a case of dhcp port, the port is deleted automatically
                # when delete_network.
        self._delete('networks', network['network']['id'])

        expected = [
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_tenant(ctx, self._tenant_id),
            mock.call.create_ofc_network(ctx, self._tenant_id,
                                         net['id'], net['name']),
            mock.call.exists_ofc_port(ctx, p['id']),
            mock.call.create_ofc_port(ctx, p['id'], mock.ANY),
            mock.call.exists_ofc_port(ctx, p['id']),
            mock.call.delete_ofc_port(ctx, p['id'], mock.ANY),
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_delete_network_with_error_status(self):
        self.ofc.set_raise_exc('create_ofc_network',
                               nexc.OFCException(reason='fake error'))

        with self.network() as net:
            net_id = net['network']['id']
            net_ref = self._show('networks', net_id)
            self.assertEqual(net_ref['network']['status'], 'ERROR')
        self._delete('networks', net['network']['id'])
        ctx = mock.ANY
        tenant_id = self._tenant_id
        net_name = mock.ANY
        net = mock.ANY
        expected = [
            mock.call.exists_ofc_tenant(ctx, tenant_id),
            mock.call.create_ofc_tenant(ctx, tenant_id),
            mock.call.create_ofc_network(ctx, tenant_id, net_id, net_name),
            mock.call.exists_ofc_network(ctx, net_id),
            mock.call.exists_ofc_tenant(ctx, tenant_id),
            mock.call.delete_ofc_tenant(ctx, tenant_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertFalse(self.ofc.delete_ofc_network.call_count)

    def test_delete_network_with_ofc_deletion_failure(self):
        self.ofc.set_raise_exc('delete_ofc_network',
                               nexc.OFCException(reason='hoge'))

        with self.network() as net:
            net_id = net['network']['id']

            self._delete('networks', net_id,
                         expected_code=webob.exc.HTTPInternalServerError.code)

            net_ref = self._show('networks', net_id)
            self.assertEqual(net_ref['network']['status'], 'ERROR')

            self.ofc.set_raise_exc('delete_ofc_network', None)
        self._delete('networks', net['network']['id'])

        ctx = mock.ANY
        tenant = mock.ANY
        net_name = mock.ANY
        net = mock.ANY
        expected = [
            mock.call.create_ofc_network(ctx, tenant, net_id, net_name),
            mock.call.exists_ofc_network(ctx, net_id),
            mock.call.delete_ofc_network(ctx, net_id, net),
            mock.call.exists_ofc_network(ctx, net_id),
            mock.call.delete_ofc_network(ctx, net_id, net),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_network.call_count, 2)

    def test_delete_network_with_deactivating_auto_delete_port_failure(self):
        self.ofc.set_raise_exc('delete_ofc_port',
                               nexc.OFCException(reason='hoge'))

        with self.network() as net:
            net_id = net['network']['id']

            device_owner = db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS[0]
            port = self._make_port(self.fmt, net_id, device_owner=device_owner)
            port_id = port['port']['id']

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

        self._delete('networks', net_id,
                     expected_code=webob.exc.HTTPInternalServerError.code)

        net_ref = self._show('networks', net_id)
        self.assertEqual(net_ref['network']['status'], 'ACTIVE')
        port_ref = self._show('ports', port_id)
        self.assertEqual(port_ref['port']['status'], 'ERROR')

        self.ofc.set_raise_exc('delete_ofc_port', None)
        self._delete('networks', net_id)

        ctx = mock.ANY
        tenant = mock.ANY
        net_name = mock.ANY
        net = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.create_ofc_network(ctx, tenant, net_id, net_name),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_network(ctx, net_id),
            mock.call.delete_ofc_network(ctx, net_id, net)
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_network.call_count, 1)

    def test_update_port(self):
        self._test_update_port_with_admin_state(resource='port')

    def test_update_network_with_ofc_port(self):
        self._test_update_port_with_admin_state(resource='network')

    def _test_update_port_with_admin_state(self, resource='port'):
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
                    self.assertEqual(p1['status'], 'DOWN')

                    net = self._show_resource('network', net_id)

                    # Check the port is not created on OFC
                    self.assertFalse(self.ofc.create_ofc_port.call_count)

                    # Register portinfo, then the port is created on OFC
                    portinfo = {'id': p1['id'], 'port_no': 123}
                    self.rpcapi_update_ports(added=[portinfo])
                    self.assertFalse(self.ofc.create_ofc_port.call_count)

                    res = self._update_resource(resource, res_id,
                                                {'admin_state_up': True})
                    self.assertEqual(res['status'], 'ACTIVE')
                    self.assertEqual(self.ofc.create_ofc_port.call_count, 1)
                    self.assertFalse(self.ofc.delete_ofc_port.call_count)

                    res = self._update_resource(resource, res_id,
                                                {'admin_state_up': False})
                    self.assertEqual(res['status'], 'DOWN')
                    self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)
        self._delete('ports', port['port']['id'])
        self._delete('networks', port['port']['network_id'])

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
            mock.call.exists_ofc_network(ctx, net['id']),
            mock.call.delete_ofc_network(ctx, net['id'], mock.ANY),
            mock.call.exists_ofc_tenant(ctx, self._tenant_id),
            mock.call.delete_ofc_tenant(ctx, self._tenant_id)
        ]
        self.ofc.assert_has_calls(expected)

    def test_update_port_with_ofc_creation_failure(self):
        with self.port(admin_state_up=False) as port:
            port_id = port['port']['id']
            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            self.ofc.set_raise_exc('create_ofc_port',
                                   nexc.OFCException(reason='hoge'))

            body = {'port': {'admin_state_up': True}}
            res = self._update('ports', port_id, body)
            self.assertEqual(res['port']['status'], 'ERROR')
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')

            body = {'port': {'admin_state_up': False}}
            res = self._update('ports', port_id, body)
            self.assertEqual(res['port']['status'], 'ERROR')
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')

            self.ofc.set_raise_exc('create_ofc_port', None)

            body = {'port': {'admin_state_up': True}}
            res = self._update('ports', port_id, body)
            self.assertEqual(res['port']['status'], 'ACTIVE')
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ACTIVE')
        self._delete('ports', port['port']['id'])
        ctx = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.create_ofc_port.call_count, 2)

    def test_update_port_with_ofc_deletion_failure(self):
        with self.port() as port:
            port_id = port['port']['id']
            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            self.ofc.set_raise_exc('delete_ofc_port',
                                   nexc.OFCException(reason='hoge'))

            body = {'port': {'admin_state_up': False}}
            self._update('ports', port_id, body,
                         expected_code=webob.exc.HTTPInternalServerError.code)
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')

            body = {'port': {'admin_state_up': True}}
            res = self._update('ports', port_id, body)
            self.assertEqual(res['port']['status'], 'ERROR')
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')

            self.ofc.set_raise_exc('delete_ofc_port', None)

            body = {'port': {'admin_state_up': False}}
            res = self._update('ports', port_id, body)
            self.assertEqual(res['port']['status'], 'DOWN')
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'DOWN')
        self._delete('ports', port['port']['id'])

        ctx = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_port.call_count, 2)

    def test_delete_port_with_error_status(self):
        self.ofc.set_raise_exc('create_ofc_port',
                               nexc.OFCException(reason='fake'))

        with self.port() as port:
            port_id = port['port']['id']
            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])
            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')
        self._delete('ports', port['port']['id'])

        ctx = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertFalse(self.ofc.delete_ofc_port.call_count)

    def test_delete_port_with_ofc_deletion_failure(self):
        self.ofc.set_raise_exc('delete_ofc_port',
                               nexc.OFCException(reason='hoge'))

        with self.port() as port:
            port_id = port['port']['id']

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            self._delete('ports', port_id,
                         expected_code=webob.exc.HTTPInternalServerError.code)

            port_ref = self._show('ports', port_id)
            self.assertEqual(port_ref['port']['status'], 'ERROR')

            self.ofc.set_raise_exc('delete_ofc_port', None)
        self._delete('ports', port['port']['id'])

        ctx = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port)
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_port.call_count, 2)

    def _test_delete_port_for_disappeared_ofc_port(self, raised_exc):
        self.ofc.set_raise_exc('delete_ofc_port', raised_exc)

        with self.port() as port:
            port_id = port['port']['id']

            portinfo = {'id': port_id, 'port_no': 123}
            self.rpcapi_update_ports(added=[portinfo])

            self._delete('ports', port_id)

            # Check the port on neutron db is deleted. NotFound for
            # neutron port itself should be handled by called. It is
            # consistent with ML2 behavior, but it may need to be
            # revisit.
            self._show('ports', port_id,
                       expected_code=webob.exc.HTTPNotFound.code)

        ctx = mock.ANY
        port = mock.ANY
        expected = [
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.create_ofc_port(ctx, port_id, port),
            mock.call.exists_ofc_port(ctx, port_id),
            mock.call.delete_ofc_port(ctx, port_id, port),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_port.call_count, 1)

    def test_delete_port_for_nonexist_ofc_port(self):
        self._test_delete_port_for_disappeared_ofc_port(
            nexc.OFCResourceNotFound(resource='ofc_port'))

    def test_delete_port_for_noofcmap_ofc_port(self):
        self._test_delete_port_for_disappeared_ofc_port(
            nexc.OFCMappingNotFound(resource='port', neutron_id='port1'))


class TestNecAllowedAddressPairs(NecPluginV2TestCase,
                                 test_pair.TestAllowedAddressPairs):
    pass
