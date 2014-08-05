# Copyright (c) 2013 OpenStack Foundation.
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
import httplib

import mock

from neutron.openstack.common import importutils
from neutron.tests import base
from neutron.tests.unit.ryu import fake_ryu


class RyuAgentTestCase(base.BaseTestCase):

    _AGENT_NAME = 'neutron.plugins.ryu.agent.ryu_neutron_agent'

    def setUp(self):
        super(RyuAgentTestCase, self).setUp()
        self.fake_ryu = fake_ryu.patch_fake_ryu_client().start()
        self.mod_agent = importutils.import_module(self._AGENT_NAME)


class TestOVSNeutronOFPRyuAgent(RyuAgentTestCase):
    def setUp(self):
        super(TestOVSNeutronOFPRyuAgent, self).setUp()
        self.plugin_api = mock.patch(
            self._AGENT_NAME + '.RyuPluginApi').start()
        self.ovsbridge = mock.patch(
            self._AGENT_NAME + '.OVSBridge').start()
        self.vifportset = mock.patch(
            self._AGENT_NAME + '.VifPortSet').start()
        self.q_ctx = mock.patch(
            self._AGENT_NAME + '.q_context').start()
        self.agent_rpc = mock.patch(
            self._AGENT_NAME + '.agent_rpc.create_consumers').start()
        self.sg_rpc = mock.patch(
            self._AGENT_NAME + '.sg_rpc').start()
        self.sg_agent = mock.patch(
            self._AGENT_NAME + '.RyuSecurityGroupAgent').start()

    def mock_rest_addr(self, rest_addr):
        integ_br = 'integ_br'
        tunnel_ip = '192.168.0.1'
        ovsdb_ip = '172.16.0.1'
        ovsdb_port = 16634
        interval = 2
        root_helper = 'helper'

        self.mod_agent.OVSBridge.return_value.datapath_id = '1234'

        mock_context = mock.Mock(return_value='abc')
        self.q_ctx.get_admin_context_without_session = mock_context

        mock_rest_addr = mock.Mock(return_value=rest_addr)
        self.plugin_api.return_value.get_ofp_rest_api_addr = mock_rest_addr

        # Instantiate OVSNeutronOFPRyuAgent
        return self.mod_agent.OVSNeutronOFPRyuAgent(
            integ_br, tunnel_ip, ovsdb_ip, ovsdb_port, interval, root_helper)

    def test_valid_rest_addr(self):
        self.mock_rest_addr('192.168.0.1:8080')

        # OVSBridge
        self.ovsbridge.assert_has_calls([
            mock.call('integ_br', 'helper'),
            mock.call().find_datapath_id()
        ])

        # RyuPluginRpc
        self.plugin_api.assert_has_calls([
            mock.call('q-plugin'),
            mock.call().get_ofp_rest_api_addr('abc')
        ])

        # Agent RPC
        self.agent_rpc.assert_has_calls([
            mock.call(mock.ANY, 'q-agent-notifier', mock.ANY)
        ])

        # OFPClient
        self.mod_agent.client.OFPClient.assert_has_calls([
            mock.call('192.168.0.1:8080')
        ])

        # VifPortSet
        self.vifportset.assert_has_calls([
            mock.call(
                self.ovsbridge.return_value,
                self.mod_agent.client.OFPClient.return_value),
            mock.call().setup()
        ])

        # SwitchConfClient
        self.mod_agent.client.SwitchConfClient.assert_has_calls([
            mock.call('192.168.0.1:8080'),
            mock.call().set_key('1234', 'ovs_tunnel_addr', '192.168.0.1'),
            mock.call().set_key('1234', 'ovsdb_addr',
                                'tcp:%s:%d' % ('172.16.0.1', 16634))
        ])

        # OVSBridge
        self.ovsbridge.return_value.set_manager.assert_has_calls([
            mock.call('ptcp:%d' % 16634)
        ])

    def test_invalid_rest_addr(self):
        self.assertRaises(self.mod_agent.n_exc.Invalid,
                          self.mock_rest_addr, (''))

    def mock_port_update(self, **kwargs):
        agent = self.mock_rest_addr('192.168.0.1:8080')
        agent.port_update(mock.Mock(), **kwargs)

    def test_port_update(self, **kwargs):
        port = {'id': 1, 'security_groups': 'default'}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value=1) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with(1)
        self.sg_agent.assert_has_calls([
            mock.call().refresh_firewall()
        ])

    def test_port_update_not_vifport(self, **kwargs):
        port = {'id': 1, 'security_groups': 'default'}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value=0) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with(1)
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update_without_secgroup(self, **kwargs):
        port = {'id': 1}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value=1) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with(1)
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def mock_update_ports(self, vif_port_set=None, registered_ports=None):
        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_set',
                               return_value=vif_port_set):
            agent = self.mock_rest_addr('192.168.0.1:8080')
            return agent._update_ports(registered_ports)

    def test_update_ports_unchanged(self):
        self.assertIsNone(self.mock_update_ports())

    def test_update_ports_changed(self):
        vif_port_set = set([1, 3])
        registered_ports = set([1, 2])
        expected = dict(current=vif_port_set,
                        added=set([3]),
                        removed=set([2]))

        actual = self.mock_update_ports(vif_port_set, registered_ports)

        self.assertEqual(expected, actual)

    def mock_process_devices_filter(self, port_info):
        agent = self.mock_rest_addr('192.168.0.1:8080')
        agent._process_devices_filter(port_info)

    def test_process_devices_filter_add(self):
        port_info = {'added': 1}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().prepare_devices_filter(1)
        ])

    def test_process_devices_filter_remove(self):
        port_info = {'removed': 2}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().remove_devices_filter(2)
        ])

    def test_process_devices_filter_both(self):
        port_info = {'added': 1, 'removed': 2}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().prepare_devices_filter(1),
            mock.call().remove_devices_filter(2)
        ])

    def test_process_devices_filter_none(self):
        port_info = {}

        self.mock_process_devices_filter(port_info)

        self.assertFalse(
            self.sg_agent.return_value.prepare_devices_filter.called)
        self.assertFalse(
            self.sg_agent.return_value.remove_devices_filter.called)


class TestRyuPluginApi(RyuAgentTestCase):
    def test_get_ofp_rest_api_addr(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.RyuPluginApi.make_msg',
                       return_value='msg'),
            mock.patch(self._AGENT_NAME + '.RyuPluginApi.call',
                       return_value='10.0.0.1')
        ) as (mock_msg, mock_call):
            api = self.mod_agent.RyuPluginApi('topics')
            addr = api.get_ofp_rest_api_addr('context')

        self.assertEqual(addr, '10.0.0.1')
        mock_msg.assert_has_calls([
            mock.call('get_ofp_rest_api')
        ])
        mock_call.assert_has_calls([
            mock.call('context', 'msg')
        ])


class TestVifPortSet(RyuAgentTestCase):
    def test_setup(self):
        attrs = {'switch.datapath_id': 'dp1', 'ofport': 'p1'}
        p1 = mock.Mock(**attrs)
        attrs = {'switch.datapath_id': 'dp2', 'ofport': 'p2'}
        p2 = mock.Mock(**attrs)
        attrs = {'get_external_ports.return_value': [p1, p2]}
        int_br = mock.Mock(**attrs)
        with mock.patch(self._AGENT_NAME + '.client.OFPClient') as client:
            api = client()
            vif = self.mod_agent.VifPortSet(int_br, api)
            vif.setup()

        client.assert_has_calls([
            mock.call().update_port('__NW_ID_EXTERNAL__', 'dp1', 'p1'),
            mock.call().update_port('__NW_ID_EXTERNAL__', 'dp2', 'p2')
        ])

    def test_setup_empty(self):
        attrs = {'get_external_ports.return_value': []}
        int_br = mock.Mock(**attrs)
        api = mock.Mock()

        vif = self.mod_agent.VifPortSet(int_br, api)
        vif.setup()

        self.assertEqual(api.update_port.call_count, 0)


class TestOVSBridge(RyuAgentTestCase):
    def setUp(self):
        super(TestOVSBridge, self).setUp()
        self.lib_ovs = mock.patch(
            'neutron.agent.linux.ovs_lib.OVSBridge').start()

    def test_find_datapath_id(self):
        with mock.patch(self._AGENT_NAME + '.OVSBridge.get_datapath_id',
                        return_value='1234') as mock_get_dpid:
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            br.find_datapath_id()

        mock_get_dpid.assert_has_calls([
            mock.call()
        ])
        self.assertEqual(br.datapath_id, '1234')

    def test_set_manager(self):
        with mock.patch(
                self._AGENT_NAME + '.OVSBridge.run_vsctl') as mock_vsctl:
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            br.set_manager('target')

        mock_vsctl.assert_has_calls([
            mock.call(['set-manager', 'target'])
        ])

    def test_get_ofport(self):
        with mock.patch(
                self._AGENT_NAME + '.OVSBridge.db_get_val',
                return_value=1) as mock_db:
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            ofport = br.get_ofport('name')

        mock_db.assert_has_calls([
            mock.call('Interface', 'name', 'ofport')
        ])
        self.assertEqual(ofport, 1)

    def test_get_ports(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_port_name_list',
                       return_value=['p1', 'p2']),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       return_value=1)
        ) as (mock_name, mock_ofport):
            get_port = mock.Mock(side_effect=['port1', 'port2'])
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            ports = br._get_ports(get_port)

        mock_name.assert_has_calls([
            mock.call()
        ])
        mock_ofport.assert_has_calls([
            mock.call('p1'),
            mock.call('p2')
        ])
        get_port.assert_has_calls([
            mock.call('p1'),
            mock.call('p2')
        ])
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports, ['port1', 'port2'])

    def test_get_ports_empty(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_port_name_list',
                       return_value=[]),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       return_value=1)
        ) as (mock_name, mock_ofport):
            get_port = mock.Mock(side_effect=['port1', 'port2'])
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            ports = br._get_ports(get_port)

        mock_name.assert_has_calls([
            mock.call()
        ])
        self.assertEqual(mock_ofport.call_count, 0)
        self.assertEqual(get_port.call_count, 0)
        self.assertEqual(len(ports), 0)

    def test_get_ports_invalid_ofport(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_port_name_list',
                       return_value=['p1', 'p2']),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       side_effect=[-1, 1])
        ) as (mock_name, mock_ofport):
            get_port = mock.Mock(side_effect=['port1', 'port2'])
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            ports = br._get_ports(get_port)

        mock_name.assert_has_calls([
            mock.call()
        ])
        mock_ofport.assert_has_calls([
            mock.call('p1'),
            mock.call('p2')
        ])
        get_port.assert_has_calls([
            mock.call('p2')
        ])
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports, ['port1'])

    def test_get_ports_invalid_port(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_port_name_list',
                       return_value=['p1', 'p2']),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       side_effect=[1, 2])
        ) as (mock_name, mock_ofport):
            get_port = mock.Mock(side_effect=[None, 'port2'])
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            ports = br._get_ports(get_port)

        mock_name.assert_has_calls([
            mock.call()
        ])
        mock_ofport.assert_has_calls([
            mock.call('p1'),
            mock.call('p2')
        ])
        get_port.assert_has_calls([
            mock.call('p1'),
            mock.call('p2')
        ])
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports, ['port2'])

    def test_get_external_port(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.db_get_map',
                       side_effect=[None, {'opts': 'opts_val'}]),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       return_value=1),
            mock.patch('neutron.agent.linux.ovs_lib.VifPort')
        ) as (mock_db, mock_ofport, mock_vif):
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            vifport = br._get_external_port('iface')

        mock_db.assert_has_calls([
            mock.call('Interface', 'iface', 'external_ids'),
            mock.call('Interface', 'iface', 'options'),
        ])
        mock_ofport.assert_has_calls([
            mock.call('iface')
        ])
        mock_vif.assert_has_calls([
            mock.call('iface', 1, None, None, br)
        ])
        self.assertEqual(vifport, mock_vif.return_value)

    def test_get_external_port_vmport(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.db_get_map',
                       side_effect=[{'extids': 'extid_val'},
                                    {'opts': 'opts_val'}]),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       return_value=1),
            mock.patch('neutron.agent.linux.ovs_lib.VifPort')
        ) as (mock_db, mock_ofport, mock_vif):
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            vifport = br._get_external_port('iface')

        mock_db.assert_has_calls([
            mock.call('Interface', 'iface', 'external_ids'),
        ])
        self.assertEqual(mock_ofport.call_count, 0)
        self.assertEqual(mock_vif.call_count, 0)
        self.assertIsNone(vifport)

    def test_get_external_port_tunnel(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge.db_get_map',
                       side_effect=[None, {'remote_ip': '0.0.0.0'}]),
            mock.patch(self._AGENT_NAME + '.OVSBridge.get_ofport',
                       return_value=1),
            mock.patch('neutron.agent.linux.ovs_lib.VifPort')
        ) as (mock_db, mock_ofport, mock_vif):
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            vifport = br._get_external_port('iface')

        mock_db.assert_has_calls([
            mock.call('Interface', 'iface', 'external_ids'),
            mock.call('Interface', 'iface', 'options'),
        ])
        self.assertEqual(mock_ofport.call_count, 0)
        self.assertEqual(mock_vif.call_count, 0)
        self.assertIsNone(vifport)

    def test_get_external_ports(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSBridge._get_external_port'),
            mock.patch(self._AGENT_NAME + '.OVSBridge._get_ports')
        ) as (mock_extport, mock_port):
            br = self.mod_agent.OVSBridge('br_name', 'helper')
            br.get_external_ports()

        mock_port.assert_has_calls([
            mock.call(mock_extport)
        ])


class TestRyuNeutronAgent(RyuAgentTestCase):
    def test_get_my_ip(self):
        sock_attrs = {
            'return_value.getsockname.return_value': ['1.2.3.4', '']}
        with mock.patch('socket.socket', **sock_attrs):
            addr = self.mod_agent._get_my_ip()

        self.assertEqual(addr, '1.2.3.4')

    def test_get_ip_from_nic(self):
        mock_device = mock.Mock()
        mock_device.addr.list = mock.Mock(
            return_value=[{'ip_version': 6, 'cidr': '::ffff:1.2.3.4'},
                          {'ip_version': 4, 'cidr': '1.2.3.4/8'}])
        mock_ip_wrapper = mock.Mock()
        mock_ip_wrapper.device = mock.Mock(return_value=mock_device)
        with mock.patch(self._AGENT_NAME + '.ip_lib.IPWrapper',
                        return_value=mock_ip_wrapper):
            addr = self.mod_agent._get_ip_from_nic('eth0')

        self.assertEqual(addr, '1.2.3.4')

    def test_get_ip_from_nic_empty(self):
        mock_device = mock.Mock()
        mock_device.addr.list = mock.Mock(return_value=[])
        mock_ip_wrapper = mock.Mock()
        mock_ip_wrapper.device = mock.Mock(return_value=mock_device)
        with mock.patch(self._AGENT_NAME + '.ip_lib.IPWrapper',
                        return_value=mock_ip_wrapper):
            addr = self.mod_agent._get_ip_from_nic('eth0')

        self.assertIsNone(addr)

    def test_get_ip_ip(self):
        cfg_attrs = {'CONF.OVS.cfg_ip': '1.2.3.4',
                     'CONF.OVS.cfg_iface': 'eth0'}
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.cfg', **cfg_attrs),
            mock.patch(self._AGENT_NAME + '._get_ip_from_nic',
                       return_value='10.0.0.1'),
            mock.patch(self._AGENT_NAME + '._get_my_ip',
                       return_value='172.16.0.1')
        ) as (_cfg, mock_nicip, mock_myip):
            ip = self.mod_agent._get_ip('cfg_ip', 'cfg_iface')

        self.assertEqual(mock_nicip.call_count, 0)
        self.assertEqual(mock_myip.call_count, 0)
        self.assertEqual(ip, '1.2.3.4')

    def test_get_ip_nic(self):
        cfg_attrs = {'CONF.OVS.cfg_ip': None,
                     'CONF.OVS.cfg_iface': 'eth0'}
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.cfg', **cfg_attrs),
            mock.patch(self._AGENT_NAME + '._get_ip_from_nic',
                       return_value='10.0.0.1'),
            mock.patch(self._AGENT_NAME + '._get_my_ip',
                       return_value='172.16.0.1')
        ) as (_cfg, mock_nicip, mock_myip):
            ip = self.mod_agent._get_ip('cfg_ip', 'cfg_iface')

        mock_nicip.assert_has_calls([
            mock.call('eth0')
        ])
        self.assertEqual(mock_myip.call_count, 0)
        self.assertEqual(ip, '10.0.0.1')

    def test_get_ip_myip(self):
        cfg_attrs = {'CONF.OVS.cfg_ip': None,
                     'CONF.OVS.cfg_iface': None}
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.cfg', **cfg_attrs),
            mock.patch(self._AGENT_NAME + '._get_ip_from_nic',
                       return_value='10.0.0.1'),
            mock.patch(self._AGENT_NAME + '._get_my_ip',
                       return_value='172.16.0.1')
        ) as (_cfg, mock_nicip, mock_myip):
            ip = self.mod_agent._get_ip('cfg_ip', 'cfg_iface')

        self.assertEqual(mock_nicip.call_count, 0)
        mock_myip.assert_has_calls([
            mock.call()
        ])
        self.assertEqual(ip, '172.16.0.1')

    def test_get_ip_nic_myip(self):
        cfg_attrs = {'CONF.OVS.cfg_ip': None,
                     'CONF.OVS.cfg_iface': 'eth0'}
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.cfg', **cfg_attrs),
            mock.patch(self._AGENT_NAME + '._get_ip_from_nic',
                       return_value=None),
            mock.patch(self._AGENT_NAME + '._get_my_ip',
                       return_value='172.16.0.1')
        ) as (_cfg, mock_nicip, mock_myip):
            ip = self.mod_agent._get_ip('cfg_ip', 'cfg_iface')

        mock_nicip.assert_has_calls([
            mock.call('eth0')
        ])
        mock_myip.assert_has_calls([
            mock.call()
        ])
        self.assertEqual(ip, '172.16.0.1')

    def test_get_tunnel_ip(self):
        with mock.patch(self._AGENT_NAME + '._get_ip',
                        return_value='1.2.3.4') as mock_getip:
            ip = self.mod_agent._get_tunnel_ip()

        mock_getip.assert_has_calls([
            mock.call('tunnel_ip', 'tunnel_interface')
        ])
        self.assertEqual(ip, '1.2.3.4')

    def test_get_ovsdb_ip(self):
        with mock.patch(self._AGENT_NAME + '._get_ip',
                        return_value='1.2.3.4') as mock_getip:
            ip = self.mod_agent._get_ovsdb_ip()

        mock_getip.assert_has_calls([
            mock.call('ovsdb_ip', 'ovsdb_interface')
        ])
        self.assertEqual(ip, '1.2.3.4')

    def mock_main(self):
        cfg_attrs = {'CONF.OVS.integration_bridge': 'integ_br',
                     'CONF.OVS.ovsdb_port': 16634,
                     'CONF.AGENT.polling_interval': 2,
                     'CONF.AGENT.root_helper': 'helper'}
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.cfg', **cfg_attrs),
            mock.patch(self._AGENT_NAME + '.common_config'),
            mock.patch(self._AGENT_NAME + '._get_tunnel_ip',
                       return_value='10.0.0.1'),
            mock.patch(self._AGENT_NAME + '._get_ovsdb_ip',
                       return_value='172.16.0.1'),
        ) as (mock_conf, mock_common_conf, _tun, _ovsdb):
            self.mod_agent.main()

        mock_common_conf.assert_has_calls([
            mock.call(mock_conf)
        ])

    def test_main(self):
        agent_attrs = {'daemon_loop.side_effect': SystemExit(0)}
        with mock.patch(self._AGENT_NAME + '.OVSNeutronOFPRyuAgent',
                        **agent_attrs) as mock_agent:
            self.assertRaises(SystemExit, self.mock_main)

        mock_agent.assert_has_calls([
            mock.call('integ_br', '10.0.0.1', '172.16.0.1', 16634, 2,
                      'helper'),
            mock.call().daemon_loop()
        ])

    def test_main_raise(self):
        with contextlib.nested(
            mock.patch(self._AGENT_NAME + '.OVSNeutronOFPRyuAgent',
                       side_effect=httplib.HTTPException('boom')),
            mock.patch('sys.exit', side_effect=SystemExit(0))
        ) as (mock_agent, mock_exit):
            self.assertRaises(SystemExit, self.mock_main)

        mock_agent.assert_has_calls([
            mock.call('integ_br', '10.0.0.1', '172.16.0.1', 16634, 2,
                      'helper')
        ])
        mock_exit.assert_has_calls([
            mock.call(1)
        ])
