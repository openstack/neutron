# Copyright (c) 2012 OpenStack Foundation.
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

import itertools

import mock
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.cmd import ovs_cleanup as util
from neutron.tests import base


class TestOVSCleanup(base.BaseTestCase):

    @mock.patch('neutron.common.config.setup_logging')
    @mock.patch('neutron.cmd.ovs_cleanup.setup_conf')
    @mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    @mock.patch.object(util, 'collect_neutron_ports')
    @mock.patch.object(util, 'delete_neutron_ports')
    def test_main(self, mock_delete, mock_collect, mock_ovs,
                  mock_get_bridges, mock_conf, mock_logging):
        bridges = ['br-int', 'br-ex']
        ports = ['p1', 'p2', 'p3']
        conf = mock.Mock()
        conf.ovs_all_ports = False
        conf.ovs_integration_bridge = 'br-int'
        conf.external_network_bridge = 'br-ex'
        mock_conf.return_value = conf
        mock_get_bridges.return_value = bridges
        mock_collect.return_value = ports

        util.main()
        mock_ovs.assert_has_calls([mock.call().delete_ports(
            all_ports=False)])
        mock_collect.assert_called_once_with(set(bridges))
        mock_delete.assert_called_once_with(ports)

    def test_collect_neutron_ports(self):
        port1 = ovs_lib.VifPort('tap1234', 1, uuidutils.generate_uuid(),
                                '11:22:33:44:55:66', 'br')
        port2 = ovs_lib.VifPort('tap5678', 2, uuidutils.generate_uuid(),
                                '77:88:99:aa:bb:cc', 'br')
        port3 = ovs_lib.VifPort('tap90ab', 3, uuidutils.generate_uuid(),
                                '99:00:aa:bb:cc:dd', 'br')
        ports = [[port1, port2], [port3]]
        portnames = [p.port_name for p in itertools.chain(*ports)]
        with mock.patch('neutron.agent.common.ovs_lib.OVSBridge') as ovs:
            ovs.return_value.get_vif_ports.side_effect = ports
            bridges = ['br-int', 'br-ex']
            ret = util.collect_neutron_ports(bridges)
            self.assertEqual(ret, portnames)

    @mock.patch.object(ip_lib, 'IPDevice')
    def test_delete_neutron_ports(self, mock_ip):
        ports = ['tap1234', 'tap5678', 'tap09ab']
        port_found = [True, False, True]

        with mock.patch.object(
                ip_lib, 'device_exists',
                side_effect=port_found) as device_exists:
            util.delete_neutron_ports(ports)
            device_exists.assert_has_calls([mock.call(p) for p in ports])
            mock_ip.assert_has_calls(
                [mock.call('tap1234'),
             mock.call().link.delete(),
             mock.call('tap09ab'),
             mock.call().link.delete()])
