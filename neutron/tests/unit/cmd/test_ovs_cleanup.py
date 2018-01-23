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

        mock_ip.return_value.exists.side_effect = port_found
        util.delete_neutron_ports(ports)
        mock_ip.assert_has_calls(
            [mock.call('tap1234'),
             mock.call().exists(),
             mock.call().link.delete(),
             mock.call('tap5678'),
             mock.call().exists(),
             mock.call('tap09ab'),
             mock.call().exists(),
             mock.call().link.delete()])
