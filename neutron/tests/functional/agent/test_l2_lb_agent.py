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

import mock
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.agent.linux import ip_lib
from neutron.objects import trunk
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent
from neutron.services.trunk.drivers.linuxbridge.agent import trunk_plumber
from neutron.tests.functional.agent.linux import test_ip_lib

lba = linuxbridge_neutron_agent


class LinuxBridgeAgentTests(test_ip_lib.IpLibTestFramework):

    def setUp(self):
        super(LinuxBridgeAgentTests, self).setUp()
        agent_rpc = ('neutron.agent.rpc.PluginApi')
        mock.patch(agent_rpc).start()
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        cfg.CONF.set_override('enable_vxlan', False, 'VXLAN')

    def test_validate_interface_mappings(self):
        mappings = {'physnet1': 'int1', 'physnet2': 'int2'}
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager({}, mappings)
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='int1'))
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager({}, mappings)
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='int2'))
        lba.LinuxBridgeManager({}, mappings)

    def test_validate_bridge_mappings(self):
        mappings = {'physnet1': 'br-eth1'}
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager(mappings, {})
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='br-eth1'))
        lba.LinuxBridgeManager(mappings, {})

    def test_vlan_subinterfaces(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        devname = device.name
        plumber = trunk_plumber.Plumber(namespace=attr.namespace)
        for i in range(20):
            subname = 'vtest-%s' % i
            plumber._create_vlan_subint(devname, subname, i)
            # ensure no addresses were assigned (e.g. ipv6)
            vlan_int = ip_lib.IPDevice(subname, namespace=attr.namespace)
            self.assertFalse(vlan_int.addr.list())
        children = plumber._get_vlan_children(devname)
        expected = {('vtest-%s' % i, i) for i in range(20)}
        self.assertEqual(expected, children)

        # delete one
        plumber._safe_delete_device('vtest-19')
        children = plumber._get_vlan_children(devname)
        expected = {('vtest-%s' % i, i) for i in range(19)}
        self.assertEqual(expected, children)
        # ensure they are removed by parent removal
        self._safe_delete_device(device)
        self.assertFalse(plumber._get_vlan_children(devname))

    def test_vlan_QinQ_subinterfaces(self):
        # the trunk model does not support this right now, but this is to
        # ensure the plumber on the agent side doesn't explode in their
        # presence in case an operator does something fancy or we have a
        # race where a trunk's parent port is converted to a subport while
        # the agent is offline.
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        devname = device.name
        plumber = trunk_plumber.Plumber(namespace=attr.namespace)
        for i in range(20):
            plumber._create_vlan_subint(devname, 'vtest-%s' % i, i)
            plumber._create_vlan_subint('vtest-%s' % i, 'qinq-%s' % i, 2)
        top_level = {('vtest-%s' % i, i) for i in range(20)}
        for i in range(20):
            # as we iterate, we delete a vlan from each dev and ensure it
            # didn't break the top-level vlans
            self.assertEqual({('qinq-%s' % i, 2)},
                             plumber._get_vlan_children('vtest-%s' % i))
            plumber._safe_delete_device('qinq-%s' % i)
            self.assertEqual(set(), plumber._get_vlan_children('vtest-%i' % i))
            self.assertEqual(top_level, plumber._get_vlan_children(devname))

    def test_ensure_trunk_subports(self):
        attr = self.generate_device_details()
        device = self.manage_device(attr)
        devname = device.name
        plumber = trunk_plumber.Plumber(namespace=attr.namespace)
        plumber._trunk_device_name = lambda x: devname
        trunk_obj = self._gen_trunk()
        plumber.ensure_trunk_subports(trunk_obj)
        # ensure no mutation the second time
        with mock.patch.object(plumber, '_safe_delete_device',
                               side_effect=RuntimeError()):
            plumber.ensure_trunk_subports(trunk_obj)

        while trunk_obj.sub_ports:
            # drain down the sub-ports and make sure it keeps
            # them equal
            trunk_obj.sub_ports.pop()
            plumber.ensure_trunk_subports(trunk_obj)
            expected = {(plumber._get_tap_device_name(sp.port_id),
                         sp.segmentation_id)
                        for sp in trunk_obj.sub_ports}
            wired = plumber._get_vlan_children(devname)
            self.assertEqual(expected, wired)

    def _gen_trunk(self):
        trunk_obj = trunk.Trunk(id=uuidutils.generate_uuid(),
                                port_id=uuidutils.generate_uuid(),
                                project_id=uuidutils.generate_uuid())
        subports = [trunk.SubPort(id=uuidutils.generate_uuid(),
                                  port_id=uuidutils.generate_uuid(),
                                  segmentation_type='vlan',
                                  trunk_id=trunk_obj.id,
                                  segmentation_id=i)
                    for i in range(20, 40)]
        trunk_obj.sub_ports = subports
        return trunk_obj
