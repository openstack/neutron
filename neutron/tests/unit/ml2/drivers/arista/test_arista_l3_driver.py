# Copyright (c) 2013 OpenStack Foundation
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
from oslo.config import cfg

from neutron.plugins.ml2.drivers.arista import arista_l3_driver as arista
from neutron.tests import base


def setup_arista_config(value='', vrf=False, mlag=False):
    cfg.CONF.set_override('primary_l3_host', value, "l3_arista")
    cfg.CONF.set_override('primary_l3_host_username', value, "l3_arista")
    if vrf:
        cfg.CONF.set_override('use_vrf', value, "l3_arista")
    if mlag:
        cfg.CONF.set_override('secondary_l3_host', value, "l3_arista")
        cfg.CONF.set_override('mlag_config', value, "l3_arista")


class AristaL3DriverTestCasesDefaultVrf(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesDefaultVrf, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        router_name = 'test-router-1'
        route_domain = '123:123'

        self.drv.create_router_on_eos(router_name, route_domain,
                                      self.drv._servers[0])
        cmds = ['enable', 'configure', 'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)

    def test_delete_router_from_eos(self):
        router_name = 'test-router-1'

        self.drv.delete_router_from_eos(router_name, self.drv._servers[0])
        cmds = ['enable', 'configure', 'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                         router_ip, mask, self.drv._servers[0])
        cmds = ['enable', 'configure', 'ip routing',
                'vlan %s' % segment_id, 'exit',
                'interface vlan %s' % segment_id,
                'ip address %s/%s' % (gw_ip, mask), 'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        self.drv.delete_interface_from_router(segment_id, router_name,
                                              self.drv._servers[0])
        cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)


class AristaL3DriverTestCasesUsingVRFs(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions using multiple VRFs.
    Note that the configuration commands are different when VRFs are used.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesUsingVRFs, self).setUp()
        setup_arista_config('value', vrf=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]
        domains = ['10%s' % n for n in range(max_vrfs)]

        for (r, d) in zip(routers, domains):
            self.drv.create_router_on_eos(r, d, self.drv._servers[0])

            cmds = ['enable', 'configure',
                    'vrf definition %s' % r,
                    'rd %(rd)s:%(rd)s' % {'rd': d}, 'exit', 'exit']

            self.drv._servers[0].runCmds.assert_called_with(version=1,
                                                            cmds=cmds)

    def test_delete_router_from_eos(self):
        max_vrfs = 5
        routers = ['testRouter-%s' % n for n in range(max_vrfs)]

        for r in routers:
            self.drv.delete_router_from_eos(r, self.drv._servers[0])
            cmds = ['enable', 'configure', 'no vrf definition %s' % r,
                    'exit']

            self.drv._servers[0].runCmds.assert_called_with(version=1,
                                                            cmds=cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                         router_ip, mask, self.drv._servers[0])
        cmds = ['enable', 'configure',
                'ip routing vrf %s' % router_name,
                'vlan %s' % segment_id, 'exit',
                'interface vlan %s' % segment_id,
                'vrf forwarding %s' % router_name,
                'ip address %s/%s' % (gw_ip, mask), 'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        self.drv.delete_interface_from_router(segment_id, router_name,
                                              self.drv._servers[0])
        cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                'exit']

        self.drv._servers[0].runCmds.assert_called_once_with(version=1,
                                                             cmds=cmds)


class AristaL3DriverTestCasesMlagConfig(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using MLAG configuration.
    MLAG configuration means that the commands will be sent to both
    primary and secondary Arista Switches.
    """

    def setUp(self):
        super(AristaL3DriverTestCasesMlagConfig, self).setUp()
        setup_arista_config('value', mlag=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_create_router_on_eos(self):
        router_name = 'test-router-1'
        route_domain = '123:123'
        router_mac = '00:11:22:33:44:55'

        for s in self.drv._servers:
            self.drv.create_router_on_eos(router_name, route_domain, s)
            cmds = ['enable', 'configure',
                    'ip virtual-router mac-address %s' % router_mac, 'exit']

            s.runCmds.assert_called_with(version=1, cmds=cmds)

    def test_delete_router_from_eos(self):
        router_name = 'test-router-1'

        for s in self.drv._servers:
            self.drv.delete_router_from_eos(router_name, s)
            cmds = ['enable', 'configure',
                    'no ip virtual-router mac-address', 'exit']

            s.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_add_interface_to_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'
        router_ip = '10.10.10.10'
        gw_ip = '10.10.10.1'
        mask = '255.255.255.0'

        for s in self.drv._servers:
            self.drv.add_interface_to_router(segment_id, router_name, gw_ip,
                                             router_ip, mask, s)
            cmds = ['enable', 'configure', 'ip routing',
                    'vlan %s' % segment_id, 'exit',
                    'interface vlan %s' % segment_id,
                    'ip address %s' % router_ip,
                    'ip virtual-router address %s' % gw_ip, 'exit']

            s.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_interface_from_router_on_eos(self):
        router_name = 'test-router-1'
        segment_id = '123'

        for s in self.drv._servers:
            self.drv.delete_interface_from_router(segment_id, router_name, s)

            cmds = ['enable', 'configure', 'no interface vlan %s' % segment_id,
                    'exit']

            s.runCmds.assert_called_once_with(version=1, cmds=cmds)


class AristaL3DriverTestCases_v4(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using IPv4.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_v4, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v4_interface_to_router(self):
        gateway_ip = '10.10.10.1'
        cidrs = ['10.10.10.0/24', '10.11.11.0/24']

        # Add couple of IPv4 subnets to router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 4}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v4_interface_from_router(self):
        gateway_ip = '10.10.10.1'
        cidrs = ['10.10.10.0/24', '10.11.11.0/24']

        # remove couple of IPv4 subnets from router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 4}

            self.assertFalse(self.drv.remove_router_interface(None, router))


class AristaL3DriverTestCases_v6(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF using IPv6.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_v6, self).setUp()
        setup_arista_config('value')
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v6_interface_to_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # Add couple of IPv6 subnets to router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v6_interface_from_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # remove couple of IPv6 subnets from router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.remove_router_interface(None, router))


class AristaL3DriverTestCases_MLAG_v6(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista L3 Driver and EOS
    to program routing functions in Default VRF on MLAG'ed switches using IPv6.
    """

    def setUp(self):
        super(AristaL3DriverTestCases_MLAG_v6, self).setUp()
        setup_arista_config('value', mlag=True)
        self.drv = arista.AristaL3Driver()
        self.drv._servers = []
        self.drv._servers.append(mock.MagicMock())
        self.drv._servers.append(mock.MagicMock())

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_add_v6_interface_to_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # Add couple of IPv6 subnets to router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.add_router_interface(None, router))

    def test_delete_v6_interface_from_router(self):
        gateway_ip = '3FFE::1'
        cidrs = ['3FFE::/16', '2001::/16']

        # remove couple of IPv6 subnets from router
        for cidr in cidrs:
            router = {'name': 'test-router-1',
                      'tenant_id': 'ten-a',
                      'seg_id': '123',
                      'cidr': "%s" % cidr,
                      'gip': "%s" % gateway_ip,
                      'ip_version': 6}

            self.assertFalse(self.drv.remove_router_interface(None, router))
